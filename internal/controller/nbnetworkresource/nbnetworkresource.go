/*
Copyright 2022 The Crossplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package nbnetworkresource

import (
	"context"
	"fmt"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/connection"
	"github.com/crossplane/crossplane-runtime/pkg/controller"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/feature"
	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/crossplane-runtime/pkg/ratelimiter"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	apisv1alpha1 "github.com/crossplane/netbird-crossplane-provider/apis/v1alpha1"
	"github.com/crossplane/netbird-crossplane-provider/apis/vpn/v1alpha1"
	nbcontrol "github.com/crossplane/netbird-crossplane-provider/internal/controller/nb"
	"github.com/crossplane/netbird-crossplane-provider/internal/features"
	netbird "github.com/netbirdio/netbird/management/client/rest"
	nbapi "github.com/netbirdio/netbird/management/server/http/api"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	errNotNbNetworkResource = "managed resource is not a NbNetworkResource custom resource"
	errTrackPCUsage         = "cannot track ProviderConfig usage"
	errGetPC                = "cannot get ProviderConfig"
	errGetCreds             = "cannot get credentials"

	errNewClient = "cannot create new Service"
)

type NbService struct {
	nbCli *netbird.Client
}

var (
	newNbService = func(url string, creds string, credType string) (*NbService, error) {
		var c *netbird.Client
		if credType == "oauth" {
			c = netbird.NewWithBearerToken(url, creds)
		} else {
			c = netbird.New(url, creds)
		}
		return &NbService{nbCli: c}, nil
	}
)

// Setup adds a controller that reconciles NbNetworkResource managed resources.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(v1alpha1.NbNetworkResourceGroupKind)

	cps := []managed.ConnectionPublisher{managed.NewAPISecretPublisher(mgr.GetClient(), mgr.GetScheme())}
	if o.Features.Enabled(features.EnableAlphaExternalSecretStores) {
		cps = append(cps, connection.NewDetailsManager(mgr.GetClient(), apisv1alpha1.StoreConfigGroupVersionKind))
	}

	reconcilerOptions := []managed.ReconcilerOption{
		managed.WithExternalConnecter(&connector{
			kube:         mgr.GetClient(),
			usage:        resource.NewProviderConfigUsageTracker(mgr.GetClient(), &apisv1alpha1.ProviderConfigUsage{}),
			newServiceFn: newNbService}),
		managed.WithLogger(o.Logger.WithValues("controller", name)),
		managed.WithPollInterval(o.PollInterval),
		managed.WithRecorder(event.NewAPIRecorder(mgr.GetEventRecorderFor(name))),
		managed.WithConnectionPublishers(cps...),
	}
	if o.Features.Enabled(feature.EnableBetaManagementPolicies) {
		reconcilerOptions = append(reconcilerOptions, managed.WithManagementPolicies())
	}

	r := managed.NewReconciler(mgr,
		resource.ManagedKind(v1alpha1.NbNetworkResourceGroupVersionKind),
		reconcilerOptions...,
	)

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		WithEventFilter(resource.DesiredStateChanged()).
		For(&v1alpha1.NbNetworkResource{}).
		Complete(ratelimiter.NewReconciler(name, r, o.GlobalRateLimiter))
}

// A connector is expected to produce an ExternalClient when its Connect method
// is called.
type connector struct {
	kube         client.Client
	usage        resource.Tracker
	newServiceFn func(url string, creds string, credsType string) (*NbService, error)
}

// Connect typically produces an ExternalClient by:
// 1. Tracking that the managed resource is using a ProviderConfig.
// 2. Getting the managed resource's ProviderConfig.
// 3. Getting the credentials specified by the ProviderConfig.
// 4. Using the credentials to form a client.
func (c *connector) Connect(ctx context.Context, mg resource.Managed) (managed.ExternalClient, error) {
	cr, ok := mg.(*v1alpha1.NbNetworkResource)
	if !ok {
		return nil, errors.New(errNotNbNetworkResource)
	}

	if err := c.usage.Track(ctx, mg); err != nil {
		return nil, errors.Wrap(err, errTrackPCUsage)
	}

	pc := &apisv1alpha1.ProviderConfig{}
	if err := c.kube.Get(ctx, types.NamespacedName{Name: cr.GetProviderConfigReference().Name}, pc); err != nil {
		return nil, errors.Wrap(err, errGetPC)
	}

	cd := pc.Spec.Credentials
	data, err := resource.CommonCredentialExtractor(ctx, cd.Source, c.kube, cd.CommonCredentialSelectors)
	if err != nil {
		return nil, errors.Wrap(err, errGetCreds)
	}
	nbManagementEndpoint := pc.Spec.MmanagementURI
	var creds string
	var err2 error
	if pc.Spec.CredentialsType == "oauth" {
		creds, err2 = nbcontrol.GetTokenUsingOauth(string(data), pc.Spec.OauthIssuerUrl)
		if err2 != nil {
			return nil, errors.Wrap(err2, errNewClient)
		}
	} else {
		creds = string(data)
	}
	svc, err := c.newServiceFn(nbManagementEndpoint, creds, pc.Spec.CredentialsType)
	if err != nil {
		return nil, errors.Wrap(err, errNewClient)
	}

	return &external{service: svc}, nil
}

// An ExternalClient observes, then either creates, updates, or deletes an
// external resource to ensure it reflects the managed resource's desired state.
type external struct {
	// A 'client' used to connect to the external resource API. In practice this
	// would be something like an AWS SDK client.
	service *NbService
}

func (c *external) Observe(ctx context.Context, mg resource.Managed) (managed.ExternalObservation, error) {
	cr, ok := mg.(*v1alpha1.NbNetworkResource)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotNbNetworkResource)
	}
	externalName := meta.GetExternalName(cr)
	if externalName == "" {
		return managed.ExternalObservation{ResourceExists: false}, nil
	}
	networks, err := c.service.nbCli.Networks.List(ctx)
	if err != nil {
		fmt.Printf("received error on call to nb: %+v", err)
		return managed.ExternalObservation{
			ResourceExists: false,
		}, nil //return nil so that observe can return without error so that it passes to create.
	}
	var apinetwork *nbapi.Network
	for _, network := range networks {
		if network.Name == cr.Spec.ForProvider.NetworkName {
			apinetwork = &network
		}
	}
	networkresource, err := c.service.nbCli.Networks.Resources(apinetwork.Id).Get(ctx, externalName)
	if err != nil {
		return managed.ExternalObservation{
			ResourceExists: false,
		}, nil
	}
	cr.Status.AtProvider = v1alpha1.NbNetworkResourceObservation{
		Id:          networkresource.Id,
		Enabled:     networkresource.Enabled,
		Address:     networkresource.Address,
		Description: networkresource.Description,
		Groups:      convertGroups(networkresource.Groups),
		Name:        networkresource.Name,
		Type:        string(networkresource.Type),
	}

	cr.Status.SetConditions(xpv1.Available())

	return managed.ExternalObservation{
		ResourceExists:   true,
		ResourceUpToDate: true,
	}, nil
}

func convertGroups(groupMinimums []nbapi.GroupMinimum) []v1alpha1.GroupMinimum {
	groups := make([]v1alpha1.GroupMinimum, len(groupMinimums))
	for i, g := range groupMinimums {
		groups[i] = v1alpha1.GroupMinimum{
			Id: &g.Id,
			//Issued:         &g.Issued,
			Name:           &g.Name,
			PeersCount:     g.PeersCount,
			ResourcesCount: g.ResourcesCount,
		}
	}
	return groups
}

func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1alpha1.NbNetworkResource)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotNbNetworkResource)
	}
	networks, err := c.service.nbCli.Networks.List(ctx)
	if err != nil {
		return managed.ExternalCreation{}, err
	}
	var apinetwork *nbapi.Network
	for _, network := range networks {
		if network.Name == cr.Spec.ForProvider.NetworkName {
			apinetwork = &network
		}
	}
	groups, err := c.service.nbCli.Groups.List(ctx)
	if err != nil {
		return managed.ExternalCreation{}, err
	}
	groupids := make([]string, len(cr.Spec.ForProvider.Groups))
	for j, provgroup := range cr.Spec.ForProvider.Groups {
		for _, apigroup := range groups {
			if apigroup.Name == *provgroup.Name {
				groupids[j] = apigroup.Id
				break
			}
		}
	}
	networkresource, err := c.service.nbCli.Networks.Resources(apinetwork.Id).Create(ctx, nbapi.NetworkResourceRequest{
		Enabled:     cr.Spec.ForProvider.Enabled,
		Address:     cr.Spec.ForProvider.Address,
		Description: cr.Spec.ForProvider.Description,
		Groups:      groupids,
		Name:        cr.Spec.ForProvider.Name,
	})

	if err != nil {
		fmt.Printf("err creating networkresource: %+v", err)
		return managed.ExternalCreation{}, err
	}
	fmt.Printf("networkresource created: %+v", networkresource)
	meta.SetExternalName(cr, networkresource.Id)
	return managed.ExternalCreation{}, nil
}

// func convertGMToStringArray(groupids []string) []string {
// 	groups := make([]string, len(groupMinimum))
// 	for i, g := range groupMinimum {
// 		groups[i] = g.Id
// 	}
// 	return groups
// }

func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1alpha1.NbNetworkResource)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotNbNetworkResource)
	}
	//networkid := meta.GetExternalName(cr)
	fmt.Printf("Updating: %+v", cr)
	//todo
	// if err != nil {
	// 	return managed.ExternalUpdate{}, err
	// }

	return managed.ExternalUpdate{
		// Optionally return any details that may be required to connect to the
		// external resource. These will be stored as the connection secret.
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Delete(ctx context.Context, mg resource.Managed) error {
	cr, ok := mg.(*v1alpha1.NbNetworkResource)
	if !ok {
		return errors.New(errNotNbNetworkResource)
	}

	fmt.Printf("Deleting: %+v", cr)
	networks, err := c.service.nbCli.Networks.List(ctx)
	if err != nil {
		return err
	}
	var apinetwork *nbapi.Network
	for _, network := range networks {
		if network.Name == cr.Spec.ForProvider.NetworkName {
			apinetwork = &network
		}
	}
	networkresourceid := meta.GetExternalName(cr)
	return c.service.nbCli.Networks.Resources(apinetwork.Id).Delete(ctx, networkresourceid)
}
