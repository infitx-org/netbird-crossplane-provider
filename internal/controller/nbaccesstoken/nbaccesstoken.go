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

package nbaccesstoken

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

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
)

const (
	errNotNbAccessToken = "managed resource is not a NbAccessToken custom resource"
	errTrackPCUsage     = "cannot track ProviderConfig usage"
	errGetPC            = "cannot get ProviderConfig"
	errGetCreds         = "cannot get credentials"

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

// Setup adds a controller that reconciles NbAccessToken managed resources.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(v1alpha1.NbAccessTokenGroupKind)

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
		resource.ManagedKind(v1alpha1.NbAccessTokenGroupVersionKind),
		reconcilerOptions...,
	)

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		WithEventFilter(resource.DesiredStateChanged()).
		For(&v1alpha1.NbAccessToken{}).
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
	cr, ok := mg.(*v1alpha1.NbAccessToken)
	if !ok {
		return nil, errors.New(errNotNbAccessToken)
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
	cr, ok := mg.(*v1alpha1.NbAccessToken)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotNbAccessToken)
	}

	// These fmt statements should be removed in the real implementation.
	fmt.Printf("Observing: %+v", cr)
	externalName := meta.GetExternalName(cr)
	if externalName == "" {
		fmt.Printf("didn't find externalname")
		return managed.ExternalObservation{ResourceExists: false}, nil
	}
	var userid string
	if cr.Spec.ForProvider.UserName != nil {
		users, err := c.service.nbCli.Users.List(ctx)
		if err != nil {
			fmt.Printf("received error on call to nb for user: %+v", err)
			return managed.ExternalObservation{
				ResourceExists: false,
			}, err
		}
		var apiuser nbapi.User
		for _, user := range users {
			if *user.IsServiceUser && (user.Name == *cr.Spec.ForProvider.UserName) {
				apiuser = user
			}
		}
		userid = apiuser.Id
	} else {
		userid = *cr.Spec.ForProvider.UserId
	}

	accesstoken, err := c.service.nbCli.Tokens.Get(ctx, userid, externalName)
	if err != nil {
		fmt.Printf("received error on call to nb for accesstoken: %+v", accesstoken)
		fmt.Printf("received error on call to nb for accesstoken: %+v", err)
		return managed.ExternalObservation{
			ResourceExists: false,
		}, nil
	}
	lastused := accesstoken.LastUsed.Local().String()
	cr.Status.AtProvider = v1alpha1.NbAccessTokenObservation{
		Id:             accesstoken.Id,
		CreatedAt:      accesstoken.CreatedBy,
		ExpirationDate: accesstoken.ExpirationDate.Local().String(),
		CreatedBy:      accesstoken.CreatedBy,
		LastUsed:       &lastused,
		Name:           accesstoken.Name,
	}

	cr.Status.SetConditions(xpv1.Available())
	return managed.ExternalObservation{
		ResourceExists:    true,
		ResourceUpToDate:  true, //isUpToDate(&cr.Spec.ForProvider, accesstoken),
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

// func isUpToDate(nbAccessTokenParameters *v1alpha1.NbAccessTokenParameters, accesstoken *nbapi.PersonalAccessToken) bool {
// 	return true //need to determine how to refresh token when expires
// }

func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1alpha1.NbAccessToken)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotNbAccessToken)
	}

	fmt.Printf("Creating: %+v", cr)
	var userid string
	if cr.Spec.ForProvider.UserName != nil {
		users, err := c.service.nbCli.Users.List(ctx)
		if err != nil {
			fmt.Printf("received error on call to nb: %+v", err)
			return managed.ExternalCreation{}, err
		}
		var apiuser nbapi.User
		for _, user := range users {
			if user.Name == *cr.Spec.ForProvider.UserName {
				apiuser = user
			}
		}
		userid = apiuser.Id
	} else {
		userid = *cr.Spec.ForProvider.UserId
	}
	accesstoken, err := c.service.nbCli.Tokens.Create(ctx, userid, nbapi.PersonalAccessTokenRequest{
		ExpiresIn: cr.Spec.ForProvider.ExpiresIn,
		Name:      cr.Spec.ForProvider.Name,
	})
	if err != nil {
		fmt.Printf("received error on call to nb : %+v", err)
		return managed.ExternalCreation{}, err
	}
	fmt.Printf("accesstoken created: %+v", accesstoken)
	meta.SetExternalName(cr, accesstoken.PersonalAccessToken.Id)

	cd := managed.ConnectionDetails{
		xpv1.ResourceCredentialsSecretPasswordKey: []byte(accesstoken.PlainToken),
	}
	return managed.ExternalCreation{
		// Optionally return any details that may be required to connect to the
		// external resource. These will be stored as the connection secret.
		ConnectionDetails: cd,
	}, nil
}

func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1alpha1.NbAccessToken)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotNbAccessToken)
	}

	fmt.Printf("Updating: %+v", cr)

	return managed.ExternalUpdate{
		// Optionally return any details that may be required to connect to the
		// external resource. These will be stored as the connection secret.
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Delete(ctx context.Context, mg resource.Managed) error {
	cr, ok := mg.(*v1alpha1.NbAccessToken)
	if !ok {
		return errors.New(errNotNbAccessToken)
	}
	externalName := meta.GetExternalName(cr)
	if externalName == "" {
		return errors.New("no externalname found")
	}
	fmt.Printf("Deleting: %+v", cr)
	var userid string
	if cr.Spec.ForProvider.UserName != nil {
		users, err := c.service.nbCli.Users.List(ctx)
		if err != nil {
			fmt.Printf("received error on call to nb: %+v", err)
			return err
		}
		var apiuser nbapi.User
		for _, user := range users {
			if user.Name == *cr.Spec.ForProvider.UserName {
				apiuser = user
			}
		}
		userid = apiuser.Id
	} else {
		userid = *cr.Spec.ForProvider.UserId
	}
	return c.service.nbCli.Tokens.Delete(ctx, userid, externalName)
}
