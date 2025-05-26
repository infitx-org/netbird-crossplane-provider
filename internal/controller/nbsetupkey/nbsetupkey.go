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

package nbsetupkey

import (
	"context"
	"reflect"

	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/crossplane/crossplane-runtime/pkg/connection"
	"github.com/crossplane/crossplane-runtime/pkg/controller"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/feature"
	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/crossplane-runtime/pkg/ratelimiter"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	apisv1alpha1 "github.com/crossplane/netbird-crossplane-provider/apis/v1alpha1"
	"github.com/crossplane/netbird-crossplane-provider/apis/vpn/v1alpha1"
	nbcontrol "github.com/crossplane/netbird-crossplane-provider/internal/controller/nb"
	"github.com/crossplane/netbird-crossplane-provider/internal/features"
	netbird "github.com/netbirdio/netbird/management/client/rest"
	"github.com/netbirdio/netbird/management/server/http/api"
)

const (
	errNotNbSetupKey = "managed resource is not a NbSetupKey custom resource"
	errTrackPCUsage  = "cannot track ProviderConfig usage"
	errGetPC         = "cannot get ProviderConfig"
	errGetCreds      = "cannot get credentials"

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

// Setup adds a controller that reconciles NbSetupKey managed resources.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(v1alpha1.NbSetupKeyGroupKind)

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
		resource.ManagedKind(v1alpha1.NbSetupKeyGroupVersionKind),
		reconcilerOptions...,
	)

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		WithEventFilter(resource.DesiredStateChanged()).
		For(&v1alpha1.NbSetupKey{}).
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
	cr, ok := mg.(*v1alpha1.NbSetupKey)
	if !ok {
		return nil, errors.New(errNotNbSetupKey)
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
	cr, ok := mg.(*v1alpha1.NbSetupKey)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotNbSetupKey)
	}
	externalName := meta.GetExternalName(cr)
	if externalName == "" {
		return managed.ExternalObservation{ResourceExists: false}, nil
	}
	log := ctrl.LoggerFrom(ctx)
	log.Info("Observing Setupkey", "cr", cr)
	setupkey, err := c.service.nbCli.SetupKeys.Get(ctx, externalName)
	if err != nil {
		log.Error(err, "received error on call to nb")
		return managed.ExternalObservation{
			ResourceExists: false,
		}, nil //return nil so that observe can return without error so that it passes to create.
	}

	cr.Status.AtProvider = v1alpha1.NbSetupKeyObservation{
		Id:                  setupkey.Id,
		AllowExtraDnsLabels: setupkey.AllowExtraDnsLabels,
		AutoGroups:          &setupkey.AutoGroups,
		Ephemeral:           setupkey.Ephemeral,
		Expires:             setupkey.Expires.String(),
		LastUsed:            setupkey.LastUsed.String(),
		Name:                setupkey.Name,
		Revoked:             setupkey.Revoked,
		State:               setupkey.State,
		Type:                setupkey.Type,
	}

	cr.Status.SetConditions(xpv1.Available())

	return managed.ExternalObservation{
		ResourceExists:    true,
		ResourceUpToDate:  isUpToDate(&cr.Spec.ForProvider, setupkey, log),
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func isUpToDate(nbSetupKeyParameters *v1alpha1.NbSetupKeyParameters, setupkey *api.SetupKey, log logr.Logger) bool {

	if !reflect.DeepEqual(nbSetupKeyParameters.AutoGroups, setupkey.AutoGroups) {
		log.Info("update failed on auto groups")
		return false
	}
	if !cmp.Equal(nbSetupKeyParameters.Revoked, setupkey.Revoked) {
		log.Info("update failed on revoked")
		return false
	}
	return true
}

func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1alpha1.NbSetupKey)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotNbSetupKey)
	}

	log := ctrl.LoggerFrom(ctx)
	log.Info("Creating Setupkey", "cr", cr)
	setupkey, err := c.service.nbCli.SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
		Name:                cr.Spec.ForProvider.Name,
		AllowExtraDnsLabels: &cr.Spec.ForProvider.AllowExtraDnsLabels,
		AutoGroups:          cr.Spec.ForProvider.AutoGroups,
		Ephemeral:           &cr.Spec.ForProvider.Ephemeral,
		ExpiresIn:           cr.Spec.ForProvider.ExpiresIn,
		Type:                cr.Spec.ForProvider.Type,
		UsageLimit:          cr.Spec.ForProvider.UsageLimit,
	})

	if err != nil {
		log.Error(err, "err creating setupkey")
		return managed.ExternalCreation{
			// Optionally return any details that may be required to connect to the
			// external resource. These will be stored as the connection secret.
			ConnectionDetails: managed.ConnectionDetails{},
		}, err
	}
	log.Info("created Setupkey", "setupkey", setupkey)
	meta.SetExternalName(cr, setupkey.Id)
	cd := managed.ConnectionDetails{xpv1.ResourceCredentialsSecretPasswordKey: []byte(setupkey.Key)}
	return managed.ExternalCreation{
		// Optionally return any details that may be required to connect to the
		// external resource. These will be stored as the connection secret.
		ConnectionDetails: cd,
	}, nil
}

func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1alpha1.NbSetupKey)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotNbSetupKey)
	}

	log := ctrl.LoggerFrom(ctx)
	log.Info("Updating Setupkey", "cr", cr)
	setupKeyId := meta.GetExternalName(cr)
	if setupKeyId == "" {
		return managed.ExternalUpdate{}, errors.New("can't find setupKeyId")
	}
	_, err := c.service.nbCli.SetupKeys.Update(ctx, setupKeyId, api.PutApiSetupKeysKeyIdJSONRequestBody{
		AutoGroups: cr.Spec.ForProvider.AutoGroups,
		Revoked:    cr.Spec.ForProvider.Revoked,
	})

	if err != nil {
		return managed.ExternalUpdate{}, err
	}
	return managed.ExternalUpdate{
		// Optionally return any details that may be required to connect to the
		// external resource. These will be stored as the connection secret.
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Delete(ctx context.Context, mg resource.Managed) error {
	cr, ok := mg.(*v1alpha1.NbSetupKey)
	if !ok {
		return errors.New(errNotNbSetupKey)
	}

	log := ctrl.LoggerFrom(ctx)
	log.Info("Deleting Setupkey", "cr", cr)

	return c.service.nbCli.SetupKeys.Delete(ctx, meta.GetExternalName(cr))
}
