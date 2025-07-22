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
	"time"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	ctrl "sigs.k8s.io/controller-runtime"

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
	auth "github.com/crossplane/netbird-crossplane-provider/internal/controller/nb"
	"github.com/crossplane/netbird-crossplane-provider/internal/features"
	"github.com/netbirdio/netbird/management/server/http/api"
)

const (
	errNotNbSetupKey = "managed resource is not a NbSetupKey custom resource"
	errTrackPCUsage  = "cannot track ProviderConfig usage"
	errGetPC         = "cannot get ProviderConfig"
	errGetCreds      = "cannot get credentials"
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
			SharedConnector: auth.NewSharedConnector(
				mgr.GetClient(),
				resource.NewProviderConfigUsageTracker(mgr.GetClient(), &apisv1alpha1.ProviderConfigUsage{}),
			),
		}),
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
	*auth.SharedConnector
}

// Connect typically produces an ExternalClient by:
// 1. Tracking that the managed resource is using a ProviderConfig.
// 2. Getting the managed resource's ProviderConfig.
// 3. Getting the credentials specified by the ProviderConfig.
// 4. Using the credentials to form a client.
func (c *connector) Connect(ctx context.Context, mg resource.Managed) (managed.ExternalClient, error) {
	_, ok := mg.(*v1alpha1.NbSetupKey)
	if !ok {
		return nil, errors.New(errNotNbSetupKey)
	}

	pc, err := c.SharedConnector.GetProviderConfig(ctx, mg)
	if err != nil {
		return nil, err
	}

	authManager, err := c.SharedConnector.Connect(ctx, mg, pc)
	if err != nil {
		return nil, err
	}

	return &external{
		authManager: authManager,
		log:         ctrl.Log.WithName("provider-nbsetupkey"),
	}, nil
}

// An ExternalClient observes, then either creates, updates, or deletes an
// external resource to ensure it reflects the managed resource's desired state.
type external struct {
	authManager *auth.AuthManager
	log         logr.Logger
}

func (c *external) Observe(ctx context.Context, mg resource.Managed) (managed.ExternalObservation, error) {
	cr, ok := mg.(*v1alpha1.NbSetupKey)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotNbSetupKey)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, "failed to get authenticated client")
	}
	c.log.Info("Observing", "cr", cr)
	externalName := meta.GetExternalName(cr)

	if externalName == "" {
		return managed.ExternalObservation{ResourceExists: false}, nil
	}

	// If we have an external name, fetch by ID
	setupkey, err := client.SetupKeys.Get(ctx, externalName)
	if err != nil {
		if auth.IsTokenInvalidError(err) {
			c.authManager.ForceRefresh(ctx)
			return managed.ExternalObservation{}, err
		}
		c.log.Info("setupkey not found")
		return managed.ExternalObservation{
			ResourceExists: false,
		}, nil //return nil so that observe can return without error so that it passes to create.
	}

	if setupkey.Expires.Before(time.Now()) || setupkey.Revoked {
		// Token setupkey exists but is expired or revoked: trigger Update, not Create
		return managed.ExternalObservation{
			ResourceExists:   true,
			ResourceUpToDate: false,
		}, nil
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
		ResourceUpToDate:  true,
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

// func isUpToDate(nbSetupKeyParameters *v1alpha1.NbSetupKeyParameters, setupkey *api.SetupKey, log logr.Logger) bool {

// 	if !reflect.DeepEqual(nbSetupKeyParameters.AutoGroups, setupkey.AutoGroups) {
// 		log.Info("update failed on auto groups")
// 		return false
// 	}
// 	if !cmp.Equal(nbSetupKeyParameters.Revoked, setupkey.Revoked) {
// 		log.Info("update failed on revoked")
// 		return false
// 	}
// 	return true
// }

func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1alpha1.NbSetupKey)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotNbSetupKey)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return managed.ExternalCreation{}, errors.Wrap(err, "failed to get authenticated client")
	}
	c.log.Info("Creating", "cr", cr)
	setupkey, err := client.SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
		Name:                cr.Spec.ForProvider.Name,
		AllowExtraDnsLabels: &cr.Spec.ForProvider.AllowExtraDnsLabels,
		AutoGroups:          cr.Spec.ForProvider.AutoGroups,
		Ephemeral:           &cr.Spec.ForProvider.Ephemeral,
		ExpiresIn:           cr.Spec.ForProvider.ExpiresIn,
		Type:                cr.Spec.ForProvider.Type,
		UsageLimit:          cr.Spec.ForProvider.UsageLimit,
	})

	if err != nil {
		return managed.ExternalCreation{
			// Optionally return any details that may be required to connect to the
			// external resource. These will be stored as the connection secret.
			ConnectionDetails: managed.ConnectionDetails{},
		}, err
	}
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
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return managed.ExternalUpdate{}, errors.Wrap(err, "failed to get authenticated client")
	}
	c.log.Info("Updating", "cr", cr)
	setupKeyId := meta.GetExternalName(cr)
	if setupKeyId == "" {
		return managed.ExternalUpdate{}, errors.New("can't find setupKeyId")
	}
	if err := client.SetupKeys.Delete(ctx, setupKeyId); err != nil {
		return managed.ExternalUpdate{}, errors.Wrap(err, "failed to delete expired setupkey")
	}
	meta.SetExternalName(cr, "")
	return managed.ExternalUpdate{
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Delete(ctx context.Context, mg resource.Managed) error {
	cr, ok := mg.(*v1alpha1.NbSetupKey)
	if !ok {
		return errors.New(errNotNbSetupKey)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to get authenticated client")
	}
	c.log.Info("Deleting", "cr", cr)

	err = client.SetupKeys.Delete(ctx, meta.GetExternalName(cr))
	if err != nil {
		return err
	}

	return nil
}
