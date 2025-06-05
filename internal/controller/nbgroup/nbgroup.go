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

package nbgroup

import (
	"context"

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
	nbapi "github.com/netbirdio/netbird/management/server/http/api"
)

const (
	errNotNbGroup   = "managed resource is not a NbGroup custom resource"
	errTrackPCUsage = "cannot track ProviderConfig usage"
	errGetPC        = "cannot get ProviderConfig"
	errGetCreds     = "cannot get credentials"
)

// Setup adds a controller that reconciles NbGroup managed resources.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(v1alpha1.NbGroupGroupKind)

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
		resource.ManagedKind(v1alpha1.NbGroupGroupVersionKind),
		reconcilerOptions...,
	)

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		WithEventFilter(resource.DesiredStateChanged()).
		For(&v1alpha1.NbGroup{}).
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
	_, ok := mg.(*v1alpha1.NbGroup)
	if !ok {
		return nil, errors.New(errNotNbGroup)
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
		log:         ctrl.Log.WithName("provider-nbgroup"),
	}, nil
}

// An ExternalClient observes, then either creates, updates, or deletes an
// external resource to ensure it reflects the managed resource's desired state.
type external struct {
	authManager *auth.AuthManager
	log         logr.Logger
}

func (c *external) Observe(ctx context.Context, mg resource.Managed) (managed.ExternalObservation, error) {

	cr, ok := mg.(*v1alpha1.NbGroup)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotNbGroup)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, "failed to get authenticated client")
	}
	c.log.Info("Observing", "cr", cr)
	externalName := meta.GetExternalName(cr)
	if externalName == "" {
		c.log.Info("external name blank")
		return managed.ExternalObservation{ResourceExists: false}, nil
	}
	c.log.Info("external name", "externalName", externalName)
	var group nbapi.Group

	//this only happens on first observe of resource that needs to be created
	if externalName == cr.Name {
		return managed.ExternalObservation{ResourceExists: false}, nil
	}
	//by convention, for provider name = external name for existing resources with observe only
	if externalName == cr.Spec.ForProvider.Name {
		if meta.WasDeleted(mg) {
			return managed.ExternalObservation{ResourceExists: false}, nil
		}
		c.log.Info("looking for existing group", "group", cr.Spec.ForProvider.Name)
		groups, err := client.Groups.List(ctx)
		if err != nil {
			c.log.Error(err, "received error on call to nb listing groups")
			return managed.ExternalObservation{ResourceExists: false}, err
		}
		for _, apigroup := range groups {
			if apigroup.Name == externalName {
				c.log.Info("found existing groupid", "groupid", apigroup.Id)
				group = apigroup
				break
			}
		}
		meta.SetExternalName(cr, group.Id)
	} else //now we are going to find by id using externalname assuming that this is a resource originally created by this provider
	{
		apigroup, err := client.Groups.Get(ctx, externalName)
		if err != nil {
			c.log.Error(err, "received error on call to nb to get group", "group", externalName)
			return managed.ExternalObservation{
				ResourceExists: false,
			}, nil //return nil so that observe can return without error so that it passes to create.
		}
		group = *apigroup
	}
	cr.Status.SetConditions(xpv1.Available())
	c.log.Info("setting atprovider")
	cr.Status.AtProvider = v1alpha1.NbGroupObservation{
		Id:             group.Id,
		Issued:         group.Issued,
		Peers:          group.Peers,
		PeersCount:     group.PeersCount,
		Resources:      group.Resources,
		ResourcesCount: group.ResourcesCount,
	}
	c.log.Info("set atprovider id", "id", cr.Status.AtProvider.Id)
	return managed.ExternalObservation{
		ResourceExists:   true,
		ResourceUpToDate: true, //since we don't update groups
	}, nil
}

func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1alpha1.NbGroup)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotNbGroup)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return managed.ExternalCreation{}, errors.Wrap(err, "failed to get authenticated client")
	}
	c.log.Info("Creating", "cr", cr)
	group, err := client.Groups.Create(ctx, nbapi.GroupRequest{
		Name: cr.Spec.ForProvider.Name,
	})

	if err != nil {
		return managed.ExternalCreation{
			// Optionally return any details that may be required to connect to the
			// external resource. These will be stored as the connection secret.
			ConnectionDetails: managed.ConnectionDetails{},
		}, err
	}
	c.log.Info("group created", "group", group)
	meta.SetExternalName(cr, group.Id)
	return managed.ExternalCreation{}, nil
}

// we don't update group
func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1alpha1.NbGroup)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotNbGroup)
	}
	c.log.Info("Updating", "cr", cr) //no fields update on group
	return managed.ExternalUpdate{
		// Optionally return any details that may be required to connect to the
		// external resource. These will be stored as the connection secret.
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Delete(ctx context.Context, mg resource.Managed) error {
	cr, ok := mg.(*v1alpha1.NbGroup)
	if !ok {
		return errors.New(errNotNbGroup)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to get authenticated client")
	}
	c.log.Info("Deleting", "cr", cr)
	return client.Groups.Delete(ctx, meta.GetExternalName(cr))
}
