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

package nbuser

import (
	"context"

	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
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
	errNotNbUser    = "managed resource is not a NbUser custom resource"
	errTrackPCUsage = "cannot track ProviderConfig usage"
	errGetPC        = "cannot get ProviderConfig"
	errGetCreds     = "cannot get credentials"
)

// Setup adds a controller that reconciles NbUser managed resources.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(v1alpha1.NbUserGroupKind)

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
		resource.ManagedKind(v1alpha1.NbUserGroupVersionKind),
		reconcilerOptions...,
	)

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		WithEventFilter(resource.DesiredStateChanged()).
		For(&v1alpha1.NbUser{}).
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
	_, ok := mg.(*v1alpha1.NbUser)
	if !ok {
		return nil, errors.New(errNotNbUser)
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
		log:         ctrl.Log.WithName("provider-nbuser"),
	}, nil
}

// An ExternalClient observes, then either creates, updates, or deletes an
// external resource to ensure it reflects the managed resource's desired state.
type external struct {
	authManager *auth.AuthManager
	log         logr.Logger
}

func (c *external) Observe(ctx context.Context, mg resource.Managed) (managed.ExternalObservation, error) {
	cr, ok := mg.(*v1alpha1.NbUser)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotNbUser)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, "failed to get authenticated client")
	}
	c.log.Info("observing", "cr", cr)

	externalName := meta.GetExternalName(cr)
	// Adoption pattern: handle each case separately
	if externalName == "" || externalName == cr.Name {
		c.log.Info("external name blank or matches resource name, attempting adoption by Email or Name")
		users, err := client.Users.List(ctx)
		if err != nil {
			if auth.IsTokenInvalidError(err) {
				c.authManager.ForceRefresh(ctx)
				return managed.ExternalObservation{}, err
			}
			c.log.Info("failed to list users")
			return managed.ExternalObservation{
				ResourceExists: false,
			}, nil //return nil so that observe can return without error so that it passes to create.
		}
		var apiuser *nbapi.User
		if !*cr.Spec.ForProvider.IsServiceUser {
			for _, user := range users {
				if cr.Spec.ForProvider.Email != "" && user.Email == cr.Spec.ForProvider.Email {
					apiuser = &user
					break
				}
			}
		} else {
			for _, user := range users {
				if user.Name == cr.Spec.ForProvider.Name {
					apiuser = &user
					break
				}
			}
		}
		if apiuser != nil {
			c.log.Info("found existing user for adoption", "userid", apiuser.Id)
			meta.SetExternalName(cr, apiuser.Id)
			cr.Status.SetConditions(xpv1.Available())
			cr.Status.AtProvider = v1alpha1.NbUserObservation{
				Id:            apiuser.Id,
				AutoGroups:    &apiuser.AutoGroups,
				Email:         apiuser.Email,
				Role:          apiuser.Role,
				IsBlocked:     apiuser.IsBlocked,
				IsCurrent:     apiuser.IsCurrent,
				IsServiceUser: apiuser.IsServiceUser,
				Issued:        apiuser.Issued,
				Name:          apiuser.Name,
				Status:        v1alpha1.UserStatus(apiuser.Status),
			}
			return managed.ExternalObservation{
				ResourceExists:   true,
				ResourceUpToDate: IsUserUpToDate(cr.Spec.ForProvider, *apiuser),
			}, nil
		}
		// Not found, resource does not exist
		return managed.ExternalObservation{ResourceExists: false}, nil
	}

	if externalName == cr.Spec.ForProvider.Name {
		// Only check for existence, do not set external name
		c.log.Info("external name matches ForProvider.Name, checking existence only", "name", cr.Spec.ForProvider.Name)
		users, err := client.Users.List(ctx)
		if err != nil {
			if auth.IsTokenInvalidError(err) {
				c.authManager.ForceRefresh(ctx)
				return managed.ExternalObservation{}, err
			}
			c.log.Info("failed to list users")
			return managed.ExternalObservation{
				ResourceExists: false,
			}, nil //return nil so that observe can return without error so that it passes to create.
		}
		var apiuser *nbapi.User
		for _, user := range users {
			if user.Name == externalName {
				apiuser = &user
				break
			}
		}
		if apiuser != nil {
			cr.Status.SetConditions(xpv1.Available())
			cr.Status.AtProvider = v1alpha1.NbUserObservation{
				Id:            apiuser.Id,
				AutoGroups:    &apiuser.AutoGroups,
				Email:         apiuser.Email,
				Role:          apiuser.Role,
				IsBlocked:     apiuser.IsBlocked,
				IsCurrent:     apiuser.IsCurrent,
				IsServiceUser: apiuser.IsServiceUser,
				Issued:        apiuser.Issued,
				Name:          apiuser.Name,
				Status:        v1alpha1.UserStatus(apiuser.Status),
			}
			return managed.ExternalObservation{
				ResourceExists:   true,
				ResourceUpToDate: IsUserUpToDate(cr.Spec.ForProvider, *apiuser),
			}, nil
		}
		return managed.ExternalObservation{ResourceExists: false}, nil
	}

	// If externalName is set, fetch by ID as usual
	users, err := client.Users.List(ctx)
	if err != nil {
		if auth.IsTokenInvalidError(err) {
			c.authManager.ForceRefresh(ctx)
			return managed.ExternalObservation{}, err
		}
		c.log.Info("failed to list users")
		return managed.ExternalObservation{
			ResourceExists: false,
		}, nil //return nil so that observe can return without error so that it passes to create.
	}
	var user *nbapi.User
	for _, u := range users {
		if u.Id == externalName {
			user = &u
			break
		}
	}
	if user == nil {
		c.log.Error(nil, "user not found by externalName", "externalName", externalName)
		return managed.ExternalObservation{
			ResourceExists: false,
		}, nil
	}

	cr.Status.AtProvider = v1alpha1.NbUserObservation{
		Id:            user.Id,
		AutoGroups:    &user.AutoGroups,
		Email:         user.Email,
		Role:          user.Role,
		IsBlocked:     user.IsBlocked,
		IsCurrent:     user.IsCurrent,
		IsServiceUser: user.IsServiceUser,
		Issued:        user.Issued,
		Name:          user.Name,
		Status:        v1alpha1.UserStatus(user.Status),
	}
	cr.Status.SetConditions(xpv1.Available())
	return managed.ExternalObservation{
		ResourceExists:   true,
		ResourceUpToDate: IsUserUpToDate(cr.Spec.ForProvider, *user),
	}, nil
}

func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1alpha1.NbUser)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotNbUser)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return managed.ExternalCreation{}, errors.Wrap(err, "failed to get authenticated client")
	}
	c.log.Info("Creating", "cr", cr)
	if *cr.Spec.ForProvider.IsServiceUser {
		serviceUser, err := client.Users.Create(ctx, nbapi.PostApiUsersJSONRequestBody{
			IsServiceUser: *cr.Spec.ForProvider.IsServiceUser,
			Name:          &cr.Spec.ForProvider.Name,
			Role:          cr.Spec.ForProvider.Role,
			AutoGroups:    *cr.Spec.ForProvider.AutoGroups,
		})
		if err != nil {
			return managed.ExternalCreation{}, err
		}
		meta.SetExternalName(cr, serviceUser.Id)
	}
	return managed.ExternalCreation{
		// Optionally return any details that may be required to connect to the
		// external resource. These will be stored as the connection secret.
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1alpha1.NbUser)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotNbUser)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return managed.ExternalUpdate{}, errors.Wrap(err, "failed to get authenticated client")
	}
	c.log.Info("Updating", "cr", cr)
	_, err = client.Users.Update(ctx, meta.GetExternalName(cr), nbapi.PutApiUsersUserIdJSONRequestBody{
		Role:       cr.Spec.ForProvider.Role,
		AutoGroups: *cr.Status.AtProvider.AutoGroups,
		IsBlocked:  false,
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
	cr, ok := mg.(*v1alpha1.NbUser)
	if !ok {
		return errors.New(errNotNbUser)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to get authenticated client")
	}
	c.log.Info("Deleting", "cr", cr)
	if *cr.Spec.ForProvider.IsServiceUser {
		return client.Users.Delete(ctx, meta.GetExternalName(cr))
	}
	return nil
}

func IsUserUpToDate(user v1alpha1.NbUserParameters, apiUser nbapi.User) bool {
	if *user.IsServiceUser {
		if !cmp.Equal(user.Name, apiUser.Name) {
			return false
		}
	}
	if user.Role != "" && !cmp.Equal(user.Role, apiUser.Role) {
		return false
	}
	return true
}
