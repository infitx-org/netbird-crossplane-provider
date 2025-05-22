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
	"fmt"

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
	nbcontrol "github.com/crossplane/netbird-crossplane-provider/internal/controller/nb"

	"github.com/crossplane/netbird-crossplane-provider/apis/vpn/v1alpha1"
	"github.com/crossplane/netbird-crossplane-provider/internal/features"
	netbird "github.com/netbirdio/netbird/management/client/rest"
	nbapi "github.com/netbirdio/netbird/management/server/http/api"
)

const (
	errNotNbUser    = "managed resource is not a NbUser custom resource"
	errTrackPCUsage = "cannot track ProviderConfig usage"
	errGetPC        = "cannot get ProviderConfig"
	errGetCreds     = "cannot get credentials"

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

// Setup adds a controller that reconciles NbUser managed resources.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(v1alpha1.NbUserGroupKind)

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
	cr, ok := mg.(*v1alpha1.NbUser)
	if !ok {
		return nil, errors.New(errNotNbUser)
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
	cr, ok := mg.(*v1alpha1.NbUser)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotNbUser)
	}
	users, err := c.service.nbCli.Users.List(ctx)
	if err != nil {
		fmt.Printf("received error on call to nb: %+v", err)
		return managed.ExternalObservation{
			ResourceExists: false,
		}, err
	}
	var apiuser *nbapi.User
	if !*cr.Spec.ForProvider.IsServiceUser {
		for _, user := range users {
			if cr.Spec.ForProvider.Email != "" && user.Email == cr.Spec.ForProvider.Email {
				apiuser = &user
			}
		}
		if apiuser == nil {
			return managed.ExternalObservation{
				ResourceExists: false,
			}, errors.New("user doesn't exist")
		}
	} else {
		for _, user := range users {
			if user.Name == cr.Spec.ForProvider.Name {
				apiuser = &user
			}
		}
		if apiuser == nil {
			return managed.ExternalObservation{
				ResourceExists: false,
			}, nil
		}
	}

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
		Permissions: &v1alpha1.UserPermissions{
			DashboardView: (*v1alpha1.UserPermissionsDashboardView)(apiuser.Permissions.DashboardView),
		},
		Status: v1alpha1.UserStatus(apiuser.Status),
	}
	if !*cr.Spec.ForProvider.IsServiceUser {
		meta.SetExternalName(cr, apiuser.Id)
	}
	uptodate := IsUserUpToDate(cr.Spec.ForProvider, *apiuser)
	cr.Status.SetConditions(xpv1.Available())

	return managed.ExternalObservation{
		ResourceExists:    true,
		ResourceUpToDate:  uptodate,
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1alpha1.NbUser)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotNbUser)
	}

	fmt.Printf("Creating: %+v", cr)
	if *cr.Spec.ForProvider.IsServiceUser {
		serviceUser, err := c.service.nbCli.Users.Create(ctx, nbapi.PostApiUsersJSONRequestBody{
			IsServiceUser: *cr.Spec.ForProvider.IsServiceUser,
			Name:          &cr.Spec.ForProvider.Name,
			Role:          cr.Spec.ForProvider.Role,
			AutoGroups:    *cr.Spec.ForProvider.AutoGroups,
		})
		if err != nil {
			fmt.Printf("received error on call to nb: %+v", err)
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

	fmt.Printf("Updating: %+v", cr)
	_, err := c.service.nbCli.Users.Update(ctx, meta.GetExternalName(cr), nbapi.PutApiUsersUserIdJSONRequestBody{
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

	fmt.Printf("Deleting: %+v", cr)
	if *cr.Spec.ForProvider.IsServiceUser {
		err := c.service.nbCli.Users.Delete(ctx, meta.GetExternalName(cr))
		if err != nil {
			return err
		}
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
