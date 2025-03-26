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

package nbaccount

import (
	"context"
	"fmt"
	"reflect"

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
	apisv1alpha1 "github.com/infitx-org/netbird-crossplane-provider/apis/v1alpha1"
	"github.com/infitx-org/netbird-crossplane-provider/apis/vpn/v1alpha1"
	nbcontrol "github.com/infitx-org/netbird-crossplane-provider/internal/controller/nb"
	"github.com/infitx-org/netbird-crossplane-provider/internal/features"
	netbird "github.com/netbirdio/netbird/management/client/rest"
	"github.com/netbirdio/netbird/management/server/http/api"
)

const (
	errNotNbAccount = "managed resource is not a NbAccount custom resource"
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

// Setup adds a controller that reconciles NbAccount managed resources.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(v1alpha1.NbAccountGroupKind)

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
		resource.ManagedKind(v1alpha1.NbAccountGroupVersionKind),
		reconcilerOptions...,
	)

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		WithEventFilter(resource.DesiredStateChanged()).
		For(&v1alpha1.NbAccount{}).
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
	cr, ok := mg.(*v1alpha1.NbAccount)
	if !ok {
		return nil, errors.New(errNotNbAccount)
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
	cr, ok := mg.(*v1alpha1.NbAccount)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotNbAccount)
	}

	// These fmt statements should be removed in the real implementation.
	fmt.Printf("Observing: %+v", cr)
	//list accounts always returns the only account
	accounts, err := c.service.nbCli.Accounts.List(ctx)
	if err != nil {
		fmt.Printf("received error on call to nb: %+v", err)
		return managed.ExternalObservation{
			ResourceExists: false,
		}, nil
	}
	accountusers, err := c.service.nbCli.Users.List(ctx)
	if err != nil {
		fmt.Printf("received error on call to nb: %+v", err)
		return managed.ExternalObservation{
			ResourceExists: false,
		}, nil
	}
	allgroups, err := c.service.nbCli.Groups.List(ctx)
	if err != nil {
		fmt.Printf("received error on call to nb: %+v", err)
		return managed.ExternalObservation{
			ResourceExists: false,
		}, nil
	}
	account := accounts[0]
	cr.Status.AtProvider = v1alpha1.NbAccountObservation{
		Settings: *ApitoNbAccountSettings(account.Settings),
		UserList: *ApitoNbAccountUsers(accountusers, allgroups),
	}
	meta.SetExternalName(cr, account.Id)
	cr.Status.SetConditions(xpv1.Available())

	return managed.ExternalObservation{
		ResourceExists:    true, //resource always exists
		ResourceUpToDate:  reflect.DeepEqual(cr.Status.AtProvider.Settings, *ApitoNbAccountSettings(account.Settings)),
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

// this method should never be called since we don't create the account, only update settings
func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1alpha1.NbAccount)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotNbAccount)
	}
	fmt.Printf("Creating: %+v", cr)
	return managed.ExternalCreation{
		// Optionally return any details that may be required to connect to the
		// external resource. These will be stored as the connection secret.
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1alpha1.NbAccount)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotNbAccount)
	}

	fmt.Printf("Updating: %+v", cr)
	accountId := meta.GetExternalName(cr)
	if accountId == "" {
		return managed.ExternalUpdate{}, errors.New("can't find accountid")
	}
	accountsettings := NbToApiAccountSettings(cr.Status.AtProvider.Settings)
	_, err := c.service.nbCli.Accounts.Update(ctx, accountId, api.AccountRequest{
		Settings: *accountsettings,
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

// this method should never be called since we don't create/delete the account, only update settings
func (c *external) Delete(ctx context.Context, mg resource.Managed) error {
	cr, ok := mg.(*v1alpha1.NbAccount)
	if !ok {
		return errors.New(errNotNbAccount)
	}

	fmt.Printf("Deleting: %+v", cr)

	return nil
}

func ApitoNbAccountSettings(p api.AccountSettings) *v1alpha1.AccountSettings {
	accountsettings := v1alpha1.AccountSettings{
		Extra:                           (*v1alpha1.AccountExtraSettings)(p.Extra),
		GroupsPropagationEnabled:        p.GroupsPropagationEnabled,
		JwtAllowGroups:                  p.JwtAllowGroups,
		JwtGroupsClaimName:              p.JwtGroupsClaimName,
		JwtGroupsEnabled:                p.JwtGroupsEnabled,
		PeerInactivityExpiration:        p.PeerInactivityExpiration,
		PeerLoginExpiration:             p.PeerLoginExpiration,
		PeerInactivityExpirationEnabled: p.PeerInactivityExpirationEnabled,
		PeerLoginExpirationEnabled:      p.PeerLoginExpirationEnabled,
		RegularUsersViewBlocked:         p.RegularUsersViewBlocked,
		RoutingPeerDnsResolutionEnabled: p.RoutingPeerDnsResolutionEnabled,
	}
	return &accountsettings
}

func NbToApiAccountSettings(p v1alpha1.AccountSettings) *api.AccountSettings {
	accountsettings := api.AccountSettings{
		Extra:                           (*api.AccountExtraSettings)(p.Extra),
		GroupsPropagationEnabled:        p.GroupsPropagationEnabled,
		JwtAllowGroups:                  p.JwtAllowGroups,
		JwtGroupsClaimName:              p.JwtGroupsClaimName,
		JwtGroupsEnabled:                p.JwtGroupsEnabled,
		PeerInactivityExpiration:        p.PeerInactivityExpiration,
		PeerLoginExpiration:             p.PeerLoginExpiration,
		PeerInactivityExpirationEnabled: p.PeerInactivityExpirationEnabled,
		PeerLoginExpirationEnabled:      p.PeerLoginExpirationEnabled,
		RegularUsersViewBlocked:         p.RegularUsersViewBlocked,
		RoutingPeerDnsResolutionEnabled: p.RoutingPeerDnsResolutionEnabled,
	}
	return &accountsettings
}

func ApitoNbAccountUsers(accountusers []api.User, allgroups []api.Group) *[]v1alpha1.NbAccountUser {
	nbaccountusers := make([]v1alpha1.NbAccountUser, len(accountusers))
	for i, accountuser := range accountusers {
		nbaccountusers[i] = v1alpha1.NbAccountUser{
			UserEmail: accountuser.Email,
			Groups:    *GetGroupIds(accountuser.AutoGroups, allgroups),
			Role:      accountuser.Role,
		}
	}
	return &nbaccountusers
}

func GetGroupIds(groupids []string, allgroups []api.Group) *[]string {
	groupnames := make([]string, len(groupids))
	for i, groupid := range groupids {
		for _, group := range allgroups {
			if group.Id == groupid {
				groupnames[i] = group.Name
				break
			}
		}
	}
	return &groupnames
}
