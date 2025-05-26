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

package nbnameserver

import (
	"context"
	"reflect"

	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"

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
	nbcontrol "github.com/crossplane/netbird-crossplane-provider/internal/controller/nb"

	"github.com/crossplane/netbird-crossplane-provider/apis/vpn/v1alpha1"
	"github.com/crossplane/netbird-crossplane-provider/internal/features"
	netbird "github.com/netbirdio/netbird/management/client/rest"
	nbapi "github.com/netbirdio/netbird/management/server/http/api"
)

const (
	errNotNbNameServer = "managed resource is not a NbNameServer custom resource"
	errTrackPCUsage    = "cannot track ProviderConfig usage"
	errGetPC           = "cannot get ProviderConfig"
	errGetCreds        = "cannot get credentials"

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

// Setup adds a controller that reconciles NbNameServer managed resources.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(v1alpha1.NbNameServerGroupKind)

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
		resource.ManagedKind(v1alpha1.NbNameServerGroupVersionKind),
		reconcilerOptions...,
	)

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		WithEventFilter(resource.DesiredStateChanged()).
		For(&v1alpha1.NbNameServer{}).
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
	cr, ok := mg.(*v1alpha1.NbNameServer)
	if !ok {
		return nil, errors.New(errNotNbNameServer)
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
	cr, ok := mg.(*v1alpha1.NbNameServer)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotNbNameServer)
	}
	log := ctrl.LoggerFrom(ctx)
	// These fmt statements should be removed in the real implementation.
	log.Info("Observing", "cr", cr)

	externalName := meta.GetExternalName(cr)
	if externalName == "" {
		return managed.ExternalObservation{ResourceExists: false}, nil
	}
	nameservergroup, err := c.service.nbCli.DNS.GetNameserverGroup(ctx, externalName)
	if err != nil {
		log.Error(err, "received error on call to nb")
		return managed.ExternalObservation{
			ResourceExists: false,
		}, nil
	}

	cr.Status.AtProvider = v1alpha1.NbNameServerObservation{
		Id:                   nameservergroup.Id,
		Description:          nameservergroup.Description,
		Domains:              nameservergroup.Domains,
		Groups:               nameservergroup.Groups,
		Enabled:              nameservergroup.Enabled,
		Name:                 nameservergroup.Name,
		Nameservers:          *ApitoNbNameServer(nameservergroup.Nameservers),
		Primary:              nameservergroup.Primary,
		SearchDomainsEnabled: nameservergroup.SearchDomainsEnabled,
	}

	cr.Status.SetConditions(xpv1.Available())
	isUpToDate := IsNbNameServerUpToDate(*nameservergroup, *cr, log)
	return managed.ExternalObservation{
		ResourceExists:   true,
		ResourceUpToDate: isUpToDate,
	}, nil
}

func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1alpha1.NbNameServer)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotNbNameServer)
	}
	log := ctrl.LoggerFrom(ctx)
	log.Info("Creating", "cr", cr)
	nameserverGroup, err := c.service.nbCli.DNS.CreateNameserverGroup(ctx, nbapi.PostApiDnsNameserversJSONRequestBody{
		Description:          cr.Spec.ForProvider.Description,
		Domains:              cr.Spec.ForProvider.Domains,
		Groups:               cr.Spec.ForProvider.Groups,
		Enabled:              cr.Spec.ForProvider.Enabled,
		Name:                 cr.Spec.ForProvider.Name,
		Nameservers:          *NbtoApiNameServer(cr.Spec.ForProvider.Nameservers),
		Primary:              cr.Spec.ForProvider.Primary,
		SearchDomainsEnabled: cr.Spec.ForProvider.SearchDomainsEnabled,
	})
	if err != nil {
		return managed.ExternalCreation{}, err
	}
	meta.SetExternalName(cr, nameserverGroup.Id)
	return managed.ExternalCreation{
		// Optionally return any details that may be required to connect to the
		// external resource. These will be stored as the connection secret.
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1alpha1.NbNameServer)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotNbNameServer)
	}
	log := ctrl.LoggerFrom(ctx)
	log.Info("Updating", "cr", cr)

	_, err := c.service.nbCli.DNS.UpdateNameserverGroup(ctx, meta.GetExternalName(cr), nbapi.PutApiDnsNameserversNsgroupIdJSONRequestBody{
		Description:          cr.Spec.ForProvider.Description,
		Domains:              cr.Spec.ForProvider.Domains,
		Groups:               cr.Spec.ForProvider.Groups,
		Enabled:              cr.Spec.ForProvider.Enabled,
		Name:                 cr.Spec.ForProvider.Name,
		Nameservers:          *NbtoApiNameServer(cr.Spec.ForProvider.Nameservers),
		Primary:              cr.Spec.ForProvider.Primary,
		SearchDomainsEnabled: cr.Spec.ForProvider.SearchDomainsEnabled,
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
	cr, ok := mg.(*v1alpha1.NbNameServer)
	if !ok {
		return errors.New(errNotNbNameServer)
	}
	log := ctrl.LoggerFrom(ctx)
	log.Info("Deleting", "cr", cr)
	return c.service.nbCli.DNS.DeleteNameserverGroup(ctx, meta.GetExternalName(cr))
}

func ApitoNbNameServer(p []nbapi.Nameserver) *[]v1alpha1.Nameserver {

	nameservers := make([]v1alpha1.Nameserver, len(p))
	for i, ns := range p {
		nameservers[i] = v1alpha1.Nameserver{
			Ip:     ns.Ip,
			Port:   ns.Port,
			NsType: v1alpha1.NameserverNsType(ns.NsType),
		}
	}
	return &nameservers
}
func NbtoApiNameServer(p []v1alpha1.Nameserver) *[]nbapi.Nameserver {

	nameservers := make([]nbapi.Nameserver, len(p))
	for i, ns := range p {
		nameservers[i] = nbapi.Nameserver{
			Ip:     ns.Ip,
			Port:   ns.Port,
			NsType: nbapi.NameserverNsType(ns.NsType),
		}
	}
	return &nameservers
}
func IsNbNameServerUpToDate(p nbapi.NameserverGroup, ns v1alpha1.NbNameServer, log logr.Logger) bool {
	if !cmp.Equal(p.Description, ns.Spec.ForProvider.Description) {
		log.Info("decription doesn't match")
		return false
	}
	if !reflect.DeepEqual(p.Domains, ns.Spec.ForProvider.Domains) {
		log.Info("domains don't match")
		return false
	}
	if !cmp.Equal(p.Enabled, ns.Spec.ForProvider.Enabled) {
		log.Info("enabled doesn't match")
		return false
	}
	if !reflect.DeepEqual(p.Groups, ns.Spec.ForProvider.Groups) {
		log.Info("groups don't match")
		return false
	}
	if !cmp.Equal(p.Name, ns.Spec.ForProvider.Name) {
		log.Info("name doesn't match")
		return false
	}
	if !cmp.Equal(len(p.Nameservers), len(ns.Spec.ForProvider.Nameservers)) {
		log.Info("nameservers don't match")
		return false
	}
	for i, pns := range p.Nameservers {
		if !cmp.Equal(pns.Ip, ns.Spec.ForProvider.Nameservers[i].Ip) {
			return false
		}
		if !cmp.Equal(string(pns.NsType), string(ns.Spec.ForProvider.Nameservers[i].NsType)) {
			return false
		}
		if !cmp.Equal(pns.Port, ns.Spec.ForProvider.Nameservers[i].Port) {
			return false
		}
	}
	return true
}
