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

package nbpolicy

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
	"github.com/google/go-cmp/cmp"
	netbird "github.com/netbirdio/netbird/management/client/rest"
	nbapi "github.com/netbirdio/netbird/management/server/http/api"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	errNotNbPolicy  = "managed resource is not a NbPolicy custom resource"
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

// Setup adds a controller that reconciles NbPolicy managed resources.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(v1alpha1.NbPolicyGroupKind)

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
		resource.ManagedKind(v1alpha1.NbPolicyGroupVersionKind),
		reconcilerOptions...,
	)
	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		WithEventFilter(resource.DesiredStateChanged()).
		For(&v1alpha1.NbPolicy{}).
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
	cr, ok := mg.(*v1alpha1.NbPolicy)
	if !ok {
		return nil, errors.New(errNotNbPolicy)
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
	cr, ok := mg.(*v1alpha1.NbPolicy)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotNbPolicy)
	}

	// These fmt statements should be removed in the real implementation.
	fmt.Printf("Observing: %+v", cr)

	externalName := meta.GetExternalName(cr)
	if externalName == "" {
		return managed.ExternalObservation{ResourceExists: false}, nil
	}
	policy, err := c.service.nbCli.Policies.Get(ctx, externalName)
	if err != nil {
		fmt.Printf("received error on call to nb: %+v", err)
		return managed.ExternalObservation{
			ResourceExists: false,
		}, nil //return nil so that observe can return without error so that it passes to create.
	}
	uptodate := IsApiToNBPolicyUpToDate(cr.Status.AtProvider, policy)
	cr.Status.AtProvider = v1alpha1.NbPolicyObservation{
		Id:                  policy.Id,
		Enabled:             policy.Enabled,
		Description:         policy.Description,
		Name:                policy.Name,
		Rules:               ApiToNBRules(policy.Rules),
		SourcePostureChecks: &policy.SourcePostureChecks,
	}

	cr.Status.SetConditions(xpv1.Available())

	return managed.ExternalObservation{
		ResourceExists:   true,
		ResourceUpToDate: uptodate,
	}, nil
}

func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1alpha1.NbPolicy)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotNbPolicy)
	}

	fmt.Printf("Creating: %+v", cr)
	groups, err := c.service.nbCli.Groups.List(ctx)
	if err != nil {
		return managed.ExternalCreation{}, err
	}
	policy, err := c.service.nbCli.Policies.Create(ctx, nbapi.PostApiPoliciesJSONRequestBody{
		Name:                cr.Spec.ForProvider.Name,
		Description:         cr.Spec.ForProvider.Description,
		Enabled:             cr.Spec.ForProvider.Enabled,
		SourcePostureChecks: cr.Spec.ForProvider.SourcePostureChecks,
		Rules:               NbToApiRules(&cr.Spec.ForProvider.Rules, groups),
	})
	if err != nil {
		fmt.Printf("err creating policy: %+v", err)
		return managed.ExternalCreation{
			// Optionally return any details that may be required to connect to the
			// external resource. These will be stored as the connection secret.
			ConnectionDetails: managed.ConnectionDetails{},
		}, err
	}
	meta.SetExternalName(cr, *policy.Id)
	return managed.ExternalCreation{
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1alpha1.NbPolicy)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotNbPolicy)
	}

	fmt.Printf("Updating: %+v", cr)

	return managed.ExternalUpdate{
		// Optionally return any details that may be required to connect to the
		// external resource. These will be stored as the connection secret.
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Delete(ctx context.Context, mg resource.Managed) error {
	cr, ok := mg.(*v1alpha1.NbPolicy)
	if !ok {
		return errors.New(errNotNbPolicy)
	}

	fmt.Printf("Deleting: %+v", cr)
	policyid := meta.GetExternalName(cr)
	return c.service.nbCli.Policies.Delete(ctx, policyid)
}

func NbToApiRules(policyRule *[]v1alpha1.PolicyRule, groups []nbapi.Group) []nbapi.PolicyRuleUpdate {
	fmt.Printf("Creating rules")
	rules := make([]nbapi.PolicyRuleUpdate, len(*policyRule))
	for i, prule := range *policyRule {
		rules[i] = nbapi.PolicyRuleUpdate{
			Action:        nbapi.PolicyRuleUpdateAction(prule.Action),
			Bidirectional: prule.Bidirectional,
			Description:   prule.Description,
			Destinations:  NbToApiGroupMinimums(prule.Destinations, groups),
			Enabled:       prule.Enabled,
			Id:            prule.Id,
			Name:          prule.Name,
			PortRanges:    NbToApiPortRanges(prule.PortRanges),
			Ports:         prule.Ports,
			Protocol:      nbapi.PolicyRuleUpdateProtocol(prule.Protocol),
			Sources:       NbToApiGroupMinimums(prule.Sources, groups),
		}
	}
	return rules
}

func NbToApiPortRanges(rulePortRange *[]v1alpha1.RulePortRange) *[]nbapi.RulePortRange {
	rportrange := make([]nbapi.RulePortRange, len(*rulePortRange))
	for i, rulePort := range *rulePortRange {
		rportrange[i] = nbapi.RulePortRange{
			End:   rulePort.End,
			Start: rulePort.Start,
		}
	}
	return &rportrange
}

func NbToApiGroupMinimums(groupMinimums *[]v1alpha1.GroupMinimum, groups []nbapi.Group) *[]string {
	ids := make([]string, len(*groupMinimums))
	for i, gmin := range *groupMinimums {
		for _, group := range groups {
			if group.Name == *gmin.Name {
				ids[i] = group.Id
				break
			}
		}
	}
	return &ids
}

func IsApiToNBPolicyUpToDate(nbPolicyObservation v1alpha1.NbPolicyObservation, policy *nbapi.Policy) bool {
	return cmp.Equal(nbPolicyObservation.Enabled, policy.Enabled)
}
func ApiToNBRules(p []nbapi.PolicyRule) *[]v1alpha1.PolicyRule {
	rules := make([]v1alpha1.PolicyRule, len(p))
	for i, prule := range p {
		rules[i] = v1alpha1.PolicyRule{
			Action:        string(prule.Action),
			Bidirectional: prule.Bidirectional,
			Description:   prule.Description,
			Destinations:  ApiToNBGroupMinimums(prule.Destinations),
			Enabled:       prule.Enabled,
			Id:            prule.Id,
			Name:          prule.Name,
			PortRanges:    ApiToNBPortRanges(prule.PortRanges),
			Ports:         prule.Ports,
			Protocol:      string(prule.Protocol),
			Sources:       ApiToNBGroupMinimums(prule.Sources),
		}
	}
	return &rules
}

func ApiToNBPortRanges(rulePortRange *[]nbapi.RulePortRange) *[]v1alpha1.RulePortRange {
	rportrange := make([]v1alpha1.RulePortRange, len(*rulePortRange))
	for i, rulePort := range *rulePortRange {
		rportrange[i] = v1alpha1.RulePortRange{
			End:   rulePort.End,
			Start: rulePort.Start,
		}
	}
	return &rportrange
}

func ApiToNBGroupMinimums(groupMinimum *[]nbapi.GroupMinimum) *[]v1alpha1.GroupMinimum {
	groupminimums := make([]v1alpha1.GroupMinimum, len(*groupMinimum))
	for i, gmin := range *groupMinimum {
		groupminimums[i] = v1alpha1.GroupMinimum{
			Id:             &gmin.Id,
			Name:           &gmin.Name,
			Issued:         (*string)(gmin.Issued),
			PeersCount:     gmin.PeersCount,
			ResourcesCount: gmin.ResourcesCount,
		}
	}
	return &groupminimums
}
