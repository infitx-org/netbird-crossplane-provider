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
	"time"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"

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
	auth "github.com/crossplane/netbird-crossplane-provider/internal/controller/nb"
	"github.com/crossplane/netbird-crossplane-provider/internal/features"
	netbird "github.com/netbirdio/netbird/management/client/rest"
	nbapi "github.com/netbirdio/netbird/management/server/http/api"
)

const (
	errNotNbAccessToken  = "managed resource is not a NbAccessToken custom resource"
	accessTokenSecretKey = "NB_API_KEY"
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
	*auth.SharedConnector
}

// Connect typically produces an ExternalClient by:
// 1. Tracking that the managed resource is using a ProviderConfig.
// 2. Getting the managed resource's ProviderConfig.
// 3. Getting the credentials specified by the ProviderConfig.
// 4. Using the credentials to form a client.
func (c *connector) Connect(ctx context.Context, mg resource.Managed) (managed.ExternalClient, error) {
	_, ok := mg.(*v1alpha1.NbAccessToken)
	if !ok {
		return nil, errors.New(errNotNbAccessToken)
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
		log:         ctrl.Log.WithName("provider-nbaccesstoken"),
	}, nil
}

type external struct {
	authManager *auth.AuthManager
	log         logr.Logger
}

func (c *external) Observe(ctx context.Context, mg resource.Managed) (managed.ExternalObservation, error) {
	cr, ok := mg.(*v1alpha1.NbAccessToken)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotNbAccessToken)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, "failed to get authenticated client")
	}
	// These fmt statements should be removed in the real implementation.
	c.log.Info("Observing", "cr", cr)
	externalName := meta.GetExternalName(cr)
	if externalName == "" {
		c.log.Info("didn't find externalname")
		return managed.ExternalObservation{ResourceExists: false}, nil
	}
	var userid string
	if cr.Spec.ForProvider.UserName != nil {
		users, err := client.Users.List(ctx)
		if err != nil {
			return managed.ExternalObservation{
				ResourceExists: false,
			}, err
		}
		var apiuser *nbapi.User
		for _, user := range users {
			if *user.IsServiceUser && (user.Name == *cr.Spec.ForProvider.UserName) {
				apiuser = &user
			}
		}
		if apiuser == nil {
			return managed.ExternalObservation{
				ResourceExists: false,
			}, errors.New("username doesn't exist")
		}
		userid = apiuser.Id
	} else {
		userid = *cr.Spec.ForProvider.UserId
	}

	accesstoken, err := client.Tokens.Get(ctx, userid, externalName)
	if err != nil {
		c.log.Error(err, "received error on call to nb to get accesstoken", "accesstoken", accesstoken)
		return managed.ExternalObservation{
			ResourceExists: false,
		}, nil
	}
	var lastused *string
	if accesstoken.LastUsed != nil {
		lastusedstring := accesstoken.LastUsed.Local().String()
		lastused = &lastusedstring
	}
	if accesstoken.ExpirationDate.Before(time.Now()) {
		cr.Status.AtProvider = v1alpha1.NbAccessTokenObservation{}
		cr.Status.SetConditions(xpv1.Condition{Type: "Expired",
			Status:             v1.ConditionTrue,
			Reason:             "TimestampExpired",
			Message:            "Resource has expired and needs recreation",
			LastTransitionTime: metav1.Now(),
		})
		return managed.ExternalObservation{
			ResourceExists:    true,
			ResourceUpToDate:  false,
			ConnectionDetails: managed.ConnectionDetails{},
		}, nil
	}
	cr.Status.AtProvider = v1alpha1.NbAccessTokenObservation{
		Id:             accesstoken.Id,
		CreatedAt:      accesstoken.CreatedBy,
		ExpirationDate: accesstoken.ExpirationDate.Local().String(),
		CreatedBy:      accesstoken.CreatedBy,
		LastUsed:       lastused,
		Name:           accesstoken.Name,
	}
	cr.Status.SetConditions(xpv1.Available(), xpv1.Condition{Type: "Expired",
		Status:             v1.ConditionFalse,
		Reason:             "TimestampExpired",
		Message:            "Resource has expired and needs recreation",
		LastTransitionTime: metav1.Now(),
	})
	return managed.ExternalObservation{
		ResourceExists:    true,
		ResourceUpToDate:  true,
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) getUserID(ctx context.Context, cr *v1alpha1.NbAccessToken, client *netbird.Client) (string, error) {
	if cr.Spec.ForProvider.UserName != nil {

		users, err := client.Users.List(ctx)
		if err != nil {
			return "", errors.Wrap(err, "failed to list users")
		}
		for _, user := range users {
			if user.Name == *cr.Spec.ForProvider.UserName {
				return user.Id, nil
			}
		}
		return "", errors.New("user not found")
	}
	return *cr.Spec.ForProvider.UserId, nil
}

func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1alpha1.NbAccessToken)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotNbAccessToken)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return managed.ExternalCreation{}, errors.Wrap(err, "failed to get authenticated client")
	}
	c.log.Info("Creating", "cr", cr)
	var userid string
	if cr.Spec.ForProvider.UserName != nil {
		users, err := client.Users.List(ctx)
		if err != nil {
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
	accesstoken, err := client.Tokens.Create(ctx, userid, nbapi.PersonalAccessTokenRequest{
		ExpiresIn: cr.Spec.ForProvider.ExpiresIn,
		Name:      cr.Spec.ForProvider.Name,
	})
	if err != nil {
		return managed.ExternalCreation{}, err
	}
	meta.SetExternalName(cr, accesstoken.PersonalAccessToken.Id)

	cd := managed.ConnectionDetails{
		accessTokenSecretKey: []byte(accesstoken.PlainToken),
	}
	return managed.ExternalCreation{
		// Optionally return any details that may be required to connect to the
		// external resource. These will be stored as the connection secret.
		ConnectionDetails: cd,
	}, nil
}

// for now only called when token expired
func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1alpha1.NbAccessToken)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotNbAccessToken)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return managed.ExternalUpdate{}, errors.Wrap(err, "failed to get authenticated client")
	}

	c.log.Info("Updating", "cr", cr)
	externalName := meta.GetExternalName(cr)
	if externalName == "" {
		return managed.ExternalUpdate{}, errors.New("no externalname found")
	}
	userid, err := c.getUserID(ctx, cr, client)
	if err != nil {
		return managed.ExternalUpdate{}, err
	}

	if err := client.Tokens.Delete(ctx, userid, externalName); err != nil {
		return managed.ExternalUpdate{}, errors.Wrap(err, "failed to delete expired token")
	}
	meta.SetExternalName(cr, "")
	return managed.ExternalUpdate{
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Delete(ctx context.Context, mg resource.Managed) error {
	cr, ok := mg.(*v1alpha1.NbAccessToken)
	if !ok {
		return errors.New(errNotNbAccessToken)
	}
	client, err := c.authManager.GetClient(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to get authenticated client")
	}

	externalName := meta.GetExternalName(cr)
	if externalName == "" {
		return errors.New("no externalname found")
	}
	c.log.Info("Deleting", "cr", cr)
	var userid string
	if cr.Spec.ForProvider.UserName != nil {
		users, err := client.Users.List(ctx)
		if err != nil {
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
	return client.Tokens.Delete(ctx, userid, externalName)
}
