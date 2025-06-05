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

package auth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/crossplane/crossplane-runtime/pkg/resource"
	netbird "github.com/netbirdio/netbird/management/client/rest"

	apisv1alpha1 "github.com/crossplane/netbird-crossplane-provider/apis/v1alpha1"
)

const (
	errTrackPCUsage = "cannot track ProviderConfig usage"
	errGetCreds     = "cannot get credentials"
)

// AuthManager handles authentication and token refresh for NetBird API
type AuthManager struct {
	mu            sync.Mutex
	client        *netbird.Client
	oauthConfig   string
	issuerURL     string
	credType      string
	endpoint      string
	lastTokenTime time.Time
	expiresIn     time.Duration
	log           logr.Logger
}

// TokenResponse represents the OAuth token response
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"` // Lifetime in seconds
}

// NewAuthManager creates a new authentication manager
func NewAuthManager(endpoint, creds, credType, issuerURL string) *AuthManager {
	return &AuthManager{
		oauthConfig: creds,
		issuerURL:   issuerURL,
		credType:    credType,
		endpoint:    endpoint,
		log:         ctrl.Log.WithName("auth-manager"),
	}
}

// GetClient returns a valid authenticated client, refreshing token if needed
func (a *AuthManager) GetClient(ctx context.Context) (*netbird.Client, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.log.Info("GetClient", "a.client", a.client)
	if a.client == nil || a.tokenNeedsRefresh() {
		a.log.Info("Refreshing NetBird API token")
		if err := a.refreshToken(ctx); err != nil {
			return nil, errors.Wrap(err, "failed to refresh token")
		}
	}
	return a.client, nil
}

func (a *AuthManager) tokenNeedsRefresh() bool {
	// Refresh if token is expired or will expire in 5 minutes
	a.log.Info("a.lastTokenTime", "a.lastTokenTime", a.lastTokenTime)
	a.log.Info("a.expiresIn", "a.expiresIn", a.expiresIn)
	return time.Since(a.lastTokenTime) > (a.expiresIn - 5*time.Minute)
}

func (a *AuthManager) refreshToken(ctx context.Context) error {
	var token string
	var expiresIn time.Duration
	var err error

	switch a.credType {
	case "oauth":
		token, expiresIn, err = a.getOauthToken(ctx)
		if err != nil {
			return errors.Wrap(err, "failed to get OAuth token")
		}
	default:
		// For non-OAuth credentials (like JWT), use directly
		token = a.oauthConfig
		expiresIn = 24 * time.Hour
	}

	a.client = netbird.NewWithBearerToken(a.endpoint, token)
	a.lastTokenTime = time.Now()
	a.expiresIn = expiresIn
	a.log.Info("Token refreshed", "a.lastTokenTime", a.lastTokenTime)
	return nil
}

func (a *AuthManager) getOauthToken(ctx context.Context) (string, time.Duration, error) {
	var tokenRequest struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		GrantType    string `json:"grant_type"`
		Scope        string `json:"scope"`
	}

	if err := json.Unmarshal([]byte(a.oauthConfig), &tokenRequest); err != nil {
		return "", 0, errors.Wrap(err, "failed to unmarshal OAuth config")
	}

	formBody := url.Values{}
	formBody.Set("client_id", tokenRequest.ClientID)
	formBody.Set("client_secret", tokenRequest.ClientSecret)
	formBody.Set("grant_type", tokenRequest.GrantType)
	formBody.Set("scope", tokenRequest.Scope)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.issuerURL, strings.NewReader(formBody.Encode()))
	if err != nil {
		return "", 0, errors.Wrap(err, "failed to create token request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", 0, errors.Wrap(err, "failed to request token")
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		return "", 0, errors.Errorf("token request failed: %s: %s", res.Status, string(body))
	}

	respBody, err := io.ReadAll(res.Body)
	if err != nil {
		return "", 0, errors.Wrap(err, "failed to read token response")
	}

	var tokenResponse TokenResponse
	if err := json.Unmarshal(respBody, &tokenResponse); err != nil {
		return "", 0, errors.Wrap(err, "failed to unmarshal token response")
	}
	ttl := time.Duration(tokenResponse.ExpiresIn) * time.Second
	return tokenResponse.AccessToken, ttl, nil
}

// SharedConnector provides common authentication logic for all controllers
type SharedConnector struct {
	kube      client.Client
	usage     resource.Tracker
	newAuthFn func(endpoint, creds, credType, issuerURL string) *AuthManager
	cache     sync.Map
}

// NewSharedConnector creates a new shared connector instance
func NewSharedConnector(kube client.Client, usage resource.Tracker) *SharedConnector {
	return &SharedConnector{
		kube:      kube,
		usage:     usage,
		newAuthFn: NewAuthManager,
		cache:     sync.Map{},
	}
}

// Connect handles the common connection logic for all controllers
func (c *SharedConnector) Connect(ctx context.Context, mg resource.Managed, pc *apisv1alpha1.ProviderConfig) (*AuthManager, error) {
	if err := c.usage.Track(ctx, mg); err != nil {
		return nil, errors.Wrap(err, errTrackPCUsage)
	}

	cd := pc.Spec.Credentials
	data, err := resource.CommonCredentialExtractor(ctx, cd.Source, c.kube, cd.CommonCredentialSelectors)
	if err != nil {
		return nil, errors.Wrap(err, errGetCreds)
	}
	// Create cache key based on ProviderConfig UID
	cacheKey := string(pc.UID)

	// Load or create AuthManager
	if manager, ok := c.cache.Load(cacheKey); ok {
		return manager.(*AuthManager), nil
	}

	manager := c.newAuthFn(
		pc.Spec.ManagementURI,
		string(data),
		pc.Spec.CredentialsType,
		pc.Spec.OauthIssuerUrl,
	)
	c.cache.Store(cacheKey, manager)
	return manager, nil
}

// GetProviderConfig retrieves the ProviderConfig for a managed resource
func (c *SharedConnector) GetProviderConfig(ctx context.Context, mg resource.Managed) (*apisv1alpha1.ProviderConfig, error) {
	pc := &apisv1alpha1.ProviderConfig{}
	if err := c.kube.Get(ctx, types.NamespacedName{Name: mg.GetProviderConfigReference().Name}, pc); err != nil {
		return nil, errors.Wrap(err, "cannot get ProviderConfig")
	}
	return pc, nil
}
