/*
Copyright 2023.

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

package gateway

import (
	"context"
	"errors"
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	serviceApi "github.com/opendatahub-io/opendatahub-operator/v2/api/services/v1alpha1"
)

const (
	ServiceName = serviceApi.GatewayServiceName
)

// AuthenticationMode represents the detected authentication mode of the cluster.
type AuthenticationMode string

const (
	ModeIntegratedOAuth AuthenticationMode = "IntegratedOAuth"
	ModeOIDC            AuthenticationMode = "OIDC"
	ModeNone            AuthenticationMode = "None"
	ModeUnknown         AuthenticationMode = "Unknown"
)

// AuthModeDetector handles detection of OpenShift authentication modes.
// Based on research from OPENSHIFT_AUTH_MODE.md SPIKE findings.
type AuthModeDetector struct {
	configClient configclient.Interface
	coreClient   kubernetes.Interface
	restConfig   *rest.Config
}

// NewAuthModeDetector creates a new authentication mode detector.
// Requires cluster configuration to access OpenShift config APIs.
func NewAuthModeDetector(config *rest.Config) (*AuthModeDetector, error) {
	configClient, err := configclient.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("creating config client: %w", err)
	}

	coreClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("creating core client: %w", err)
	}

	return &AuthModeDetector{
		configClient: configClient,
		coreClient:   coreClient,
		restConfig:   config,
	}, nil
}

// GetAuthenticationMode determines the cluster's current authentication mode.
// Returns the detected mode and the Authentication CR for further analysis.
func (d *AuthModeDetector) GetAuthenticationMode(ctx context.Context) (AuthenticationMode, *configv1.Authentication, error) {
	// Get the cluster Authentication CR (always named "cluster")
	auth, err := d.configClient.ConfigV1().Authentications().Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return ModeUnknown, nil, fmt.Errorf("getting authentication config: %w", err)
	}

	// Determine mode based on Authentication CR spec using SPIKE findings
	mode := d.determineMode(auth)
	return mode, auth, nil
}

// determineMode implements the authentication mode detection logic from SPIKE-1.
// Uses the same logic as cluster-authentication-operator for consistency.
func (d *AuthModeDetector) determineMode(auth *configv1.Authentication) AuthenticationMode {
	// Check explicit type field first (primary detection method)
	switch auth.Spec.Type {
	case configv1.AuthenticationTypeOIDC:
		// External OIDC mode - direct JWT validation
		return ModeOIDC
	case configv1.AuthenticationTypeIntegratedOAuth, "":
		// Empty string is equivalent to IntegratedOAuth (default)
		// Uses OpenShift OAuth server as identity broker
		return ModeIntegratedOAuth
	case configv1.AuthenticationTypeNone:
		// None mode - no authentication
		return ModeNone
	}

	// Advanced mode detection: check for webhook authenticator without OAuth metadata
	// This indicates "None" mode with external authentication system
	if auth.Spec.WebhookTokenAuthenticator != nil &&
		auth.Spec.OAuthMetadata.Name == "" {
		return ModeNone
	}

	// Default to IntegratedOAuth if detection is unclear
	return ModeIntegratedOAuth
}

// IsOIDCFullyDeployed verifies that OIDC configuration has rolled out to all control plane nodes.
// Critical for preventing authentication failures during transitions.
// Implements the rollout detection logic from SPIKE-1 findings.
func (d *AuthModeDetector) IsOIDCFullyDeployed(ctx context.Context) (bool, error) {
	mode, _, err := d.GetAuthenticationMode(ctx)
	if err != nil {
		return false, err
	}

	// Only relevant for OIDC mode
	if mode != ModeOIDC {
		return true, nil
	}

	// TODO: Implement rollout verification logic
	// This should:
	// 1. Get KubeAPIServer CR to check rollout status
	// 2. Collect all active revisions across control plane nodes
	// 3. Verify each revision has proper OIDC configuration
	// 4. Check auth-config-<revision> ConfigMaps exist
	// 5. Validate config-<revision> ConfigMaps have OIDC settings
	//
	// See OPENSHIFT_AUTH_MODE.md for complete implementation details

	return false, errors.New("OIDC rollout verification not implemented - see SPIKE-1 findings")
}

// GetProxyConfiguration returns configuration needed for kube-auth-proxy deployment.
// Based on detected authentication mode and cluster configuration.
func (d *AuthModeDetector) GetProxyConfiguration(ctx context.Context) (*ProxyConfig, error) {
	mode, auth, err := d.GetAuthenticationMode(ctx)
	if err != nil {
		return nil, err
	}

	config := &ProxyConfig{
		Mode: mode,
	}

	// TODO: Implement proxy configuration generation based on mode
	// This should populate different configuration structures:
	// - ModeIntegratedOAuth: OAuth server endpoints, client secrets
	// - ModeOIDC: External provider details, JWT validation settings
	// - ModeNone: Webhook configuration for external validation
	// See OPENSHIFT_AUTH_MODE.md for complete configuration examples.

	switch mode {
	case ModeIntegratedOAuth:
		// Configure for OpenShift OAuth server.
		config.OAuthConfig = &OAuthProxyConfig{
			// TODO: Extract OAuth server endpoints from cluster.
		}

	case ModeOIDC:
		// Configure for external OIDC provider.
		if len(auth.Spec.OIDCProviders) == 0 {
			return nil, errors.New("OIDC mode configured but no providers found")
		}
		config.OIDCConfig = &OIDCProxyConfig{
			// TODO: Extract OIDC provider configuration.
		}

	case ModeNone:
		// Configure for external webhook authentication
		config.WebhookConfig = &WebhookProxyConfig{
			// TODO: Extract webhook configuration.
		}

	case ModeUnknown:
		// Unknown mode - cannot configure proxy.
		return nil, errors.New("cannot configure proxy for unknown authentication mode")
	}

	return config, nil
}

// Configuration structures for kube-auth-proxy deployment
// These will be used to generate the proxy deployment with correct auth settings

// ProxyConfig represents the complete configuration for kube-auth-proxy.
type ProxyConfig struct {
	Mode          AuthenticationMode  `json:"mode"`
	OAuthConfig   *OAuthProxyConfig   `json:"oauth,omitempty"`
	OIDCConfig    *OIDCProxyConfig    `json:"oidc,omitempty"`
	WebhookConfig *WebhookProxyConfig `json:"webhook,omitempty"`
}

// OAuthProxyConfig contains settings for OpenShift OAuth integration.
type OAuthProxyConfig struct {
	AuthorizeURL     string `json:"authorize_url"`
	TokenURL         string `json:"token_url"`
	UserinfoURL      string `json:"userinfo_url"`
	IssuerURL        string `json:"issuer_url"`
	ClientIDFile     string `json:"client_id_file"`
	ClientSecretFile string `json:"client_secret_file"`
}

// OIDCProxyConfig contains settings for external OIDC provider integration.
type OIDCProxyConfig struct {
	IssuerURL string   `json:"issuer_url"`
	ClientID  string   `json:"client_id"`
	Audiences []string `json:"audiences"`
	// ClaimMappings can be added in future versions if needed.
}

// WebhookProxyConfig contains settings for external webhook authentication.
type WebhookProxyConfig struct {
	WebhookConfigFile string `json:"webhook_config_file"`
	CacheTTL          string `json:"cache_ttl"`
}
