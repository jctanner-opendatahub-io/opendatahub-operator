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

package v1alpha1

import (
	"github.com/opendatahub-io/opendatahub-operator/v2/api/common"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	GatewayServiceName  = "gateway"
	GatewayInstanceName = "gateway"
	GatewayKind         = "Gateway"
)

// Check that the component implements common.PlatformObject.
var _ common.PlatformObject = (*Gateway)(nil)

// GatewaySpec defines the desired state of Gateway
type GatewaySpec struct {
	// Auth configuration for gateway authentication handling
	// Determines how the gateway will authenticate users (auto-detect vs manual)
	Auth GatewayAuthSpec `json:"auth,omitempty"`

	// Domain configuration for the gateway
	// The base domain for all gateway routes (e.g., "odh.example.com")
	Domain string `json:"domain,omitempty"`

	// Certificate configuration for TLS termination
	// Supports user-provided certificates or integration with existing certificate hooks
	Certificates GatewayCertSpec `json:"certificates,omitempty"`

	// Rollout configuration for managing authentication mode transitions
	// Controls behavior during OIDC rollouts and authentication mode changes
	RolloutConfig GatewayRolloutSpec `json:"rollout,omitempty"`
}

// GatewayAuthSpec defines authentication configuration for the gateway
type GatewayAuthSpec struct {
	// Authentication mode: "auto" (default) | "manual"
	// "auto" - detect from cluster configuration
	// "manual" - use explicit ForceMode setting
	Mode string `json:"mode,omitempty"`

	// Manual override for authentication mode
	// Only used when Mode is "manual"
	// Values: "IntegratedOAuth" | "OIDC" | "None"
	ForceMode *string `json:"forceMode,omitempty"`

	// OIDC configuration (required when ForceMode="OIDC" or auto-detected OIDC)
	// Contains external OIDC provider details for kube-auth-proxy configuration
	OIDC *OIDCConfig `json:"oidc,omitempty"`

	// Wait for OIDC rollout completion before deploying gateway components
	// Prevents authentication failures during cluster authentication transitions
	WaitForRollout bool `json:"waitForRollout,omitempty"`
}

// OIDCConfig defines external OIDC provider configuration
type OIDCConfig struct {
	// OIDC issuer URL for external provider
	IssuerURL string `json:"issuerURL"`

	// Reference to secret containing clientID and clientSecret
	// Secret must be in the same namespace as the Gateway resource
	ClientSecretRef corev1.SecretKeySelector `json:"clientSecretRef"`

	// Additional audiences for token validation
	// Used for multi-tenant or multi-application scenarios
	Audiences []string `json:"audiences,omitempty"`
}

// GatewayCertSpec defines certificate management for the gateway
type GatewayCertSpec struct {
	// Type of certificate management: "auto" | "provided" | "cert-manager"
	// "auto" - use OpenShift auto-generated certificates
	// "provided" - use user-provided certificate secret
	// "cert-manager" - integrate with cert-manager for automatic renewal
	Type string `json:"type,omitempty"`

	// Reference to user-provided certificate secret (when Type="provided")
	// Secret must contain tls.crt and tls.key
	SecretRef *corev1.SecretKeySelector `json:"secretRef,omitempty"`
}

// GatewayRolloutSpec defines rollout behavior during authentication transitions
type GatewayRolloutSpec struct {
	// Maximum time to wait for OIDC rollout completion
	// Default: 10 minutes
	RolloutTimeout *metav1.Duration `json:"rolloutTimeout,omitempty"`

	// Interval for checking OIDC rollout status
	// Default: 30 seconds
	RolloutCheckInterval *metav1.Duration `json:"rolloutCheckInterval,omitempty"`
}

// GatewayStatus defines the observed state of Gateway
type GatewayStatus struct {
	common.Status `json:",inline"`

	// Currently detected authentication mode from cluster analysis
	// Values: "IntegratedOAuth" | "OIDC" | "None" | "Unknown"
	DetectedAuthMode string `json:"detectedAuthMode,omitempty"`

	// OIDC rollout status (when applicable)
	// Tracks the progress of OIDC configuration rollout across control plane nodes
	OIDCRolloutStatus *OIDCRolloutStatus `json:"oidcRolloutStatus,omitempty"`

	// Gateway API resources status
	// Tracks the status of created GatewayClass and Gateway resources
	GatewayResourceStatus *GatewayResourceStatus `json:"gatewayResourceStatus,omitempty"`

	// Authentication proxy status
	// Status of the deployed kube-auth-proxy instance
	AuthProxyStatus *AuthProxyStatus `json:"authProxyStatus,omitempty"`
}

// OIDCRolloutStatus tracks OIDC rollout progress across control plane
type OIDCRolloutStatus struct {
	// Whether OIDC rollout is complete across all control plane nodes
	Complete bool `json:"complete"`

	// List of active control plane node revisions
	// Used to verify consistent OIDC configuration deployment
	ActiveRevisions []int32 `json:"activeRevisions,omitempty"`

	// Timestamp when rollout monitoring started
	StartTime *metav1.Time `json:"startTime,omitempty"`

	// Current rollout phase: "Detecting" | "InProgress" | "Complete" | "Failed"
	Phase string `json:"phase,omitempty"`

	// Human-readable message about rollout status
	Message string `json:"message,omitempty"`
}

// GatewayResourceStatus tracks Gateway API resource creation and status
type GatewayResourceStatus struct {
	// GatewayClass resource status
	GatewayClassReady bool `json:"gatewayClassReady"`

	// Gateway resource status
	GatewayReady bool `json:"gatewayReady"`

	// Assigned gateway hostname/address
	// Populated once the Gateway resource gets an address
	GatewayAddress string `json:"gatewayAddress,omitempty"`

	// List of HTTPRoute resources created for components
	HTTPRoutes []HTTPRouteStatus `json:"httpRoutes,omitempty"`
}

// HTTPRouteStatus tracks individual component HTTPRoute status
type HTTPRouteStatus struct {
	// Component name (e.g., "dashboard", "kserve")
	Component string `json:"component"`

	// HTTPRoute resource name
	Name string `json:"name"`

	// HTTPRoute readiness status
	Ready bool `json:"ready"`

	// Route path prefix (e.g., "/dashboard")
	Path string `json:"path,omitempty"`
}

// AuthProxyStatus tracks kube-auth-proxy deployment status
type AuthProxyStatus struct {
	// Deployment readiness status
	Ready bool `json:"ready"`

	// Currently configured authentication mode in the proxy
	ConfiguredMode string `json:"configuredMode,omitempty"`

	// Proxy service endpoint
	ServiceEndpoint string `json:"serviceEndpoint,omitempty"`

	// TLS certificate status for auth proxy
	TLSReady bool `json:"tlsReady"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:scope=Cluster
//+kubebuilder:validation:XValidation:rule="self.metadata.name == 'gateway'",message="Gateway name must be gateway"
//+kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`,description="Ready"
//+kubebuilder:printcolumn:name="Auth Mode",type=string,JSONPath=`.status.detectedAuthMode`,description="Authentication Mode"
//+kubebuilder:printcolumn:name="Gateway Ready",type=string,JSONPath=`.status.gatewayResourceStatus.gatewayReady`,description="Gateway Resource Ready"
//+kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`,description="Age"

// Gateway is the Schema for the gateways API
// Manages a single Gateway API-based ingress with centralized authentication
// for all OpenDataHub components, replacing multiple OpenShift Routes
type Gateway struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   GatewaySpec   `json:"spec,omitempty"`
	Status GatewayStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// GatewayList contains a list of Gateway
type GatewayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Gateway `json:"items"`
}

// Implement common.PlatformObject interface methods

func (m *Gateway) GetStatus() *common.Status {
	return &m.Status.Status
}

func (c *Gateway) GetConditions() []common.Condition {
	return c.Status.GetConditions()
}

func (c *Gateway) SetConditions(conditions []common.Condition) {
	c.Status.SetConditions(conditions)
}

func init() {
	SchemeBuilder.Register(&Gateway{}, &GatewayList{})
}
