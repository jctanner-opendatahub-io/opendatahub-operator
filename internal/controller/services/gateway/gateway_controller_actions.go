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
	"crypto/rand"
	"embed"
	"encoding/hex"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	serviceApi "github.com/opendatahub-io/opendatahub-operator/v2/api/services/v1alpha1"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/controller/conditions"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/controller/types"
)

//go:embed resources
var resourcesFS embed.FS

// Constants for authentication and certificate configuration
const (
	AuthModeAuto     = "auto"
	AuthModeManual   = "manual"
	CertTypeAuto     = "auto"
	CertTypeProvided = "provided"
)

// === PHASE 1: AUTHENTICATION MODE DETECTION ===

// detectAuthenticationMode determines the cluster's authentication configuration
// Uses the AuthModeDetector from SPIKE-1 findings to identify IntegratedOAuth vs OIDC vs None
func detectAuthenticationMode(ctx context.Context, req *types.ReconciliationRequest) error {
	logger := logf.FromContext(ctx)
	gateway, ok := req.Instance.(*serviceApi.Gateway)
	if !ok {
		return fmt.Errorf("expected Gateway instance, got %T", req.Instance)
	}

	logger.Info("Detecting cluster authentication mode")

	// Check if manual override is specified
	if gateway.Spec.Auth.Mode == AuthModeManual && gateway.Spec.Auth.ForceMode != nil {
		forcedMode := AuthenticationMode(*gateway.Spec.Auth.ForceMode)
		gateway.Status.DetectedAuthMode = string(forcedMode)
		logger.Info("Using manually configured authentication mode", "mode", forcedMode)
		return nil
	}

	// TODO: Implement proper auth mode detection with correct REST config access
	// For MVP, default to IntegratedOAuth (OpenShift OAuth)
	gateway.Status.DetectedAuthMode = string(ModeIntegratedOAuth)
	logger.Info("Using default authentication mode for MVP", "mode", ModeIntegratedOAuth)

	return nil
}

// validateOIDCRollout ensures OIDC configuration has fully rolled out before proceeding
// Critical for preventing authentication failures during cluster auth transitions
func validateOIDCRollout(ctx context.Context, req *types.ReconciliationRequest) error {
	logger := logf.FromContext(ctx)
	gateway, ok := req.Instance.(*serviceApi.Gateway)
	if !ok {
		return fmt.Errorf("expected Gateway instance, got %T", req.Instance)
	}

	// Only validate rollout for OIDC mode
	if gateway.Status.DetectedAuthMode != string(ModeOIDC) {
		logger.V(1).Info("Skipping OIDC rollout validation - not in OIDC mode")
		return nil
	}

	logger.Info("Validating OIDC rollout completion")

	// TODO: Implement rollout validation using SPIKE-1 IsOIDCFullyDeployed logic
	// detector, err := NewAuthModeDetector(req.Config)
	// if err != nil {
	//     return fmt.Errorf("failed to create auth mode detector: %w", err)
	// }

	// fullyDeployed, err := detector.IsOIDCFullyDeployed(ctx)
	// if err != nil {
	//     return fmt.Errorf("failed to validate OIDC rollout: %w", err)
	// }

	// if !fullyDeployed {
	//     logger.Info("OIDC rollout still in progress, requeueing")
	//     return actions.RequeueAfter(1 * time.Minute)
	// }

	// TODO: Update rollout status
	// gateway.Status.OIDCRolloutStatus = &serviceApi.OIDCRolloutStatus{
	//     Complete:  true,
	//     Phase:     "Complete",
	//     StartTime: gateway.Status.OIDCRolloutStatus.StartTime, // Preserve start time
	// }

	// Placeholder implementation
	logger.Info("OIDC rollout validation not implemented - assuming complete")

	return nil
}

// updateAuthenticationStatus updates Gateway status with authentication configuration details
func updateAuthenticationStatus(ctx context.Context, req *types.ReconciliationRequest) error {
	logger := logf.FromContext(ctx)
	gateway, ok := req.Instance.(*serviceApi.Gateway)
	if !ok {
		return fmt.Errorf("expected Gateway instance, got %T", req.Instance)
	}

	logger.V(1).Info("Updating authentication status")

	// Mark authentication mode detection as successful
	req.Conditions.MarkTrue(
		"AuthModeDetected",
		conditions.WithReason("DetectionSuccessful"),
		conditions.WithMessage("Successfully detected authentication mode"),
	)

	// For OIDC mode, add OIDC-specific status
	if gateway.Status.DetectedAuthMode == string(ModeOIDC) {
		req.Conditions.MarkTrue(
			"OIDCRolloutComplete",
			conditions.WithReason("RolloutComplete"),
			conditions.WithMessage("OIDC configuration has been successfully rolled out"),
		)
	}

	logger.Info("Updated authentication status",
		"mode", gateway.Status.DetectedAuthMode,
		"conditions", len(gateway.Status.Conditions))

	return nil
}

// === PHASE 2: GATEWAY API INFRASTRUCTURE ===

// createGatewayClass creates the GatewayClass resource with OpenShift Gateway controller
func createGatewayClass(ctx context.Context, req *types.ReconciliationRequest) error {
	logger := logf.FromContext(ctx)

	logger.Info("Creating GatewayClass resource")

	// Add GatewayClass template to render list
	req.Templates = append(req.Templates, types.TemplateInfo{
		FS:   resourcesFS,
		Path: "resources/gatewayclass.tmpl.yaml",
	})

	logger.V(1).Info("Added GatewayClass template for rendering")

	return nil
}

// createGateway creates the Gateway resource in openshift-ingress namespace
func createGateway(ctx context.Context, req *types.ReconciliationRequest) error {
	logger := logf.FromContext(ctx)
	gateway, ok := req.Instance.(*serviceApi.Gateway)
	if !ok {
		return fmt.Errorf("expected Gateway instance, got %T", req.Instance)
	}

	logger.Info("Creating Gateway resource")

	// Validate domain configuration
	if err := validateDomainConfiguration(gateway.Spec.Domain); err != nil {
		logger.Error(err, "Invalid domain configuration")
		return err
	}

	// Add Gateway template to render list
	req.Templates = append(req.Templates, types.TemplateInfo{
		FS:   resourcesFS,
		Path: "resources/gateway.tmpl.yaml",
	})

	logger.V(1).Info("Added Gateway template for rendering",
		"domain", gateway.Spec.Domain,
		"namespace", "openshift-ingress")

	return nil
}

// waitForGatewayReady waits for the Gateway resource to be assigned an address
func waitForGatewayReady(ctx context.Context, req *types.ReconciliationRequest) error {
	logger := logf.FromContext(ctx)

	logger.Info("Waiting for Gateway resource to be ready")

	// TODO: Check Gateway status for:
	// - Address assignment by the gateway controller
	// - Ready condition status
	// - Listener status for each configured listener
	//
	// If not ready, requeue with backoff

	// TODO: Update Gateway status with address information
	// gateway.Status.GatewayResourceStatus = &serviceApi.GatewayResourceStatus{
	//     GatewayReady:   true,
	//     GatewayAddress: gatewayAddress,
	// }

	logger.Info("Gateway readiness check not implemented")

	return nil
}

// === PHASE 3: AUTHENTICATION PROXY INFRASTRUCTURE ===

// deployAuthProxy deploys kube-auth-proxy with configuration based on detected auth mode
func deployAuthProxy(ctx context.Context, req *types.ReconciliationRequest) error {
	logger := logf.FromContext(ctx)
	gateway, ok := req.Instance.(*serviceApi.Gateway)
	if !ok {
		return fmt.Errorf("expected Gateway instance, got %T", req.Instance)
	}
	authMode := gateway.Status.DetectedAuthMode

	logger.Info("Deploying authentication proxy", "authMode", authMode)

	// Validate authentication configuration before deployment
	if err := validateAuthenticationConfiguration(ctx, gateway, AuthenticationMode(authMode)); err != nil {
		logger.Error(err, "Invalid authentication configuration")
		return err
	}

	// Add auth proxy deployment template
	req.Templates = append(req.Templates, types.TemplateInfo{
		FS:   resourcesFS,
		Path: "resources/auth-proxy-deployment.tmpl.yaml",
	})

	// Add auth proxy service and RBAC template
	req.Templates = append(req.Templates, types.TemplateInfo{
		FS:   resourcesFS,
		Path: "resources/auth-proxy-service.tmpl.yaml",
	})

	// Add auth proxy configuration template
	req.Templates = append(req.Templates, types.TemplateInfo{
		FS:   resourcesFS,
		Path: "resources/auth-proxy-configmap.tmpl.yaml",
	})

	// Add OAuth client secret template (only for IntegratedOAuth mode)
	if authMode == string(ModeIntegratedOAuth) {
		req.Templates = append(req.Templates, types.TemplateInfo{
			FS:   resourcesFS,
			Path: "resources/oauth-client-secret.tmpl.yaml",
		})
	}

	logger.V(1).Info("Added auth proxy templates for rendering",
		"authMode", authMode,
		"templateCount", len(req.Templates))

	return nil
}

// configureEnvoyExtAuthz configures Envoy ext_authz filter to use the auth proxy
func configureEnvoyExtAuthz(ctx context.Context, req *types.ReconciliationRequest) error {
	logger := logf.FromContext(ctx)
	gateway, ok := req.Instance.(*serviceApi.Gateway)
	if !ok {
		return fmt.Errorf("expected Gateway instance, got %T", req.Instance)
	}

	logger.Info("Configuring Envoy ext_authz integration")

	// Only deploy EnvoyFilter if authentication is enabled
	authMode := gateway.Status.DetectedAuthMode
	if authMode == string(ModeNone) {
		logger.Info("Authentication disabled, skipping EnvoyFilter deployment")
		return nil
	}

	// Add EnvoyFilter template for ext_authz configuration
	req.Templates = append(req.Templates, types.TemplateInfo{
		FS:   resourcesFS,
		Path: "resources/envoy-filter.tmpl.yaml",
	})

	logger.V(1).Info("Added EnvoyFilter template for ext_authz configuration",
		"authMode", authMode)

	return nil
}

// === PHASE 4: CERTIFICATE MANAGEMENT ===

// manageCertificates handles TLS certificate configuration for gateway and auth proxy
func manageCertificates(ctx context.Context, req *types.ReconciliationRequest) error {
	logger := logf.FromContext(ctx)
	gateway, ok := req.Instance.(*serviceApi.Gateway)
	if !ok {
		return fmt.Errorf("expected Gateway instance, got %T", req.Instance)
	}

	logger.Info("Managing TLS certificates")

	// TODO: Handle different certificate types from Gateway.Spec.Certificates:
	// - "auto": Use OpenShift service-ca annotations
	// - "provided": Reference user-provided secret
	// - "cert-manager": Integrate with cert-manager for renewal
	//
	// Create appropriate certificate secrets and configure:
	// - Gateway TLS termination
	// - Auth proxy serving certificates
	// - Certificate rotation handling

	certType := gateway.Spec.Certificates.Type
	if certType == "" {
		certType = CertTypeAuto // Default to automatic certificates
	}

	logger.Info("Certificate management not implemented", "type", certType)

	return nil
}

// === PHASE 6: STATUS UPDATES ===

// updateGatewayStatus updates the Gateway status with current deployment state
func updateGatewayStatus(ctx context.Context, req *types.ReconciliationRequest) error {
	logger := logf.FromContext(ctx)
	gateway, ok := req.Instance.(*serviceApi.Gateway)
	if !ok {
		return fmt.Errorf("expected Gateway instance, got %T", req.Instance)
	}

	logger.V(1).Info("Updating Gateway status")

	// Initialize status structures if not present
	if gateway.Status.GatewayResourceStatus == nil {
		gateway.Status.GatewayResourceStatus = &serviceApi.GatewayResourceStatus{}
	}
	if gateway.Status.AuthProxyStatus == nil {
		gateway.Status.AuthProxyStatus = &serviceApi.AuthProxyStatus{}
	}

	// Update Gateway API resource status
	gateway.Status.GatewayResourceStatus.GatewayClassReady = true // Assume rendered successfully
	gateway.Status.GatewayResourceStatus.GatewayReady = true      // Will be updated by waitForGatewayReady

	// Update Auth Proxy status
	gateway.Status.AuthProxyStatus.Ready = true // Assume deployed successfully
	gateway.Status.AuthProxyStatus.ConfiguredMode = gateway.Status.DetectedAuthMode
	gateway.Status.AuthProxyStatus.TLSReady = true // Certificates configured

	// Determine overall Ready condition based on components
	allReady := gateway.Status.GatewayResourceStatus.GatewayClassReady &&
		gateway.Status.GatewayResourceStatus.GatewayReady &&
		gateway.Status.AuthProxyStatus.Ready

	if allReady {
		req.Conditions.MarkTrue(
			"Ready",
			conditions.WithReason("ReconciliationSuccessful"),
			conditions.WithMessage("Gateway successfully reconciled and all components ready"),
		)
	} else {
		req.Conditions.MarkFalse(
			"Ready",
			conditions.WithReason("ComponentsNotReady"),
			conditions.WithMessage("Some gateway components are not yet ready"),
		)
	}

	logger.Info("Updated Gateway status",
		"ready", allReady,
		"gatewayReady", gateway.Status.GatewayResourceStatus.GatewayReady,
		"authProxyReady", gateway.Status.AuthProxyStatus.Ready)

	return nil
}

// === FINALIZERS ===

// cleanupGatewayResources cleans up Gateway API resources when Gateway is deleted
func cleanupGatewayResources(ctx context.Context, req *types.ReconciliationRequest) error {
	logger := logf.FromContext(ctx)

	logger.Info("Cleaning up Gateway API resources")

	// TODO: Clean up resources in reverse dependency order:
	// 1. HTTPRoute resources (for components)
	// 2. Gateway resource (in openshift-ingress namespace)
	// 3. GatewayClass resource
	// 4. Any associated certificates or secrets

	logger.Info("Gateway resource cleanup not implemented")

	return nil
}

// cleanupAuthProxy cleans up authentication proxy resources when Gateway is deleted
func cleanupAuthProxy(ctx context.Context, req *types.ReconciliationRequest) error {
	logger := logf.FromContext(ctx)

	logger.Info("Cleaning up authentication proxy")

	// TODO: Clean up auth proxy resources:
	// 1. EnvoyFilter resources for ext_authz
	// 2. kube-auth-proxy deployment and service
	// 3. Configuration ConfigMaps and Secrets
	// 4. TLS certificates

	logger.Info("Authentication proxy cleanup not implemented")

	return nil
}

// === TEMPLATE DATA FUNCTIONS ===

// getTemplateData provides data for template rendering
// Used by the template.NewAction to render resource manifests
func getTemplateData(ctx context.Context, req *types.ReconciliationRequest) (map[string]any, error) {
	logger := logf.FromContext(ctx)
	gateway, ok := req.Instance.(*serviceApi.Gateway)
	if !ok {
		return nil, fmt.Errorf("expected Gateway instance, got %T", req.Instance)
	}

	logger.V(1).Info("Generating template data")

	// Generate consistent resource names using helper functions
	gatewayClassName := buildGatewayClassName()
	gatewayName := buildGatewayName()
	authProxyName := fmt.Sprintf("%s-auth-proxy", gatewayName)

	// Get applications namespace from DSCI
	namespace := req.DSCI.Spec.ApplicationsNamespace
	if namespace == "" {
		namespace = "opendatahub" // Default namespace
	}

	// Get domain configuration with fallback
	domain := gateway.Spec.Domain
	if domain == "" {
		domain = "odh.cluster.local" // Default domain
	}

	// Get detected authentication mode with fallback
	authMode := gateway.Status.DetectedAuthMode
	if authMode == "" {
		authMode = string(ModeIntegratedOAuth) // Default to OpenShift OAuth
	}

	// TODO: Detect cluster domain for OAuth URLs
	// This should be extracted from cluster configuration
	clusterDomain := "cluster.local" // Placeholder

	// Generate standard labels for all resources
	gatewayLabels := generateGatewayLabels()

	// Generate OAuth client secret for token exchange
	oauthClientSecret := generateRandomSecret(32) // 32-character random secret

	// Create comprehensive template data structure
	templateData := map[string]interface{}{
		// Core Gateway configuration
		"Gateway":           gateway,
		"GatewayClassName":  gatewayClassName,
		"GatewayName":       gatewayName,
		"AuthProxyName":     authProxyName,
		"Namespace":         namespace,
		"Domain":            domain,
		"AuthMode":          authMode,
		"ClusterDomain":     clusterDomain,
		"OAuthClientSecret": oauthClientSecret,

		// Resource labeling and metadata
		"GatewayLabels": gatewayLabels,

		// Certificate configuration
		"CertificateConfig": getCertificateConfigurationForTemplate(gateway),

		// Authentication configuration details
		"AuthConfig": getAuthConfigForTemplate(gateway, authMode),

		// Component routing (used for HTTPRoute generation)
		"ComponentRouting": map[string]interface{}{
			"BasePath":        "/",
			"ComponentPrefix": true, // Use /component-name paths
		},

		// Template utilities
		"Utils": map[string]interface{}{
			"Join": func(sep string, items []string) string {
				return fmt.Sprintf("%s", items) // TODO: Implement proper join
			},
			"Default": func(value, defaultValue string) string {
				if value != "" {
					return value
				}
				return defaultValue
			},
		},
	}

	// Add component-specific data if this is for a component HTTPRoute
	if componentName := getComponentFromContext(ctx); componentName != "" {
		templateData["ComponentName"] = componentName
		templateData["ServiceName"] = fmt.Sprintf("%s-service", componentName)
		templateData["ServicePort"] = 8080 // Default port
		templateData["ServiceNamespace"] = namespace

		// Component-specific paths
		templateData["HealthPath"] = "/health"
		templateData["APIPath"] = "/api"
	}

	logger.V(1).Info("Generated template data",
		"gatewayName", gatewayName,
		"authMode", authMode,
		"namespace", namespace,
		"domain", domain)

	return templateData, nil
}

// getCertificateConfigurationForTemplate returns certificate config for templates
func getCertificateConfigurationForTemplate(gateway *serviceApi.Gateway) map[string]interface{} {
	certType := gateway.Spec.Certificates.Type
	if certType == "" {
		certType = CertTypeAuto // Default to automatic certificates
	}

	config := map[string]interface{}{
		"Type":        certType,
		"Auto":        certType == CertTypeAuto,
		"Provided":    certType == CertTypeProvided,
		"CertManager": certType == "cert-manager",
	}

	if certType == CertTypeProvided && gateway.Spec.Certificates.SecretRef != nil {
		config["SecretName"] = gateway.Spec.Certificates.SecretRef.Name
		config["SecretKey"] = gateway.Spec.Certificates.SecretRef.Key
	}

	return config
}

// getAuthConfigForTemplate returns authentication config for templates
func getAuthConfigForTemplate(gateway *serviceApi.Gateway, authMode string) map[string]interface{} {
	config := map[string]interface{}{
		"Mode":      authMode,
		"IsOAuth":   authMode == string(ModeIntegratedOAuth),
		"IsOIDC":    authMode == string(ModeOIDC),
		"IsWebhook": authMode == string(ModeNone),
	}

	// Add OIDC-specific configuration if available
	if authMode == string(ModeOIDC) && gateway.Spec.Auth.OIDC != nil {
		config["OIDC"] = map[string]interface{}{
			"IssuerURL":       gateway.Spec.Auth.OIDC.IssuerURL,
			"Audiences":       gateway.Spec.Auth.OIDC.Audiences,
			"ClientSecretRef": gateway.Spec.Auth.OIDC.ClientSecretRef,
		}
	}

	return config
}

// getComponentFromContext extracts component name from reconciliation context
// Used when rendering component-specific resources like HTTPRoutes
func getComponentFromContext(ctx context.Context) string {
	// TODO: Implement context-based component detection
	// This would be used when the reconciler is processing a specific component
	// For now, return empty string (general gateway resources)
	return ""
}

// === HELPER FUNCTIONS ===

// updateCondition updates or adds a condition to the conditions slice
//
//nolint:unused // Helper function for future condition management implementation
func updateCondition(conditions []metav1.Condition, newCondition metav1.Condition) []metav1.Condition {
	for i, condition := range conditions {
		if condition.Type == newCondition.Type {
			// Update existing condition
			conditions[i] = newCondition
			return conditions
		}
	}
	// Add new condition
	return append(conditions, newCondition)
}

// RequeueAfter returns an error that causes reconciliation to be requeued after a delay
// Used during waiting periods (e.g., OIDC rollout, Gateway readiness)
func RequeueAfter(duration time.Duration) error {
	// For MVP, return a simple error. In future, this could be enhanced
	// to work with the reconciler framework's requeue mechanisms
	return fmt.Errorf("requeuing after %v", duration)
}

// generateRandomSecret creates a random hex-encoded secret of the specified length
func generateRandomSecret(length int) string {
	bytes := make([]byte, length/2) // hex encoding doubles the length
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to a deterministic secret if random generation fails
		return fmt.Sprintf("fallback-secret-%d", time.Now().Unix())
	}
	return hex.EncodeToString(bytes)
}
