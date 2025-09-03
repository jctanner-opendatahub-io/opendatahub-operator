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
	"strings"
	"time"

	operatorv1 "github.com/openshift/api/operator/v1"
	corev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	serviceApi "github.com/opendatahub-io/opendatahub-operator/v2/api/services/v1alpha1"
)

// === AUTHENTICATION MODE VALIDATION ===

// against the detected cluster authentication mode.
func validateAuthenticationConfiguration(_ context.Context, gateway *serviceApi.Gateway, detectedMode AuthenticationMode) error {
	authSpec := gateway.Spec.Auth

	// Validate mode configuration
	switch authSpec.Mode {
	case AuthModeAuto, "":
		// Auto mode - use detected configuration
		return validateAutoModeConfiguration(detectedMode, authSpec)
	case AuthModeManual:
		// Manual mode - validate explicit configuration
		return validateManualModeConfiguration(authSpec)
	default:
		return fmt.Errorf("invalid authentication mode: %s (must be 'auto' or 'manual')", authSpec.Mode)
	}
}

// validateAutoModeConfiguration validates configuration when using automatic detection.
func validateAutoModeConfiguration(detectedMode AuthenticationMode, authSpec serviceApi.GatewayAuthSpec) error {
	switch detectedMode {
	case ModeOIDC:
		// OIDC mode detected - validate OIDC configuration if provided
		if authSpec.OIDC != nil {
			return validateOIDCConfiguration(authSpec.OIDC)
		}
		// No OIDC config provided - will use cluster default
		return nil

	case ModeIntegratedOAuth:
		// IntegratedOAuth mode - no additional config needed
		return nil

	case ModeNone:
		// None mode - external authentication system required
		return errors.New("authentication mode 'None' detected but external authentication configuration not supported in auto mode")

	default:
		return fmt.Errorf("unknown authentication mode detected: %s", detectedMode)
	}
}

// validateManualModeConfiguration validates configuration when using manual override.
func validateManualModeConfiguration(authSpec serviceApi.GatewayAuthSpec) error {
	if authSpec.ForceMode == nil {
		return errors.New("manual authentication mode requires ForceMode to be specified")
	}

	switch AuthenticationMode(*authSpec.ForceMode) {
	case ModeOIDC:
		// Manual OIDC mode - OIDC configuration required
		if authSpec.OIDC == nil {
			return errors.New("OIDC configuration required when ForceMode is 'OIDC'")
		}
		return validateOIDCConfiguration(authSpec.OIDC)

	case ModeIntegratedOAuth:
		// Manual IntegratedOAuth mode - no additional config needed
		return nil

	case ModeNone:
		// Manual None mode - not supported yet
		return errors.New("authentication mode 'None' not supported in manual mode")

	default:
		return fmt.Errorf("invalid ForceMode: %s (must be 'IntegratedOAuth', 'OIDC', or 'None')", *authSpec.ForceMode)
	}
}

// validateOIDCConfiguration validates OIDC provider configuration.
func validateOIDCConfiguration(oidcConfig *serviceApi.OIDCConfig) error {
	if oidcConfig.IssuerURL == "" {
		return errors.New("OIDC IssuerURL is required")
	}

	if oidcConfig.ClientSecretRef.Name == "" {
		return errors.New("OIDC ClientSecretRef.Name is required")
	}

	if oidcConfig.ClientSecretRef.Key == "" {
		return errors.New("OIDC ClientSecretRef.Key is required")
	}

	// TODO: Validate issuer URL format and accessibility
	// TODO: Validate secret exists and has required keys

	return nil
}

// === GATEWAY API UTILITIES ===

// buildGatewayClassName generates a consistent GatewayClass name.
func buildGatewayClassName() string {
	return "odh-gateway-class"
}

// buildGatewayName generates a consistent Gateway resource name.
func buildGatewayName() string {
	return "odh-gateway"
}

// buildGatewayNamespace returns the namespace where Gateway resources should be created.
//
//nolint:unused // Part of planned Gateway API resource management implementation
func buildGatewayNamespace() string {
	return "openshift-ingress" // As specified in design document
}

// generateGatewayLabels creates standard labels for Gateway API resources.
func generateGatewayLabels() map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":       "opendatahub-gateway",
		"app.kubernetes.io/component":  "gateway",
		"app.kubernetes.io/managed-by": "opendatahub-operator",
		"app.kubernetes.io/part-of":    "opendatahub",
	}
}

// === CERTIFICATE UTILITIES ===

// getCertificateConfiguration determines certificate settings based on Gateway spec
//
//nolint:unused // Part of planned certificate management implementation
func getCertificateConfiguration(gateway *serviceApi.Gateway) (*CertificateConfig, error) {
	certSpec := gateway.Spec.Certificates
	certType := certSpec.Type

	if certType == "" {
		certType = CertTypeAuto // Default to automatic certificates
	}

	config := &CertificateConfig{
		Type: certType,
	}

	switch certType {
	case CertTypeAuto:
		// Use OpenShift service-ca for automatic certificate generation
		config.SecretName = buildGatewayName() + "-tls"
		config.UseServiceCA = true

	case CertTypeProvided:
		// Use user-provided certificate secret
		if certSpec.SecretRef == nil {
			return nil, errors.New("certificate type 'provided' requires SecretRef to be specified")
		}
		config.SecretName = certSpec.SecretRef.Name
		config.SecretKey = certSpec.SecretRef.Key

	case "cert-manager":
		// Integrate with cert-manager for automatic renewal
		config.SecretName = buildGatewayName() + "-tls"
		config.UseCertManager = true
		// TODO: Add cert-manager specific configuration

	default:
		return nil, fmt.Errorf("unsupported certificate type: %s", certType)
	}

	return config, nil
}

// CertificateConfig represents certificate configuration for the gateway.
type CertificateConfig struct {
	Type           string
	SecretName     string
	SecretKey      string
	UseServiceCA   bool
	UseCertManager bool
}

// === ROLLOUT TRACKING UTILITIES ===

// calculateRolloutTimeout determines the timeout for OIDC rollout based on Gateway spec
//
//nolint:unused // Part of planned OIDC rollout implementation
func calculateRolloutTimeout(gateway *serviceApi.Gateway) time.Duration {
	if gateway.Spec.RolloutConfig.RolloutTimeout != nil {
		return gateway.Spec.RolloutConfig.RolloutTimeout.Duration
	}
	return 10 * time.Minute // Default timeout
}

// calculateRolloutCheckInterval determines the check interval for OIDC rollout
//
//nolint:unused // Part of planned OIDC rollout implementation
func calculateRolloutCheckInterval(gateway *serviceApi.Gateway) time.Duration {
	if gateway.Spec.RolloutConfig.RolloutCheckInterval != nil {
		return gateway.Spec.RolloutConfig.RolloutCheckInterval.Duration
	}
	return 30 * time.Second // Default interval
}

// trackOIDCRolloutProgress updates the Gateway status with rollout progress information
//
//nolint:unused // Part of planned OIDC rollout implementation
func trackOIDCRolloutProgress(gateway *serviceApi.Gateway, phase string, message string, activeRevisions []int32) {
	if gateway.Status.OIDCRolloutStatus == nil {
		gateway.Status.OIDCRolloutStatus = &serviceApi.OIDCRolloutStatus{
			StartTime: &metav1.Time{Time: time.Now()},
		}
	}

	gateway.Status.OIDCRolloutStatus.Phase = phase
	gateway.Status.OIDCRolloutStatus.Message = message
	gateway.Status.OIDCRolloutStatus.ActiveRevisions = activeRevisions
	gateway.Status.OIDCRolloutStatus.Complete = (phase == "Complete")
}

// === STATUS CONDITION UTILITIES ===

// updateReadyCondition updates the Gateway Ready condition based on component states
//
//nolint:unused // Part of planned status management implementation
func updateReadyCondition(gateway *serviceApi.Gateway) {
	// TODO: Implement condition logic based on:
	// - AuthModeDetected condition
	// - GatewayReady status
	// - AuthProxyReady status
	// - CertificatesReady status

	// Example logic (to be implemented):
	// ready := gateway.Status.GatewayResourceStatus.GatewayReady &&
	//          gateway.Status.AuthProxyStatus.Ready &&
	//          gateway.Status.GatewayResourceStatus.GatewayClassReady

	// condition := metav1.Condition{
	//     Type:    "Ready",
	//     Status:  metav1.ConditionTrue, // or ConditionFalse
	//     Reason:  "ComponentsReady",    // or appropriate reason
	//     Message: "All gateway components are ready and operational",
	// }

	// gateway.Status.SetCondition(condition)
}

// === RESOURCE EXISTENCE CHECKS ===

// checkGatewayAPIAvailability verifies that Gateway API CRDs are installed
//
//nolint:unused // Part of planned resource validation implementation
func checkGatewayAPIAvailability(ctx context.Context, c client.Client) error {
	// Check for Gateway API CRDs
	// TODO: Check if required Gateway API CRDs exist
	// This should use discovery client or similar to verify CRD availability:
	// - gateway.networking.k8s.io/v1/GatewayClass
	// - gateway.networking.k8s.io/v1/Gateway
	// - gateway.networking.k8s.io/v1/HTTPRoute

	return nil
}

// checkServiceMeshAvailability verifies that Service Mesh is available for Envoy integration
//
//nolint:unused // Part of planned Service Mesh integration implementation
func checkServiceMeshAvailability(ctx context.Context, c client.Client) error {
	// TODO: Check for Service Mesh operator and control plane
	// This may be optional depending on implementation approach
	// - Check for ServiceMeshControlPlane CRD
	// - Verify control plane is ready
	// - Check for required namespace membership

	return nil
}

// === HELPER FUNCTIONS FOR SPIKE-1 INTEGRATION ===

// isAuthConfigMap determines if a ConfigMap is relevant for OIDC rollout tracking
// Implements the filtering logic from SPIKE-1 findings
//
//nolint:unused // Part of planned OIDC rollout implementation
func isAuthConfigMap(cm *corev1.ConfigMap) bool {
	// Must be in the openshift-kube-apiserver namespace
	if cm.Namespace != "openshift-kube-apiserver" {
		return false
	}

	// Must be an auth-config-* or config-* ConfigMap
	return strings.HasPrefix(cm.Name, "auth-config-") || strings.HasPrefix(cm.Name, "config-")
}

// extractActiveRevisions extracts active revision numbers from KubeAPIServer status
// Used for OIDC rollout validation as discovered in SPIKE-1
//
//nolint:unused // Part of planned OIDC rollout implementation
func extractActiveRevisions(kas *operatorv1.KubeAPIServer) []int32 {
	revisions := make([]int32, 0, len(kas.Status.NodeStatuses))
	for _, nodeStatus := range kas.Status.NodeStatuses {
		revisions = append(revisions, nodeStatus.CurrentRevision)
	}
	return revisions
}

// validateRevisionOIDCConfig checks if a specific revision has proper OIDC configuration
// Implements the validation logic from SPIKE-1 findings
//
//nolint:unused // Part of planned OIDC rollout implementation
func validateRevisionOIDCConfig(ctx context.Context, coreClient kubernetes.Interface, revision int32) (bool, error) {
	namespace := "openshift-kube-apiserver"

	// Check auth-config-<revision> ConfigMap exists
	authConfigName := fmt.Sprintf("auth-config-%d", revision)
	_, err := coreClient.CoreV1().ConfigMaps(namespace).Get(ctx, authConfigName, metav1.GetOptions{})
	if k8serr.IsNotFound(err) {
		return false, nil // Rollout still in progress
	} else if err != nil {
		return false, fmt.Errorf("checking auth-config-%d: %w", revision, err)
	}

	// Check main config-<revision> has OIDC configuration
	configName := fmt.Sprintf("config-%d", revision)
	cm, err := coreClient.CoreV1().ConfigMaps(namespace).Get(ctx, configName, metav1.GetOptions{})
	if err != nil {
		return false, fmt.Errorf("checking config-%d: %w", revision, err)
	}

	configYaml := cm.Data["config.yaml"]

	// Validate OIDC-specific configuration markers from SPIKE-1
	hasOIDCMarkers := strings.Contains(configYaml, `"oauthMetadataFile":""`) &&
		!strings.Contains(configYaml, `"authentication-token-webhook-config-file":`) &&
		strings.Contains(configYaml, `"authentication-config":["/etc/kubernetes/static-pod-resources/configmaps/auth-config/auth-config.json"]`)

	return hasOIDCMarkers, nil
}

// === DOMAIN AND ROUTING UTILITIES ===

// buildComponentRoute generates the route path for a specific ODH component.
//
//nolint:unused // Part of planned component routing implementation
func buildComponentRoute(componentName string) string {
	return fmt.Sprintf("/%s", componentName)
}

// buildGatewayHostname constructs the full hostname for the gateway
//
//nolint:unused // Part of planned domain configuration implementation
func buildGatewayHostname(domain string) string {
	if domain == "" {
		// TODO: Generate default domain based on cluster configuration
		return "odh.cluster.local"
	}
	return domain
}

// validateDomainConfiguration validates the domain configuration in Gateway spec.
func validateDomainConfiguration(domain string) error {
	if domain == "" {
		return errors.New("domain configuration is required")
	}

	// TODO: Add domain format validation
	// - Check for valid hostname format
	// - Validate against cluster domain restrictions
	// - Check for conflicts with existing routes

	return nil
}

// === COMPONENT INTEGRATION UTILITIES ===

// ComponentMigrationPlan represents a plan for migrating a component from Routes to HTTPRoutes.
type ComponentMigrationPlan struct {
	ComponentName string
	RoutePath     string
	ServiceName   string
	ServicePort   int32
	Namespace     string
	HasOAuthProxy bool // Whether component currently uses oauth-proxy
}

// buildComponentMigrationPlan creates a migration plan for a specific component
// This will be used in future iterations to migrate components from Routes to HTTPRoutes
//
//nolint:unused // Part of planned component migration implementation
func buildComponentMigrationPlan(componentName string) *ComponentMigrationPlan {
	// TODO: Implement component analysis logic
	// This should examine existing component deployments and extract:
	// - Current Route configuration
	// - Service endpoints
	// - OAuth proxy configuration
	// - Required path mappings

	return &ComponentMigrationPlan{
		ComponentName: componentName,
		RoutePath:     buildComponentRoute(componentName),
		// TODO: Populate other fields from component analysis
	}
}
