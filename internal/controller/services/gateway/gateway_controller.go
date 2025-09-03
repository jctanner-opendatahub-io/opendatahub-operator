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
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/opendatahub-io/opendatahub-operator/v2/api/common"
	dsciv1 "github.com/opendatahub-io/opendatahub-operator/v2/api/dscinitialization/v1"
	serviceApi "github.com/opendatahub-io/opendatahub-operator/v2/api/services/v1alpha1"
	sr "github.com/opendatahub-io/opendatahub-operator/v2/internal/controller/services/registry"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/controller/actions/deploy"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/controller/actions/render/template"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/controller/handlers"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/controller/reconciler"
)

//nolint:gochecknoinits
func init() {
	// Register this service handler with the service registry
	// This ensures the Gateway controller is automatically started when the operator begins
	sr.Add(&ServiceHandler{})
}

// ServiceHandler implements the service registry interface for the Gateway controller.
// Manages the lifecycle and configuration of the Gateway service.
type ServiceHandler struct {
}

// Init initializes the Gateway service handler.
// Called during operator startup to prepare service-specific resources.
func (h *ServiceHandler) Init(_ common.Platform) error {
	// TODO: Initialize any service-specific resources
	// Examples:
	// - Validate Gateway API CRDs are installed
	// - Check for required permissions
	// - Initialize authentication mode detector
	return nil
}

// GetName returns the service name for registration and logging.
func (h *ServiceHandler) GetName() string {
	return ServiceName
}

// GetManagementState determines if the Gateway service should be managed.
// Based on platform configuration and DSCInitialization settings.
func (h *ServiceHandler) GetManagementState(platform common.Platform, dsci *dsciv1.DSCInitialization) operatorv1.ManagementState {
	// For MVP: Gateway service is managed if:
	// 1. We're on OpenShift (has Gateway API support)
	// 2. DSCInitialization exists (general ODH setup is ready)
	//
	// Note: Future versions should add a Gateway field to DSCInitialization
	// to allow explicit enable/disable like other services

	if dsci == nil {
		// No DSCI means ODH isn't properly initialized
		return operatorv1.Unmanaged
	}

	// Check if we have the minimum requirements for Gateway operation
	if dsci.Spec.ApplicationsNamespace == "" {
		// Need applications namespace to deploy auth proxy
		return operatorv1.Unmanaged
	}

	// For MVP, enable Gateway service when DSCI is present and configured
	// This allows testing without needing to modify DSCInitialization CRD
	return operatorv1.Managed
}

// NewReconciler creates and configures the Gateway controller reconciler.
// Sets up watches, actions, and reconciliation logic following the design patterns.
func (h *ServiceHandler) NewReconciler(ctx context.Context, mgr ctrl.Manager) error {
	// Create the reconciler using the common reconciler framework
	// This follows the same pattern as other service controllers in the codebase
	_, err := reconciler.ReconcilerFor(mgr, &serviceApi.Gateway{}).
		// === OWNED RESOURCES ===
		// Resources that the Gateway controller creates and manages

		// Gateway API resources - core infrastructure
		Owns(&gwapiv1.GatewayClass{}).
		Owns(&gwapiv1.Gateway{}).
		Owns(&gwapiv1.HTTPRoute{}).

		// Authentication proxy resources
		Owns(&appsv1.Deployment{}).     // kube-auth-proxy deployment
		Owns(&corev1.Service{}).        // kube-auth-proxy service
		Owns(&corev1.Secret{}).         // OAuth client secrets, TLS certificates
		Owns(&corev1.ConfigMap{}).      // Proxy configuration, Envoy config
		Owns(&corev1.ServiceAccount{}). // Service account for auth proxy
		Owns(&rbacv1.ClusterRole{}).    // RBAC for auth proxy
		Owns(&rbacv1.ClusterRoleBinding{}).

		// === WATCHED RESOURCES ===
		// External resources that trigger reconciliation when changed

		// Authentication configuration changes (from SPIKE-1 findings)
		Watches(&configv1.Authentication{},
			reconciler.WithEventHandler(handlers.ToNamed(serviceApi.GatewayInstanceName))).

		// KubeAPIServer status for OIDC rollout tracking
		Watches(&operatorv1.KubeAPIServer{},
			reconciler.WithEventHandler(handlers.ToNamed(serviceApi.GatewayInstanceName))).

		// === ACTIONS ===
		// Reconciliation actions in dependency order

		// Phase 1: Authentication Mode Detection and Validation
		WithAction(detectAuthenticationMode).   // Detect cluster auth mode using SPIKE-1 logic
		WithAction(validateOIDCRollout).        // Wait for OIDC rollout completion if needed
		WithAction(updateAuthenticationStatus). // Update status with detected mode

		// Phase 2: Gateway API Infrastructure
		WithAction(createGatewayClass).  // Create GatewayClass with OpenShift controller
		WithAction(createGateway).       // Create Gateway resource in openshift-ingress
		WithAction(waitForGatewayReady). // Wait for Gateway to be assigned an address

		// Phase 3: Authentication Proxy Infrastructure
		WithAction(deployAuthProxy).        // Add auth proxy templates to list
		WithAction(configureEnvoyExtAuthz). // Add EnvoyFilter template to list
		WithAction(template.NewAction(      // Template rendering for ALL resources (including auth proxy)
			template.WithDataFn(getTemplateData),
		)).

		// Phase 4: Certificate Management
		WithAction(manageCertificates). // Handle TLS certificates for gateway and proxy

		// Phase 5: Component Integration (Future)
		// WithAction(createComponentHTTPRoutes).    // Create HTTPRoutes for ODH components
		// WithAction(migrateFromRoutes).           // Migrate components from Routes to HTTPRoutes

		// Phase 6: Deployment and Status
		WithAction(deploy.NewAction( // Deploy all rendered resources
			deploy.WithCache(),
		)).
		WithAction(updateGatewayStatus). // Update status with deployment results

		// === FINALIZERS ===
		// Cleanup actions when Gateway is deleted
		WithFinalizer(cleanupGatewayResources). // Clean up Gateway API resources
		WithFinalizer(cleanupAuthProxy).        // Clean up authentication proxy

		// === CONDITIONS ===
		// Status conditions for tracking reconciliation state
		WithConditions(
			"AuthModeDetected",    // Authentication mode successfully detected
			"OIDCRolloutComplete", // OIDC rollout completed (if applicable)
			"GatewayReady",        // Gateway API resources ready
			"AuthProxyReady",      // Authentication proxy deployed and ready
			"CertificatesReady",   // TLS certificates configured
			"Ready",               // Overall readiness condition
		).

		// Build the reconciler and register with the manager
		Build(ctx)

	if err != nil {
		return fmt.Errorf("could not create the Gateway controller: %w", err)
	}

	return nil
}

// === MAPPING FUNCTIONS ===
// Functions to map watched resources to Gateway reconciliation requests

// mapAuthToGateway maps Authentication CR changes to Gateway reconciliation
//
//nolint:unused // Part of planned architecture, will be used when watches are implemented
func (h *ServiceHandler) mapAuthToGateway(_ context.Context, obj client.Object) []reconcile.Request {
	// TODO: Implement mapping logic
	// Should trigger reconciliation of the singleton Gateway resource
	// when cluster authentication configuration changes
	return []reconcile.Request{
		{NamespacedName: client.ObjectKey{Name: serviceApi.GatewayInstanceName}},
	}
}

// mapKASToGateway maps KubeAPIServer CR changes to Gateway reconciliation
//
//nolint:unused // Part of planned architecture, will be used when watches are implemented
func (h *ServiceHandler) mapKASToGateway(_ context.Context, obj client.Object) []reconcile.Request {
	// TODO: Implement mapping logic
	// Should trigger reconciliation when KubeAPIServer status changes
	// (relevant for OIDC rollout tracking)
	return []reconcile.Request{
		{NamespacedName: client.ObjectKey{Name: serviceApi.GatewayInstanceName}},
	}
}

// mapConfigMapToGateway maps auth-related ConfigMap changes to Gateway reconciliation
//
//nolint:unused // Part of planned architecture, will be used when watches are implemented
func (h *ServiceHandler) mapConfigMapToGateway(_ context.Context, obj client.Object) []reconcile.Request {
	// TODO: Implement mapping logic
	// Should trigger reconciliation when auth-config-* or config-* ConfigMaps change
	// (relevant for OIDC rollout detection)
	return []reconcile.Request{
		{NamespacedName: client.ObjectKey{Name: serviceApi.GatewayInstanceName}},
	}
}

// isAuthConfigMap filters ConfigMaps to only auth-related ones in openshift-kube-apiserver
//
//nolint:unused // Part of planned architecture, will be used when watches are implemented
func (h *ServiceHandler) isAuthConfigMap(obj interface{}) bool {
	// TODO: Implement filtering logic from SPIKE-1 findings
	// Should return true for:
	// - ConfigMaps in openshift-kube-apiserver namespace
	// - Names starting with "auth-config-" or "config-"
	// These are used for OIDC rollout validation
	return false
}
