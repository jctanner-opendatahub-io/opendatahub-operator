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
	"embed"
	"fmt"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	serviceApi "github.com/opendatahub-io/opendatahub-operator/v2/api/services/v1alpha1"
	odhtypes "github.com/opendatahub-io/opendatahub-operator/v2/pkg/controller/types"
	"github.com/opendatahub-io/opendatahub-operator/v2/pkg/metadata/annotations"
)

const (
	GatewayTemplate = "resources/gateway.tmpl.yaml"
)

//go:embed resources
var resourcesFS embed.FS

func initialize(ctx context.Context, rr *odhtypes.ReconciliationRequest) error {
	rr.Templates = []odhtypes.TemplateInfo{
		{
			FS:   resourcesFS,
			Path: GatewayTemplate,
		},
	}

	return nil
}

func createGatewayClass(ctx context.Context, rr *odhtypes.ReconciliationRequest) error {
	log := logf.FromContext(ctx)

	// Create Istio GatewayClass resource
	gatewayClass := &gwapiv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: generateGatewayClassName(),
			Labels: map[string]string{
				"app.kubernetes.io/name":       "istio-gateway",
				"app.kubernetes.io/component":  "gatewayclass",
				"app.kubernetes.io/managed-by": "opendatahub-operator",
			},
			Annotations: map[string]string{
				annotations.ManagedByODHOperator: "true",
			},
		},
		Spec: gwapiv1.GatewayClassSpec{
			ControllerName: "istio.io/gateway-controller",
			Description:    ptr.To("Istio Gateway implementation for OpenDataHub"),
		},
	}

	if err := rr.AddResources(gatewayClass); err != nil {
		return fmt.Errorf("failed to add gateway class: %w", err)
	}

	log.Info("GatewayClass created successfully", "name", gatewayClass.Name, "controllerName", gatewayClass.Spec.ControllerName)
	return nil
}

func createGatewayServiceResource(ctx context.Context, rr *odhtypes.ReconciliationRequest) error {
	log := logf.FromContext(ctx)

	// This function is called when reconciling an existing Gateway service resource
	// The Gateway service resource should already exist if we're here
	// But we can log some information about the current resource being reconciled

	if rr.Instance != nil {
		gatewayInstance, ok := rr.Instance.(*serviceApi.Gateway)
		if ok {
			log.Info("Reconciling existing Gateway service resource",
				"name", gatewayInstance.Name,
				"namespace", gatewayInstance.Namespace,
				"domain", gatewayInstance.Spec.Domain)
		}
	}

	return nil
}

func createGatewayService(ctx context.Context, rr *odhtypes.ReconciliationRequest) error {
	log := logf.FromContext(ctx)

	// Create a Gateway Service object if it doesn't exist
	gatewayService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "odh-gateway",
			Namespace: rr.DSCI.Spec.ApplicationsNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "odh-gateway",
				"app.kubernetes.io/component":  "gateway",
				"app.kubernetes.io/managed-by": "opendatahub-operator",
			},
			Annotations: map[string]string{
				annotations.ManagedByODHOperator: "true",
			},
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{
					Name:     "http",
					Port:     80,
					Protocol: corev1.ProtocolTCP,
				},
				{
					Name:     "https",
					Port:     443,
					Protocol: corev1.ProtocolTCP,
				},
			},
			Selector: map[string]string{
				"app.kubernetes.io/name": "odh-gateway",
			},
		},
	}

	if err := rr.AddResources(gatewayService); err != nil {
		return fmt.Errorf("failed to add gateway service: %w", err)
	}

	log.Info("Gateway service added successfully", "service", gatewayService.Name)
	return nil
}

func createCertificateResources(ctx context.Context, rr *odhtypes.ReconciliationRequest) error {
	log := logf.FromContext(ctx)

	// Get the Gateway instance
	gatewayInstance, ok := rr.Instance.(*serviceApi.Gateway)
	if !ok {
		return fmt.Errorf("instance is not of type *services.Gateway")
	}

	// Only create cert-manager resources if certificate type is CertManager
	if gatewayInstance.Spec.Certificate == nil || gatewayInstance.Spec.Certificate.Type != serviceApi.CertManagerCertificate {
		log.Info("Skipping cert-manager certificate creation", "certificateType", gatewayInstance.Spec.Certificate)
		return nil
	}

	// Generate certificate name if not provided
	certName := "odh-gateway-tls"
	if gatewayInstance.Spec.Certificate.SecretName != "" {
		certName = gatewayInstance.Spec.Certificate.SecretName
	}

	// Set default issuer if not provided
	issuerRef := gatewayInstance.Spec.Certificate.IssuerRef
	if issuerRef == nil {
		issuerRef = &serviceApi.GatewayIssuerRef{
			Name:  "odh-gateway-issuer",
			Kind:  "ClusterIssuer",
			Group: "cert-manager.io",
		}
	}

	// Get domain from gateway domain function
	domain, err := getGatewayDomain(ctx, rr.Client)
	if err != nil {
		log.Info("Failed to get gateway domain, using default", "error", err)
		domain = "gateway.local"
	}

	// Create cert-manager Certificate resource
	certificate := &certmanagerv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      certName,
			Namespace: rr.DSCI.Spec.ApplicationsNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "odh-gateway",
				"app.kubernetes.io/component":  "gateway",
				"app.kubernetes.io/managed-by": "opendatahub-operator",
			},
			Annotations: map[string]string{
				annotations.ManagedByODHOperator: "true",
			},
		},
		Spec: certmanagerv1.CertificateSpec{
			SecretName: certName + "-secret",
			IssuerRef: cmmeta.ObjectReference{
				Name:  issuerRef.Name,
				Kind:  issuerRef.Kind,
				Group: issuerRef.Group,
			},
			DNSNames: []string{
				fmt.Sprintf("*.%s", domain),
				domain,
			},
			SecretTemplate: &certmanagerv1.CertificateSecretTemplate{
				Labels: map[string]string{
					"app.kubernetes.io/name":       "odh-gateway",
					"app.kubernetes.io/component":  "gateway-tls",
					"app.kubernetes.io/managed-by": "opendatahub-operator",
				},
				Annotations: map[string]string{
					annotations.ManagedByODHOperator: "true",
				},
			},
		},
	}

	if err := rr.AddResources(certificate); err != nil {
		return fmt.Errorf("failed to add cert-manager certificate: %w", err)
	}

	log.Info("cert-manager Certificate created successfully", "certificate", certificate.Name, "secretName", certificate.Spec.SecretName)
	return nil
}
