# Gateway Controller Resources

This directory contains template resources used by the Gateway Controller for deploying and managing gateway infrastructure.

## Template Structure

The following templates will be implemented based on the Gateway Controller design:

### Gateway API Resources
- `gatewayclass.tmpl.yaml` - GatewayClass resource with OpenShift controller reference
- `gateway.tmpl.yaml` - Gateway resource with HTTPS listeners and domain configuration
- `httproute.tmpl.yaml` - HTTPRoute template for component routing (future migration)

### Authentication Proxy Resources
- `auth-proxy-deployment.tmpl.yaml` - kube-auth-proxy deployment with authentication configuration
- `auth-proxy-service.tmpl.yaml` - Service for auth proxy (ext_authz endpoint)
- `auth-proxy-configmap.tmpl.yaml` - Configuration for different auth modes (OAuth/OIDC/Webhook)
- `oauth-client-secret.tmpl.yaml` - OAuth client registration for OpenShift OAuth integration

### Certificate Resources
- `gateway-tls-secret.tmpl.yaml` - TLS certificate secret for Gateway termination
- `auth-proxy-serving-cert.tmpl.yaml` - Serving certificate for auth proxy HTTPS

### Service Mesh Integration
- `envoyfilter-extauthz.tmpl.yaml` - EnvoyFilter for ext_authz configuration (if Service Mesh used)
- `destinationrule.tmpl.yaml` - DestinationRule for auth proxy service (if Service Mesh used)

## Template Data

Templates receive data from the `getTemplateData()` function in `gateway_controller_actions.go`:

```go
type TemplateData struct {
    Gateway              *serviceApi.Gateway        // Gateway resource being reconciled
    Domain               string                     // Gateway domain configuration  
    AuthMode             string                     // Detected authentication mode
    Namespace            string                     // Applications namespace
    ProxyConfig          *ProxyConfig              // Auth proxy configuration
    CertificateConfig    *CertificateConfig        // Certificate configuration
    GatewayLabels        map[string]string         // Standard labels for resources
    GatewayClassName     string                    // Generated GatewayClass name
    GatewayName          string                    // Generated Gateway name
    AuthProxyName        string                    // Auth proxy deployment name
}
```

## Authentication Mode Configurations

### IntegratedOAuth Mode
Templates should configure kube-auth-proxy for OpenShift OAuth integration:
- OAuth server endpoints from cluster configuration
- OAuth client credentials
- Token validation via OpenShift OAuth server

### OIDC Mode  
Templates should configure kube-auth-proxy for external OIDC provider:
- External OIDC issuer URL
- Client ID and secret references  
- JWT validation configuration
- Claim mapping from Gateway.Spec.Auth.OIDC

### None Mode (Future)
Templates should configure kube-auth-proxy for external webhook validation:
- Webhook endpoint configuration
- External token validation
- Custom authentication headers

## Development Notes

1. **Template Testing**: Each template should have corresponding unit tests
2. **Validation**: Templates should include validation for required fields
3. **Labeling**: All resources should use consistent labeling from `generateGatewayLabels()`
4. **Ownership**: Resources should have proper owner references for garbage collection
5. **Security**: Sensitive data should be properly handled via secrets and RBAC

## Implementation Priority

For MVP development, implement templates in this order:

1. **Core Gateway API**: GatewayClass and Gateway resources
2. **Basic Auth Proxy**: Deployment and service with IntegratedOAuth support
3. **Certificate Management**: Auto-generated certificates using OpenShift service-ca
4. **Status Tracking**: Resources for monitoring deployment state

Advanced features (OIDC mode, Service Mesh integration, component migration) can be added in subsequent iterations.
