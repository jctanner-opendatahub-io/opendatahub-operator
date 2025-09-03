package gateway

// Gateway Service CRD permissions
// +kubebuilder:rbac:groups=services.platform.opendatahub.io,resources=gateways,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=services.platform.opendatahub.io,resources=gateways/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=services.platform.opendatahub.io,resources=gateways/finalizers,verbs=update;patch

// Gateway API permissions - Core gateway infrastructure
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gatewayclasses,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gateways,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=httproutes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gatewayclasses/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gateways/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=httproutes/status,verbs=get;update;patch

// Authentication mode detection - OpenShift cluster configuration  
// +kubebuilder:rbac:groups=config.openshift.io,resources=authentications,verbs=get;list;watch
// +kubebuilder:rbac:groups=operator.openshift.io,resources=kubeapiservers,verbs=get;list;watch

// Authentication proxy infrastructure
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete

// RBAC for authentication proxy
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterrolebindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings,verbs=get;list;watch;create;update;patch;delete

// OAuth client management (OpenShift OAuth integration)
// +kubebuilder:rbac:groups=oauth.openshift.io,resources=oauthclients,verbs=get;list;watch;create;update;patch;delete

// Istio EnvoyFilter for ext_authz configuration
// +kubebuilder:rbac:groups=networking.istio.io,resources=envoyfilters,verbs=get;list;watch;create;update;patch;delete

// User and group access for authentication
// +kubebuilder:rbac:groups=user.openshift.io,resources=users,verbs=get;list;watch
// +kubebuilder:rbac:groups=user.openshift.io,resources=groups,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=users,verbs=get;list;watch  
// +kubebuilder:rbac:groups="",resources=groups,verbs=get;list;watch

// Token validation for authentication proxy
// +kubebuilder:rbac:groups=authentication.k8s.io,resources=tokenreviews,verbs=create;get
// +kubebuilder:rbac:groups=authorization.k8s.io,resources=subjectaccessreviews,verbs=create;get

// OAuth token management (OpenShift OAuth mode)
// +kubebuilder:rbac:groups=oauth.openshift.io,resources=oauthaccesstokens,verbs=get;list;create;delete

// Events for debugging and status reporting
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
