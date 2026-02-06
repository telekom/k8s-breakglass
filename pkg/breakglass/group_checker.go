package breakglass

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"go.uber.org/zap"
	authenticationv1 "k8s.io/api/authentication/v1"
	authenticationv1alpha1 "k8s.io/api/authentication/v1alpha1"
	authenticationv1beta1 "k8s.io/api/authentication/v1beta1"
	authorizationv1 "k8s.io/api/authorization/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	pkgconfig "github.com/telekom/k8s-breakglass/pkg/config"
)

type CanGroupsDoFunction func(ctx context.Context,
	rc *rest.Config,
	groups []string,
	sar authorizationv1.SubjectAccessReview,
	clustername string) (bool, error)

type GetUserGroupsFunction func(ctx context.Context, cug ClusterUserGroup) ([]string, error)

// Checks if operations defined in access review could be performed if user belongs to given groups on a given cluster.
func getConfigForClusterName(name string) (*rest.Config, error) {
	// try direct context name first
	cfg, err := config.GetConfigWithContext(name)
	if err == nil {
		zap.S().Debugw("Loaded rest.Config for cluster context", "cluster", name, "context", name)
		return cfg, nil
	}
	kindCtx := fmt.Sprintf("kind-%s", name)
	if kindCfg, kerr := config.GetConfigWithContext(kindCtx); kerr == nil {
		zap.S().Debugw("Loaded rest.Config via kind- fallback", "cluster", name, "context", kindCtx)
		return kindCfg, nil
	}
	zap.S().Warnw("Failed to load rest.Config for cluster", "cluster", name, "error", err.Error())
	return nil, err
}

// CanGroupsDo impersonates given groups against provided rest.Config (target cluster kubeconfig), not the hub.
func CanGroupsDo(ctx context.Context,
	rc *rest.Config,
	groups []string,
	sar authorizationv1.SubjectAccessReview,
	clustername string,
) (bool, error) {
	if rc == nil {
		return false, errors.New("rest config is nil")
	}
	zap.S().Debugw("Checking if groups can perform SAR operation", "groups", groups, "cluster", clustername)
	// Copy to avoid mutating shared config
	cfg := rest.CopyConfig(rc)
	cfg.Impersonate = rest.ImpersonationConfig{UserName: "system:auth-checker", Groups: groups}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		zap.S().Errorw("Failed to create client for CanGroupsDo", "error", err.Error())
		return false, fmt.Errorf("failed to create client: %w", err)
	}

	// Build SelfSubjectAccessReview spec based on whether we have resource or non-resource attributes
	var v1SarSpec authorizationv1.SelfSubjectAccessReviewSpec
	if sar.Spec.ResourceAttributes != nil {
		v1SarSpec.ResourceAttributes = &authorizationv1.ResourceAttributes{
			Namespace:   sar.Spec.ResourceAttributes.Namespace,
			Verb:        sar.Spec.ResourceAttributes.Verb,
			Group:       sar.Spec.ResourceAttributes.Group,
			Resource:    sar.Spec.ResourceAttributes.Resource,
			Subresource: sar.Spec.ResourceAttributes.Subresource,
			Name:        sar.Spec.ResourceAttributes.Name,
		}
	} else if sar.Spec.NonResourceAttributes != nil {
		v1SarSpec.NonResourceAttributes = &authorizationv1.NonResourceAttributes{
			Path: sar.Spec.NonResourceAttributes.Path,
			Verb: sar.Spec.NonResourceAttributes.Verb,
		}
	} else {
		return false, errors.New("sar spec must have either resourceAttributes or nonResourceAttributes")
	}

	v1Sar := authorizationv1.SelfSubjectAccessReview{Spec: v1SarSpec}
	// NOTE: SelfSubjectAccessReview uses Create() to "submit" the review.
	// This is not a write operation in the traditional sense - it's a readonly query
	// to check permissions. The K8s API uses POST/Create for SubjectAccessReviews
	// because they are ephemeral request/response resources, not stored objects.
	response, err := client.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &v1Sar, metav1.CreateOptions{})
	if err != nil {
		zap.S().Errorw("Failed to create SelfSubjectAccessReview", "error", err.Error())
		return false, err
	}
	zap.S().Infow("SelfSubjectAccessReview result", "allowed", response.Status.Allowed)
	return response.Status.Allowed, nil
}

// Legacy wrapper kept for compatibility (uses local context); prefer CanGroupsDo with explicit rest.Config.
func CanGroupsDoLegacy(ctx context.Context, groups []string, sar authorizationv1.SubjectAccessReview, clustername string) (bool, error) {
	rc, err := getConfigForClusterName(clustername)
	if err != nil {
		return false, err
	}
	return CanGroupsDo(ctx, rc, groups, sar, clustername)
}

// stripOIDCPrefixes removes configured OIDC prefixes from user groups to allow matching with cluster groups
func stripOIDCPrefixes(groups []string, oidcPrefixes []string) []string {
	if len(oidcPrefixes) == 0 {
		zap.S().Debug("No OIDC prefixes configured, returning groups unchanged")
		return groups
	}

	var strippedGroups []string
	zap.S().Debugw("Stripping OIDC prefixes from groups", "originalGroups", groups, "prefixes", oidcPrefixes)

	for _, group := range groups {
		strippedGroup := group
		for _, prefix := range oidcPrefixes {
			if strings.HasPrefix(group, prefix) {
				strippedGroup = strings.TrimPrefix(group, prefix)
				zap.S().Debugw("Stripped OIDC prefix from group", "originalGroup", group, "prefix", prefix, "strippedGroup", strippedGroup)
				break
			}
		}
		strippedGroups = append(strippedGroups, strippedGroup)
	}

	// Ensure we return an empty slice instead of nil for consistency
	if strippedGroups == nil {
		strippedGroups = []string{}
	}

	zap.S().Debugw("OIDC prefix stripping complete", "originalGroups", groups, "strippedGroups", strippedGroups)
	return strippedGroups
}

// getUserGroupsInternal is a shared helper function for GetUserGroups and GetUserGroupsWithConfig.
// It fetches user groups assigned in a cluster (duplicating kubectl auth whoami logic) with optional OIDC prefix stripping.
// If configPath is empty, uses the default config path.
func getUserGroupsInternal(ctx context.Context, cug ClusterUserGroup, configPath string) ([]string, error) {
	// Load config to get OIDC prefixes
	cfg, err := pkgconfig.Load(configPath)
	configLoaded := true
	if err != nil {
		zap.S().Errorw("Failed to load config for OIDC prefixes", "error", err.Error())
		// Continue without OIDC prefix stripping if config loading fails
		configLoaded = false
	}

	kubeCfg, err := getConfigForClusterName(cug.Clustername)
	if err != nil {
		zap.S().Errorw("GetUserGroups: rest.Config load failed", "cluster", cug.Clustername, "error", err.Error())
		return nil, fmt.Errorf("failed to get config: %w", err)
	}

	kubeCfg.Impersonate = rest.ImpersonationConfig{
		UserName: cug.Username,
	}

	client, err := kubernetes.NewForConfig(kubeCfg)
	if err != nil {
		zap.S().Errorw("GetUserGroups: client construction failed", "cluster", cug.Clustername, "error", err.Error())
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	var res runtime.Object
	res, err = client.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})

	if err != nil && k8serrors.IsNotFound(err) {
		zap.S().Warn("Falling back to Beta API for SelfSubjectReview")
		res, err = client.AuthenticationV1beta1().SelfSubjectReviews().Create(ctx, &authenticationv1beta1.SelfSubjectReview{}, metav1.CreateOptions{})
		if err != nil && k8serrors.IsNotFound(err) {
			zap.S().Warn("Falling back to Alpha API for SelfSubjectReview")
			res, err = client.AuthenticationV1alpha1().SelfSubjectReviews().Create(ctx, &authenticationv1alpha1.SelfSubjectReview{}, metav1.CreateOptions{})
		}
	}

	if err != nil {
		zap.S().Errorw("Failed to get user's subject review", "error", err.Error())
		return nil, fmt.Errorf("failed to get users subject review: %w", err)
	}

	ui, err := getUserInfo(res)
	if err != nil {
		zap.S().Errorw("Failed to get user info from response", "error", err.Error())
		return nil, fmt.Errorf("failed to get user info from response: %w", err)
	}

	// Apply OIDC prefix stripping if config was loaded successfully
	originalGroups := ui.Groups
	finalGroups := originalGroups
	if configLoaded && len(cfg.Kubernetes.OIDCPrefixes) > 0 {
		finalGroups = stripOIDCPrefixes(originalGroups, cfg.Kubernetes.OIDCPrefixes)
		zap.S().Infow("Applied OIDC prefix stripping", "originalGroups", originalGroups, "finalGroups", finalGroups, "oidcPrefixes", cfg.Kubernetes.OIDCPrefixes)
	} else {
		zap.S().Debug("No OIDC prefixes configured, using original groups")
	}

	return finalGroups, nil
}

func GetUserGroups(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
	zap.S().Debugw("Getting user groups for cluster user group", "cluster", cug.Clustername, "username", cug.Username)

	finalGroups, err := getUserGroupsInternal(ctx, cug, "")
	if err != nil {
		return nil, err
	}

	// Removed BREAKGLASS_E2E_ASSUME_GROUPS fallback to ensure real cluster auth is always required.

	zap.S().Infow("GetUserGroups complete", "cluster", cug.Clustername, "username", cug.Username, "groups", finalGroups, "count", len(finalGroups))
	return finalGroups, nil
}

// GetUserGroupsWithConfig returns users groups assigned in cluster with custom config path for OIDC prefix stripping.
func GetUserGroupsWithConfig(ctx context.Context, cug ClusterUserGroup, configPath string) ([]string, error) {
	zap.S().Debugw("Getting user groups for cluster user group with custom config", "cluster", cug.Clustername, "username", cug.Username, "configPath", configPath)

	finalGroups, err := getUserGroupsInternal(ctx, cug, configPath)
	if err != nil {
		return nil, err
	}

	zap.S().Infow("GetUserGroupsWithConfig complete", "cluster", cug.Clustername, "username", cug.Username, "groups", finalGroups, "count", len(finalGroups))
	return finalGroups, nil
}

func getUserInfo(obj runtime.Object) (authenticationv1.UserInfo, error) {
	switch val := obj.(type) {
	case *authenticationv1alpha1.SelfSubjectReview:
		zap.S().Debug("Parsing user info from v1alpha1.SelfSubjectReview")
		return val.Status.UserInfo, nil
	case *authenticationv1beta1.SelfSubjectReview:
		zap.S().Debug("Parsing user info from v1beta1.SelfSubjectReview")
		return val.Status.UserInfo, nil
	case *authenticationv1.SelfSubjectReview:
		zap.S().Debug("Parsing user info from v1.SelfSubjectReview")
		return val.Status.UserInfo, nil
	default:
		zap.S().Errorw("Unexpected response type for user info extraction", "type", fmt.Sprintf("%T", obj))
		return authenticationv1.UserInfo{}, fmt.Errorf("unexpected response type %T, expected SelfSubjectReview", obj)
	}
}
