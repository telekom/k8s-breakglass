package breakglass

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
	authenticationv1 "k8s.io/api/authentication/v1"
	authenticationv1alpha1 "k8s.io/api/authentication/v1alpha1"
	authenticationv1beta1 "k8s.io/api/authentication/v1beta1"
	authorizationv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/kubernetes/pkg/apis/authorization"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

type CanGroupsDoFunction func(ctx context.Context,
	groups []string,
	sar authorization.SubjectAccessReview,
	clustername string) (bool, error)

// Checks if operations defined in access review could be performed if user belongs to given groups on a given cluster.
func CanGroupsDo(ctx context.Context,
	groups []string,
	sar authorization.SubjectAccessReview,
	clustername string,
) (bool, error) {
	cfg, err := config.GetConfigWithContext(clustername)
	if err != nil {
		return false, errors.Wrap(err, "failed to get config")
	}

	cfg.Impersonate = rest.ImpersonationConfig{
		UserName: "system:auth-checker",
		Groups:   groups,
	}

	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return false, errors.Wrap(err, "failed to create client")
	}

	authClient := client.AuthorizationV1()

	v1Sar := authorizationv1.SelfSubjectAccessReview{
		Spec: authorizationv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace:   sar.Spec.ResourceAttributes.Namespace,
				Verb:        sar.Spec.ResourceAttributes.Verb,
				Group:       sar.Spec.ResourceAttributes.Group,
				Resource:    sar.Spec.ResourceAttributes.Resource,
				Subresource: sar.Spec.ResourceAttributes.Subresource,
				Name:        sar.Spec.ResourceAttributes.Resource,
			},
		},
	}

	response, err := authClient.SelfSubjectAccessReviews().Create(ctx, &v1Sar, metav1.CreateOptions{})
	if err != nil {
		return false, err
	}

	return response.Status.Allowed, nil
}

// Returns users groups assigned in cluster by duplicating kubectl auth whoami logic.
func GetUserGroups(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
	cfg, err := config.GetConfigWithContext(cug.Clustername)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get config")
	}

	cfg.Impersonate = rest.ImpersonationConfig{
		UserName: cug.Username,
	}

	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create client")
	}

	var res runtime.Object

	res, err = client.AuthenticationV1().SelfSubjectReviews().Create(context.TODO(), &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})

	if err != nil && apierrors.IsNotFound(err) {
		// Fallback to Beta API if Beta is not enabled
		res, err = client.AuthenticationV1beta1().
			SelfSubjectReviews().
			Create(context.TODO(), &authenticationv1beta1.SelfSubjectReview{}, metav1.CreateOptions{})
		if err != nil && apierrors.IsNotFound(err) {
			// Fallback to Alpha API if Beta is not enabled
			res, err = client.AuthenticationV1alpha1().
				SelfSubjectReviews().
				Create(context.TODO(), &authenticationv1alpha1.SelfSubjectReview{}, metav1.CreateOptions{})
		}
	}

	if err != nil {
		return nil, errors.Wrap(err, "failed to get users subject review")
	}

	ui, err := getUserInfo(res)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get user info from response")
	}

	return ui.Groups, nil
}

func getUserInfo(obj runtime.Object) (authenticationv1.UserInfo, error) {
	switch val := obj.(type) {
	case *authenticationv1alpha1.SelfSubjectReview:
		return val.Status.UserInfo, nil
	case *authenticationv1beta1.SelfSubjectReview:
		return val.Status.UserInfo, nil
	case *authenticationv1.SelfSubjectReview:
		return val.Status.UserInfo, nil
	default:
		return authenticationv1.UserInfo{}, fmt.Errorf("unexpected response type %T, expected SelfSubjectReview", obj)
	}
}
