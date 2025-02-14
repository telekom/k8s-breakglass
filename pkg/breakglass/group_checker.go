package breakglass

import (
	"context"
	"fmt"
	"io"

	"github.com/pkg/errors"
	authenticationv1 "k8s.io/api/authentication/v1"
	authenticationv1alpha1 "k8s.io/api/authentication/v1alpha1"
	authenticationv1beta1 "k8s.io/api/authentication/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/cli-runtime/pkg/printers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/kubectl/pkg/cmd/auth"
	"k8s.io/kubectl/pkg/util/term"
	"k8s.io/kubernetes/pkg/apis/authorization"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

type KAuthManager struct {
	clustername string
}

func NewKAuthManager(clustername string) KAuthManager {
	return KAuthManager{clustername: clustername}
}

// Checks if operations defined in access review could be performed if user belongs to given groups.
// FIXME: This call has to be based on cluster name to get proper kubeconfig context
// TODO: This calls should probably include context.Context for timeouts and cancellation
func CanUserDo(sar authorization.SubjectAccessReview, groups []string) (bool, error) {
	o := auth.CanIOptions{
		Verb: sar.Spec.ResourceAttributes.Verb,
		Resource: schema.GroupVersionResource{
			Version:  sar.Spec.ResourceAttributes.Version,
			Resource: sar.Spec.ResourceAttributes.Resource,
		},
		ResourceName: sar.Spec.ResourceAttributes.Resource,
		Namespace:    sar.Spec.ResourceAttributes.Namespace,
	}
	o.ErrOut = io.Discard
	// could be saved to buffer and displayed as debug or some reason information
	o.Out = io.Discard

	o.WarningPrinter = printers.NewWarningPrinter(o.ErrOut, printers.WarningPrinterOptions{Color: term.AllowsColorOutput(o.ErrOut)})
	if err := o.Validate(); err != nil {
		return false, errors.Wrap(err, "failed to create validate CanIOptions")
	}

	// TODO: Probably this default config might be not enough as we need
	// to specify cluster.
	cfg, err := config.GetConfig()
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

	o.AuthClient = client.AuthorizationV1()

	ret, err := o.RunAccessCheck()
	if err != nil {
		return false, errors.Wrap(err, "failed to run access check")
	}

	return ret, nil
}

// Returns users groups assigned in cluster by duplicating kubectl auth whoami logic.
// FIXME: This call has to be based on cluster name to get proper kubeconfig context
func GetUserGroups(username string) ([]string, error) {
	cfg, err := config.GetConfig()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get config")
	}

	cfg.Impersonate = rest.ImpersonationConfig{
		UserName: username,
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
