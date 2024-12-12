package accessreview

import (
	"io"

	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/cli-runtime/pkg/printers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/kubectl/pkg/cmd/auth"
	"k8s.io/kubectl/pkg/util/term"
	"k8s.io/kubernetes/pkg/apis/authorization"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

// Checks if operations defined in access review could be performed if user belongs to given groups.
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
