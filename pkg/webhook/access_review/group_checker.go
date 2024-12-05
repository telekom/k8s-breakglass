package accessreview

import (
	"bytes"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/kubectl/pkg/cmd/auth"
	"k8s.io/kubernetes/pkg/apis/authorization"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

// _ "k8s.io/client-go/plugin/pkg/client/auth"

func CanUserDo(sar authorization.SubjectAccessReview) bool {
	o := auth.CanIOptions{
		Verb: sar.Spec.ResourceAttributes.Verb,
		Resource: schema.GroupVersionResource{
			Resource: sar.Spec.ResourceAttributes.Resource,
			Version:  sar.Spec.ResourceAttributes.Version,
			Group:    sar.Spec.ResourceAttributes.Group,
		},
		Namespace: sar.Namespace,
	}
	o.Out = new(bytes.Buffer)

	cfg := config.GetConfigOrDie()

	cfg.Impersonate = rest.ImpersonationConfig{
		UserName: sar.Spec.User,
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		fmt.Println(err)
		return false
	}

	o.AuthClient = client.AuthorizationV1()

	ret, err := o.RunAccessCheck()
	if err != nil {
		fmt.Println(err)
		return false
	}

	return ret
}
