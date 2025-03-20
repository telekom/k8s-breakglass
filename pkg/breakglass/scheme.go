package breakglass

import (
	telekomv1alpha1 "gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
)

var Scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(Scheme))

	utilruntime.Must(telekomv1alpha1.AddToScheme(Scheme))
	// +kubebuilder:scaffold:scheme
}
