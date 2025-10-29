package breakglass

import (
	"context"
	"fmt"
	"os"
	"time"

	"go.uber.org/zap"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"

	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/system"
)

// K8sEventRecorder implements record.EventRecorder but writes Events via the provided clientset.
// Clientset is the kubernetes client to use for creating Events. Use the
// kubernetes.Interface here so unit tests can inject the fake clientset.
type K8sEventRecorder struct {
	Clientset kubernetes.Interface
	Source    corev1.EventSource
	// Namespace where events should be created (controller pod namespace)
	Namespace string
	// optional logger for reporting event creation problems
	Logger *zap.SugaredLogger
}

func (r *K8sEventRecorder) Event(object runtime.Object, eventtype, reason, message string) {
	metaObj, ok := object.(metav1.Object)
	if !ok {
		return
	}
	// Per new policy: always emit events into the same namespace the object
	// lives in. Only for cluster-scoped objects (object namespace empty) we
	// fall back to the POD_NAMESPACE environment variable. If neither the
	// object's namespace nor POD_NAMESPACE is available, do not create an
	// Event (best-effort, but avoids writing into an unrelated namespace).
	objNS := metaObj.GetNamespace()
	podNS := os.Getenv("POD_NAMESPACE")

	var ns string
	var involvedNS string
	if objNS != "" {
		ns = objNS
		involvedNS = objNS
	} else if podNS != "" {
		ns = podNS
		involvedNS = podNS
	} else {
		if r.Logger != nil {
			r.Logger.Infow("skipping kubernetes Event creation: object has no namespace and POD_NAMESPACE is not set", "object", metaObj.GetName())
		}
		return
	}

	ev := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: metaObj.GetName() + "-",
			Namespace:    ns,
		},
		InvolvedObject: corev1.ObjectReference{
			Namespace: involvedNS,
			Name:      metaObj.GetName(),
			UID:       metaObj.GetUID(),
		},
		Reason:         reason,
		Message:        message,
		Source:         r.Source,
		FirstTimestamp: metav1.NewTime(time.Now()),
		LastTimestamp:  metav1.NewTime(time.Now()),
		Count:          1,
		Type:           eventtype,
	}
	// best-effort write; surface errors to optional logger so operators can diagnose
	if created, err := r.Clientset.CoreV1().Events(ns).Create(context.Background(), ev, metav1.CreateOptions{}); err != nil {
		if r.Logger != nil {
			// include namespace information for the involved object
			fields := system.NamespacedFields(metaObj.GetName(), ns)
			r.Logger.Warnw("failed to create kubernetes Event", append(fields, "reason", reason, "message", message, "error", err)...)
		}
	} else {
		if r.Logger != nil {
			// created is namespaced where Namespace == ns
			fields := system.NamespacedFields(created.GetName(), created.GetNamespace())
			r.Logger.Debugw("kubernetes Event created", append(fields, "reason", reason, "message", message)...)
		}
	}
}

func (r *K8sEventRecorder) Eventf(object runtime.Object, eventtype, reason, messageFmt string, args ...interface{}) {
	// format message and delegate
	msg := messageFmt
	if len(args) > 0 {
		msg = fmt.Sprintf(messageFmt, args...)
	}
	r.Event(object, eventtype, reason, msg)
}

func (r *K8sEventRecorder) AnnotatedEventf(object runtime.Object, annotations map[string]string, eventtype, reason, messageFmt string, args ...interface{}) {
	// annotated events are not fully supported via clientset create path
	// maintain existing behavior: format message and create an Event
	msg := messageFmt
	if len(args) > 0 {
		msg = fmt.Sprintf(messageFmt, args...)
	}
	r.Event(object, eventtype, reason, msg)
}

// Ensure K8sEventRecorder satisfies record.EventRecorder
var _ record.EventRecorder = &K8sEventRecorder{}
