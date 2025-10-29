package breakglass

import (
	"context"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"
)

// K8sEventRecorder implements record.EventRecorder but writes Events via the provided clientset.
type K8sEventRecorder struct {
	Clientset *kubernetes.Clientset
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
	// Determine controller (recorder) namespace.
	// Prefer the POD_NAMESPACE environment variable when present (set by many
	// deployment systems). Fall back to the recorder's configured Namespace and
	// lastly try the in-cluster serviceaccount namespace file.
	controllerNS := os.Getenv("POD_NAMESPACE")
	if controllerNS == "" {
		controllerNS = r.Namespace
	}
	if controllerNS == "" {
		// try reading namespace from pod serviceaccount file (in-cluster default)
		data, _ := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
		if len(data) > 0 {
			controllerNS = strings.TrimSpace(string(data))
		}
	}

	// Decide event namespace: prefer controller namespace when available.
	// If no controller namespace configured, fall back to the object's namespace
	// (for namespaced objects). If both are empty, use "default".
	ns := controllerNS
	if ns == "" {
		ns = metaObj.GetNamespace()
		if ns == "" {
			ns = "default"
		}
	}

	// Ensure involved object's namespace is set. For cluster-scoped objects the
	// object's namespace will be empty — in that case set it to the controller
	// namespace (so involvedObject.namespace equals the Event namespace).
	involvedNS := metaObj.GetNamespace()
	if involvedNS == "" {
		// prefer controller namespace if available, otherwise the event namespace
		if controllerNS != "" {
			involvedNS = controllerNS
		} else {
			involvedNS = ns
		}
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
			r.Logger.Warnw("failed to create kubernetes Event", "namespace", ns, "object", metaObj.GetName(), "reason", reason, "message", message, "error", err)
		}
	} else {
		if r.Logger != nil {
			r.Logger.Debugw("kubernetes Event created", "namespace", ns, "name", created.GetName(), "reason", reason, "message", message)
		}
	}
}

func (r *K8sEventRecorder) Eventf(object runtime.Object, eventtype, reason, messageFmt string, args ...interface{}) {
	// simple non-formatted path
	r.Event(object, eventtype, reason, messageFmt)
}

func (r *K8sEventRecorder) AnnotatedEventf(object runtime.Object, annotations map[string]string, eventtype, reason, messageFmt string, args ...interface{}) {
	r.Event(object, eventtype, reason, messageFmt)
}

// Ensure K8sEventRecorder satisfies record.EventRecorder
var _ record.EventRecorder = &K8sEventRecorder{}
