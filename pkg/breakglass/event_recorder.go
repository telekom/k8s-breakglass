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
	// Always emit events into the configured recorder namespace; fall back to object's namespace then default
	ns := r.Namespace
	if ns == "" {
		// try reading namespace from pod serviceaccount file (in-cluster default)
		data, _ := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
		if len(data) > 0 {
			ns = strings.TrimSpace(string(data))
		}
		if ns == "" {
			ns = metaObj.GetNamespace()
			if ns == "" {
				ns = "default"
			}
		}
	}
	ev := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: metaObj.GetName() + "-",
			Namespace:    ns,
		},
		InvolvedObject: corev1.ObjectReference{
			Namespace: metaObj.GetNamespace(),
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
