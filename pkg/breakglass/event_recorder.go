package breakglass

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/events"
	"k8s.io/client-go/tools/reference"

	"github.com/telekom/k8s-breakglass/pkg/system"
)

// K8sEventRecorder implements events.EventRecorder and writes Events via the provided clientset.
// Clientset is the kubernetes client to use for creating Events. Use the
// kubernetes.Interface here so unit tests can inject the fake clientset.
type K8sEventRecorder struct {
	Clientset kubernetes.Interface
	Source    corev1.EventSource
	Scheme    *runtime.Scheme
	// Namespace where events should be created (controller pod namespace)
	Namespace string
	// optional logger for reporting event creation problems
	Logger *zap.SugaredLogger
}

func (r *K8sEventRecorder) Eventf(regarding runtime.Object, related runtime.Object, eventtype, reason, action, note string, args ...interface{}) {
	metaObj, ok := regarding.(metav1.Object)
	if !ok {
		return
	}
	// Per new policy: always emit events into the same namespace the object
	// lives in. Only for cluster-scoped objects (object namespace empty) we
	// fall back to the controller's pod namespace (from r.Namespace field).
	// If neither the object's namespace nor the controller's namespace is available,
	// do not create an Event (best-effort, but avoids writing into an unrelated namespace).
	objNS := metaObj.GetNamespace()
	podNS := r.Namespace

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
			r.Logger.Infow("skipping kubernetes Event creation: object has no namespace and controller namespace is not set", "object", metaObj.GetName())
		}
		return
	}

	regardingRef := &corev1.ObjectReference{
		Namespace: involvedNS,
		Name:      metaObj.GetName(),
		UID:       metaObj.GetUID(),
	}
	if r.Scheme != nil {
		if ref, err := reference.GetReference(r.Scheme, regarding); err == nil {
			regardingRef = ref
		}
	}

	var relatedRef *corev1.ObjectReference
	if related != nil {
		if r.Scheme != nil {
			if ref, err := reference.GetReference(r.Scheme, related); err == nil {
				relatedRef = ref
			}
		}
	}

	noteMessage := note
	if len(args) > 0 {
		noteMessage = fmt.Sprintf(note, args...)
	}

	// For events.k8s.io/v1 API:
	// - ReportingInstance is required and must be non-empty
	// - Deprecated fields (firstTimestamp, lastTimestamp, count, source) must NOT be set
	reportingInstance := r.Source.Host
	if reportingInstance == "" {
		// Use component name as fallback if host is not set
		reportingInstance = r.Source.Component
	}

	ev := &eventsv1.Event{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: metaObj.GetName() + "-",
			Namespace:    ns,
		},
		Regarding:           *regardingRef,
		Related:             relatedRef,
		Reason:              reason,
		Note:                noteMessage,
		Type:                eventtype,
		Action:              action,
		ReportingController: r.Source.Component,
		ReportingInstance:   reportingInstance,
		EventTime:           metav1.MicroTime{Time: time.Now()},
		// NOTE: Do NOT set deprecated fields (DeprecatedSource, DeprecatedFirstTimestamp,
		// DeprecatedLastTimestamp, DeprecatedCount) - events.k8s.io/v1 API rejects them
	}
	// NOTE: Using Events().Create() instead of SSA.
	// Reason: Kubernetes Events are ephemeral, best-effort resources. They are
	// automatically garbage-collected by the API server (default TTL: 1 hour).
	// SSA would add unnecessary overhead for resources that are never updated.
	if created, err := r.Clientset.EventsV1().Events(ns).Create(context.Background(), ev, metav1.CreateOptions{}); err != nil {
		if r.Logger != nil {
			// include namespace information for the involved object
			fields := system.NamespacedFields(metaObj.GetName(), ns)
			r.Logger.Warnw("failed to create kubernetes Event", append(fields, "reason", reason, "note", noteMessage, "error", err)...)
		}
	} else {
		if r.Logger != nil {
			// created is namespaced where Namespace == ns
			fields := system.NamespacedFields(created.GetName(), created.GetNamespace())
			r.Logger.Debugw("kubernetes Event created", append(fields, "reason", reason, "note", noteMessage)...)
		}
	}
}

// Ensure K8sEventRecorder satisfies events.EventRecorder
var _ events.EventRecorder = &K8sEventRecorder{}
