package breakglass

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// Test that K8sEventRecorder emits Events into the same namespace as the object
func TestEventRecorder_UsesObjectNamespace(t *testing.T) {
	cs := fake.NewSimpleClientset() //nolint:staticcheck // TODO: migrate to NewClientset when available
	logger, _ := zap.NewDevelopment()
	rec := &K8sEventRecorder{Clientset: cs, Source: corev1.EventSource{Component: "test"}, Logger: logger.Sugar()}

	// create a Namespaced object (simulate a CR) as metav1.Object
	obj := &metav1.PartialObjectMetadata{}
	obj.SetName("myobj")
	obj.SetNamespace("myns")
	obj.SetUID("1111")

	rec.Eventf(obj, nil, "Normal", "ReasonTest", "ReasonTest", "message")

	// give the fake client a moment (not strictly necessary for fake client)
	time.Sleep(10 * time.Millisecond)

	evs, err := cs.EventsV1().Events("myns").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("failed to list events: %v", err)
	}
	if len(evs.Items) == 0 {
		t.Fatalf("expected at least one event in namespace 'myns', got 0")
	}
	// verify involved object namespace is set to object's namespace
	found := false
	for _, e := range evs.Items {
		if e.Regarding.Namespace == "myns" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected event involvedObject.namespace to be 'myns'")
	}
}

// Test that when object has no namespace, recorder falls back to controller namespace
func TestEventRecorder_FallbackToPodNamespace(t *testing.T) {
	cs := fake.NewSimpleClientset() //nolint:staticcheck // TODO: migrate to NewClientset when available
	logger, _ := zap.NewDevelopment()
	rec := &K8sEventRecorder{Clientset: cs, Source: corev1.EventSource{Component: "test"}, Namespace: "podns", Logger: logger.Sugar()}

	// object without namespace -> cluster-scoped
	obj := &metav1.PartialObjectMetadata{}
	obj.SetName("clusterobj")
	obj.SetUID("2222")

	rec.Eventf(obj, nil, "Warning", "ReasonCluster", "ReasonCluster", "cluster message")
	time.Sleep(10 * time.Millisecond)

	evs, err := cs.EventsV1().Events("podns").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("failed to list events: %v", err)
	}
	if len(evs.Items) == 0 {
		t.Fatalf("expected at least one event in namespace 'podns', got 0")
	}
	// ensure involved object namespace equals podns as set by the recorder
	found := false
	for _, e := range evs.Items {
		if e.Regarding.Namespace == "podns" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected event involvedObject.namespace to be 'podns' when object has no namespace")
	}
}
