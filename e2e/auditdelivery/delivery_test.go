// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package auditdelivery

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/segmentio/kafka-go"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

func kubectl(t *testing.T, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	output, err := exec.CommandContext(ctx, "kubectl", args...).CombinedOutput()
	require.NoError(t, err, "%s", output)
}

func forward(t *testing.T) func() {
	t.Helper()
	cmd := exec.Command("kubectl", "-n", "audit-delivery", "port-forward", "deployment/broker", "19093:9095")
	require.NoError(t, cmd.Start())
	stop := func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
	t.Cleanup(stop)
	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		conn, err := kafka.DialContext(ctx, "tcp", "localhost:19093")
		if err != nil {
			return false
		}
		defer conn.Close()
		_, err = conn.Brokers()
		return err == nil
	}, time.Minute, time.Second)
	return stop
}

// This isolated kind test exercises the production audit service and Kafka
// protocol during a real broker outage. API lifecycle correlation is separately
// covered by TestAuditLogging in the existing controller + Keycloak kind suite.
func TestBrokerOutageRetainsEventsAndIdentity(t *testing.T) {
	if os.Getenv("AUDIT_DELIVERY_E2E") != "true" {
		t.Skip("run hack/audit-delivery-kind.sh")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cli := kubeClient(t)
	ns := &corev1.Namespace{}
	require.NoError(t, cli.Get(ctx, client.ObjectKey{Name: "audit-delivery"}, ns))
	require.NotEmpty(t, ns.UID)
	stop := forward(t)
	t.Cleanup(func() { stop() })
	svc := audit.NewService(cli, nil, zap.NewNop(), "audit-delivery")
	require.NoError(t, svc.Reload(ctx, &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "delivery"},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{{
				Name: "outage", Type: breakglassv1alpha1.AuditSinkTypeKafka,
				Kafka: &breakglassv1alpha1.KafkaSinkSpec{Brokers: []string{"localhost:19093"}, Topic: "audit-delivery", RequiredAcks: -1, BatchSize: 1},
			}},
			Queue: &breakglassv1alpha1.AuditQueueConfig{Size: 1000, Workers: 1, DropOnFull: ptr.To(false),
				RetryAttempts: 100, RetryInitialBackoffMillis: 1000, RetryMaxBackoffMillis: 5000, RetryTimeoutSeconds: 180},
		},
	}))
	t.Cleanup(func() { require.NoError(t, svc.Close()) })
	kubectl(t, "-n", "audit-delivery", "scale", "deployment/broker", "--replicas=0")
	kubectl(t, "-n", "audit-delivery", "wait", "--for=delete", "pod", "-l", "app=audit-delivery", "--timeout=90s")
	stop()
	stop = func() {}
	groups := []string{"/operations/platform", "auditors", "system:authenticated"}
	actorCtx := audit.WithAuthenticatedActor(ctx, []string{"operator"}, groups)
	svc.Emit(actorCtx, &audit.Event{
		ID: "outage-event", Type: audit.EventConfigChanged,
		Actor:  audit.Actor{User: "operator"},
		Target: audit.Target{Kind: "Namespace", Name: ns.Name, UID: string(ns.UID)},
	})
	require.Eventually(t, func() bool {
		stats := svc.GetQueuedSinkHealth()
		return len(stats) == 1 && stats[0].FailedEvents > 0
	}, 20*time.Second, time.Second)
	kubectl(t, "-n", "audit-delivery", "scale", "deployment/broker", "--replicas=1")
	kubectl(t, "-n", "audit-delivery", "rollout", "status", "deployment/broker", "--timeout=90s")
	stop = forward(t)
	reader := kafka.NewReader(kafka.ReaderConfig{Brokers: []string{"localhost:19093"}, Topic: "audit-delivery", Partition: 0, MinBytes: 1, MaxBytes: 1e6})
	t.Cleanup(func() { require.NoError(t, reader.Close()) })
	message, err := reader.ReadMessage(ctx)
	require.NoError(t, err)
	var event audit.Event
	require.NoError(t, json.Unmarshal(message.Value, &event))
	require.Equal(t, "outage-event", event.ID)
	require.Equal(t, string(ns.UID), event.Target.UID)
	require.Equal(t, "operator", event.Actor.User)
	require.ElementsMatch(t, groups, event.Actor.Groups)
	require.NotEmpty(t, event.Timestamp)
	require.Eventually(t, func() bool {
		stats := svc.GetQueuedSinkHealth()
		return len(stats) == 1 && stats[0].ProcessedEvents == 1 && stats[0].DroppedEvents == 0
	}, 10*time.Second, time.Second)
}

func kubeClient(t *testing.T) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	cli, err := client.New(config.GetConfigOrDie(), client.Options{Scheme: scheme})
	require.NoError(t, err)
	return cli
}

func newKafkaService(ctx context.Context, t *testing.T, cli client.Client, topic string, queue *breakglassv1alpha1.AuditQueueConfig) *audit.Service {
	t.Helper()
	svc := audit.NewService(cli, nil, zap.NewNop(), "audit-delivery")
	require.NoError(t, svc.Reload(ctx, &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: topic},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{{
				Name: topic, Type: breakglassv1alpha1.AuditSinkTypeKafka,
				Kafka: &breakglassv1alpha1.KafkaSinkSpec{Brokers: []string{"localhost:19093"}, Topic: topic, RequiredAcks: -1, BatchSize: 1},
			}},
			Queue: queue,
		},
	}))
	t.Cleanup(func() { require.NoError(t, svc.Close()) })
	return svc
}

func stopBroker(t *testing.T, stopForward func()) {
	t.Helper()
	kubectl(t, "-n", "audit-delivery", "scale", "deployment/broker", "--replicas=0")
	kubectl(t, "-n", "audit-delivery", "wait", "--for=delete", "pod", "-l", "app=audit-delivery", "--timeout=90s")
	stopForward()
}

func startBroker(t *testing.T) func() {
	t.Helper()
	kubectl(t, "-n", "audit-delivery", "scale", "deployment/broker", "--replicas=1")
	kubectl(t, "-n", "audit-delivery", "rollout", "status", "deployment/broker", "--timeout=90s")
	return forward(t)
}

// readIDs consumes the topic until want messages arrived and returns their IDs.
func readIDs(ctx context.Context, t *testing.T, topic string, want int) []string {
	t.Helper()
	reader := kafka.NewReader(kafka.ReaderConfig{Brokers: []string{"localhost:19093"}, Topic: topic, Partition: 0, MinBytes: 1, MaxBytes: 1e6})
	defer func() { require.NoError(t, reader.Close()) }()
	ids := make([]string, 0, want)
	for len(ids) < want {
		message, err := reader.ReadMessage(ctx)
		require.NoError(t, err, "received %v", ids)
		var event audit.Event
		require.NoError(t, json.Unmarshal(message.Value, &event))
		ids = append(ids, event.ID)
	}
	return ids
}

func emit(ctx context.Context, svc *audit.Service, id string) {
	svc.Emit(ctx, &audit.Event{ID: id, Type: audit.EventConfigChanged, Actor: audit.Actor{User: "operator"}})
}

// An outage longer than both the retry window and the circuit breaker's open
// timeout loses nothing by default: the worker retains the batch, the breaker
// keeps probing half-open and closes again after the broker returns
// (#1538, TCAAS-1614).
func TestOutageLongerThanRetryWindowRetainsEventsAndBreakerRecovers(t *testing.T) {
	if os.Getenv("AUDIT_DELIVERY_E2E") != "true" {
		t.Skip("run hack/audit-delivery-kind.sh")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	cli := kubeClient(t)
	stop := forward(t)
	t.Cleanup(func() { stop() })
	const topic = "audit-retained"
	svc := newKafkaService(ctx, t, cli, topic, &breakglassv1alpha1.AuditQueueConfig{Size: 1000, Workers: 1,
		RetryAttempts: 2, RetryInitialBackoffMillis: 500, RetryMaxBackoffMillis: 2000, RetryTimeoutSeconds: 3})
	emit(ctx, svc, "before-outage")
	require.Eventually(t, func() bool { return svc.GetQueuedSinkHealth()[0].ProcessedEvents == 1 }, time.Minute, time.Second)

	stopBroker(t, stop)
	stop = func() {}
	outage := time.Now()
	for _, id := range []string{"outage-1", "outage-2", "outage-3"} {
		emit(ctx, svc, id)
	}
	require.Eventually(t, func() bool { return svc.GetQueuedSinkHealth()[0].CircuitState == "open" }, time.Minute, time.Second)
	require.Positive(t, testutil.ToFloat64(metrics.AuditEventsRetained.WithLabelValues(topic)))
	// Outlast the retry window (3 s) and the breaker's 30 s open timeout so at
	// least one half-open probe fails while the broker is still down.
	time.Sleep(time.Until(outage.Add(45 * time.Second)))
	require.Zero(t, svc.GetQueuedSinkHealth()[0].DroppedEvents)

	stop = startBroker(t)
	require.ElementsMatch(t, []string{"outage-1", "outage-2", "outage-3"}, readIDs(ctx, t, topic, 3))
	emit(ctx, svc, "after-recovery")
	require.Eventually(t, func() bool {
		health := svc.GetQueuedSinkHealth()[0]
		return health.ProcessedEvents == 5 && health.CircuitState == "closed" && health.Healthy
	}, 2*time.Minute, time.Second)
	health := svc.GetQueuedSinkHealth()[0]
	require.Zero(t, health.DroppedEvents)
	require.Zero(t, testutil.ToFloat64(metrics.AuditEventsRetained.WithLabelValues(topic)))
}

// queue.dropAfterRetryWindow restores the earlier contract: the batch is
// dropped and counted once the retry window is exhausted, and the sink still
// recovers on its own after the broker returns.
func TestDropAfterRetryWindowOptOut(t *testing.T) {
	if os.Getenv("AUDIT_DELIVERY_E2E") != "true" {
		t.Skip("run hack/audit-delivery-kind.sh")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cli := kubeClient(t)
	stop := forward(t)
	t.Cleanup(func() { stop() })
	const topic = "audit-opt-out"
	svc := newKafkaService(ctx, t, cli, topic, &breakglassv1alpha1.AuditQueueConfig{Size: 1000, Workers: 1,
		RetryAttempts: 2, RetryInitialBackoffMillis: 500, RetryMaxBackoffMillis: 2000, RetryTimeoutSeconds: 3,
		DropAfterRetryWindow: ptr.To(true)})
	exhausted := metrics.AuditEventsDropped.WithLabelValues(topic, "retry_exhausted")
	before := testutil.ToFloat64(exhausted)

	stopBroker(t, stop)
	stop = func() {}
	emit(ctx, svc, "dropped")
	require.Eventually(t, func() bool { return svc.GetQueuedSinkHealth()[0].DroppedEvents == 1 }, time.Minute, time.Second)
	require.Equal(t, before+1, testutil.ToFloat64(exhausted))

	stop = startBroker(t)
	// With the short window, events emitted while the restarted broker still
	// creates the topic may be dropped too; keep emitting until one arrives.
	attempt := 0
	require.Eventually(t, func() bool {
		attempt++
		emit(ctx, svc, fmt.Sprintf("after-recovery-%d", attempt))
		return svc.GetQueuedSinkHealth()[0].ProcessedEvents > 0
	}, 2*time.Minute, 5*time.Second)
	ids := readIDs(ctx, t, topic, int(svc.GetQueuedSinkHealth()[0].ProcessedEvents))
	require.NotContains(t, ids, "dropped")
	require.Contains(t, ids[0], "after-recovery-")
}
