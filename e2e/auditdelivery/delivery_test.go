// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package auditdelivery

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	kube := config.GetConfigOrDie()
	cli, err := client.New(kube, client.Options{Scheme: scheme})
	require.NoError(t, err)
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
			Queue: &breakglassv1alpha1.AuditQueueConfig{Size: 1000, Workers: 1, DropOnFull: false,
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
