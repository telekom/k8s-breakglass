package breakglass

import (
	"context"
	"time"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ClusterConfigChecker periodically validates that ClusterConfig resources reference
// a secret containing the expected `kubeconfig` key. It logs Info when configs are valid
// and Warn when a secret or the key is missing so operators can remediate.
type ClusterConfigChecker struct {
	Log      *zap.SugaredLogger
	Client   client.Client
	Interval time.Duration
	Recorder record.EventRecorder
}

const ClusterConfigCheckInterval = 10 * time.Minute

func (ccc ClusterConfigChecker) Start(ctx context.Context) {
	// Ensure we always have a logger to avoid nil deref
	lg := ccc.Log
	interval := ccc.Interval
	if interval == 0 {
		interval = ClusterConfigCheckInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			lg.Info("ClusterConfigChecker stopping (context canceled)")
			return
		default:
		}
		ccc.runOnce(ctx, lg)
		select {
		case <-ctx.Done():
			lg.Info("ClusterConfigChecker stopping (context canceled)")
			return
		case <-ticker.C:
		}
	}
}

func (ccc ClusterConfigChecker) runOnce(ctx context.Context, lg *zap.SugaredLogger) {

	lg.Debug("Running ClusterConfig validation check")
	list := telekomv1alpha1.ClusterConfigList{}
	if err := ccc.Client.List(ctx, &list); err != nil {
		lg.With("error", err).Error("Failed to list ClusterConfig resources for validation")
		return
	}
	for _, item := range list.Items {
		// take address of local copy to avoid pointer-to-loop-variable issue
		cc := item
		// metric: one check attempted (label by cluster name)
		metrics.ClusterConfigsChecked.WithLabelValues(cc.Name).Inc()
		// if no kubeconfigSecretRef is set, log a warning
		ref := cc.Spec.KubeconfigSecretRef
		if ref.Name == "" || ref.Namespace == "" {
			lg.Warnw("ClusterConfig has no kubeconfigSecretRef configured",
				"cluster", cc.Name,
				"namespace", cc.Namespace)
			continue
		}
		// fetch secret
		key := client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}
		sec := corev1.Secret{}
		if err := ccc.Client.Get(ctx, key, &sec); err != nil {
			msg := "Referenced kubeconfig secret missing or unreadable"
			lg.Warnw(msg,
				"cluster", cc.Name,
				"secret", ref.Name,
				"secretNamespace", ref.Namespace,
				"error", err)
			// update status and emit event
			if err2 := ccc.setStatusAndEvent(ctx, &cc, "Failed", msg+": "+err.Error(), corev1.EventTypeWarning, lg); err2 != nil {
				lg.Warnw("failed to persist status/event for ClusterConfig", "cluster", cc.Name, "error", err2)
			}
			metrics.ClusterConfigsFailed.WithLabelValues(cc.Name).Inc()
			continue
		}
		// check for kubeconfig key (cluster-api provides key 'value')
		keyName := "value"
		if ref.Key != "" {
			keyName = ref.Key
		}
		if _, ok := sec.Data[keyName]; !ok {
			// If secret exists but missing key, warn with metadata
			msg := "Referenced kubeconfig secret missing key: " + keyName
			lg.Warnw(msg,
				"cluster", cc.Name,
				"secret", ref.Name,
				"secretNamespace", ref.Namespace,
				"secretCreation", sec.CreationTimestamp.Time.Format(time.RFC3339))
			if err2 := ccc.setStatusAndEvent(ctx, &cc, "Failed", msg, corev1.EventTypeWarning, lg); err2 != nil {
				lg.Warnw("failed to persist status/event for ClusterConfig", "cluster", cc.Name, "error", err2)
			}
			metrics.ClusterConfigsFailed.WithLabelValues(cc.Name).Inc()
			continue
		}
		// Good: secret exists and has key
		lg.Debugw("ClusterConfig kubeconfig validated",
			"cluster", cc.Name,
			"secret", ref.Name,
			"secretNamespace", ref.Namespace)

		// Try to parse kubeconfig and attempt a simple discovery to verify reachability
		kubecfgBytes := sec.Data[keyName]
		// Build rest.Config from kubeconfig bytes via overridable function for testing
		restCfg, err := RestConfigFromKubeConfig(kubecfgBytes)
		if err != nil {
			msg := "kubeconfig parse failed: " + err.Error()
			lg.Warnw(msg, "cluster", cc.Name)
			if err2 := ccc.setStatusAndEvent(ctx, &cc, "Failed", msg, corev1.EventTypeWarning, lg); err2 != nil {
				lg.Warnw("failed to persist status/event for ClusterConfig", "cluster", cc.Name, "error", err2)
			}
			metrics.ClusterConfigsFailed.WithLabelValues(cc.Name).Inc()
			continue
		}
		// discovery client to attempt server version call
		if err := CheckClusterReachable(restCfg); err != nil {
			msg := "cluster unreachable: " + err.Error()
			lg.Warnw(msg, "cluster", cc.Name)
			if err2 := ccc.setStatusAndEvent(ctx, &cc, "Failed", msg, corev1.EventTypeWarning, lg); err2 != nil {
				lg.Warnw("failed to persist status/event for ClusterConfig", "cluster", cc.Name, "error", err2)
			}
			metrics.ClusterConfigsFailed.WithLabelValues(cc.Name).Inc()
			continue
		}

		// Success: update status Ready and emit Normal event
		if err2 := ccc.setStatusAndEvent(ctx, &cc, "Ready", "Kubeconfig validated and cluster reachable", corev1.EventTypeNormal, lg); err2 != nil {
			lg.Warnw("failed to persist status/event for ClusterConfig", "cluster", cc.Name, "error", err2)
		}
	}
	lg.Debug("ClusterConfig validation check completed")
}

func (ccc ClusterConfigChecker) setStatusAndEvent(ctx context.Context, cc *telekomv1alpha1.ClusterConfig, phase, message, eventType string, lg *zap.SugaredLogger) error {

	// update status
	now := metav1.Now()
	cc.Status.Phase = phase
	cc.Status.Message = message
	cc.Status.LastCheckTime = now
	// persist status: try full Update first (fake client often requires this), fallback to status update
	if err := ccc.Client.Update(ctx, cc); err != nil {
		lg.Warnw("ClusterConfig full Update failed; attempting Status().Update", "cluster", cc.Name, "error", err)
		if err2 := ccc.Client.Status().Update(ctx, cc); err2 != nil {
			lg.Warnw("failed to update ClusterConfig status via Status().Update", "cluster", cc.Name, "error", err2)
			// return the underlying status update error to caller
			return err2
		}
		lg.Debugw("ClusterConfig status updated via Status().Update", "cluster", cc.Name)
	} else {
		lg.Debugw("ClusterConfig full Update succeeded", "cluster", cc.Name)
	}
	// emit event if recorder present
	if ccc.Recorder != nil {
		if eventType == corev1.EventTypeNormal {
			lg.Debugw("Emitting Normal event for ClusterConfig", "cluster", cc.Name, "message", message)
			ccc.Recorder.Event(cc, eventType, "ClusterConfigValidationSucceeded", message)
		} else {
			lg.Debugw("Emitting Warning event for ClusterConfig", "cluster", cc.Name, "message", message)
			ccc.Recorder.Event(cc, eventType, "ClusterConfigValidationFailed", message)
		}
	} else {
		lg.Warnw("No Event recorder configured; skipping Kubernetes Event emission", "cluster", cc.Name)
	}
	return nil
}

// checkClusterReachable tries to perform a simple discovery (server version) to ensure the cluster is reachable
func checkClusterReachable(cfg *rest.Config) error {
	d, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return err
	}
	_, err = d.ServerVersion()
	return err
}

// overridable function variables for unit testing
var RestConfigFromKubeConfig = clientcmd.RESTConfigFromKubeConfig
var CheckClusterReachable = func(cfg *rest.Config) error { return checkClusterReachable(cfg) }

// Fallback: attempt to build rest.Config via clientcmd
