// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

const (
	// hotfixExpiringWindow raises the Expiring condition before expiresAt.
	hotfixExpiringWindow = 3 * 24 * time.Hour
	// hotfixRecordResync is how often an open record is checked for drift.
	hotfixRecordResync = 5 * time.Minute
)

// HotfixRecordReconciler keeps the drift conditions and metrics of open
// HotfixRecords current: expiry, nodes that lost the hotfix (Reverted) and
// selected nodes without it (Uncovered). It only reports; it never changes
// a node and never rolls back.
type HotfixRecordReconciler struct {
	client              ctrlclient.Client
	ccProvider          *cluster.ClientProvider
	log                 *zap.SugaredLogger
	now                 func() time.Time
	targetClientFactory func(*rest.Config) (ctrlclient.Client, error)
}

// NewHotfixRecordReconciler creates the drift reconciler.
func NewHotfixRecordReconciler(log *zap.SugaredLogger, client ctrlclient.Client, ccProvider *cluster.ClientProvider) *HotfixRecordReconciler {
	return &HotfixRecordReconciler{client: client, ccProvider: ccProvider, log: log, now: time.Now}
}

// SetupWithManager registers the reconciler.
func (r *HotfixRecordReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Status-only updates (including this reconciler's own) do not trigger a
	// reconcile; the periodic requeue re-checks drift.
	return ctrl.NewControllerManagedBy(mgr).For(&breakglassv1alpha1.HotfixRecord{},
		builder.WithPredicates(predicate.GenerationChangedPredicate{})).Named("hotfixrecord").Complete(r)
}

func hotfixRecordLabels(record *breakglassv1alpha1.HotfixRecord) []string {
	return []string{record.Spec.Cluster, string(record.Spec.Payload.Type), record.Namespace + "/" + record.Name}
}

// Reconcile updates conditions and metrics of one record. A steady state
// writes nothing: the status is patched only when a condition or a node
// changed, or when the last observation is older than the resync period.
func (r *HotfixRecordReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	record := &breakglassv1alpha1.HotfixRecord{}
	if err := r.client.Get(ctx, req.NamespacedName, record); err != nil {
		if apierrors.IsNotFound(err) {
			deleteHotfixRecordSeries(req.Namespace + "/" + req.Name)
		}
		return ctrl.Result{}, ctrlclient.IgnoreNotFound(err)
	}
	if meta.IsStatusConditionTrue(record.Status.Conditions, string(breakglassv1alpha1.HotfixRecordConditionClosed)) {
		deleteHotfixRecordSeries(record.Namespace + "/" + record.Name)
		return ctrl.Result{}, nil
	}
	// base keeps the original status for the merge patch; observeNodes
	// filters record.Status.Nodes in place.
	base := record.DeepCopy()
	now := r.now()
	setCondition := func(conditionType breakglassv1alpha1.HotfixRecordConditionType, active bool, reason, trueMessage, falseMessage string) {
		status, message := metav1.ConditionFalse, falseMessage
		if active {
			status, message = metav1.ConditionTrue, trueMessage
		}
		meta.SetStatusCondition(&record.Status.Conditions, metav1.Condition{Type: string(conditionType), Status: status,
			Reason: reason, Message: message, ObservedGeneration: record.Generation})
	}
	expires := record.Spec.ExpiresAt.Time
	expired := !now.Before(expires)
	when := expires.UTC().Format(time.RFC3339)
	setCondition(breakglassv1alpha1.HotfixRecordConditionExpired, expired, "Expiry",
		"expired at "+when+"; reconfirm, roll back or close it", "expires at "+when)
	setCondition(breakglassv1alpha1.HotfixRecordConditionExpiring, !expired && now.Add(hotfixExpiringWindow).After(expires), "Expiry",
		"expires at "+when, "expires at "+when)

	busy, err := r.stageInFlight(ctx, record)
	if err != nil {
		return ctrl.Result{}, err
	}
	if busy {
		// An apply or rollback is changing nodes right now; its own results
		// are authoritative until it ends.
	} else if uncovered, reverted, driftErr := r.observeNodes(ctx, record); driftErr != nil {
		r.log.Warnw("HotfixRecord drift check failed; keeping the last observation", "record", req.NamespacedName, "error", driftErr)
	} else {
		setCondition(breakglassv1alpha1.HotfixRecordConditionUncovered, uncovered > 0, "NodeScan",
			fmt.Sprintf("%d selected nodes do not carry the hotfix", uncovered), "every selected node carries the hotfix or was skipped")
		setCondition(breakglassv1alpha1.HotfixRecordConditionReverted, reverted > 0, "NodeScan",
			fmt.Sprintf("%d nodes lost the hotfix without a rollback session", reverted), "no node lost the hotfix")
	}
	counts := map[breakglassv1alpha1.HotfixNodeState]float64{}
	for _, node := range record.Status.Nodes {
		counts[node.State]++
	}
	labels := hotfixRecordLabels(record)
	metrics.HotfixActive.WithLabelValues(labels...).Set(min(counts[breakglassv1alpha1.HotfixNodeApplied], 1))
	metrics.HotfixExpiresTimestamp.WithLabelValues(labels...).Set(float64(expires.Unix()))
	metrics.HotfixUncoveredNodes.WithLabelValues(labels...).Set(counts[breakglassv1alpha1.HotfixNodeUncovered])
	metrics.HotfixRevertedNodes.WithLabelValues(labels...).Set(counts[breakglassv1alpha1.HotfixNodeReverted])

	changed := !apiequality.Semantic.DeepEqual(base.Status.Conditions, record.Status.Conditions) ||
		!apiequality.Semantic.DeepEqual(base.Status.Nodes, record.Status.Nodes)
	stale := base.Status.ObservedAt == nil || now.Sub(base.Status.ObservedAt.Time) >= hotfixRecordResync
	if changed || stale {
		observed := metav1.NewTime(now)
		record.Status.ObservedAt = &observed
		if err := r.client.Status().Patch(ctx, record, ctrlclient.MergeFromWithOptions(base, ctrlclient.MergeFromWithOptimisticLock{})); err != nil {
			if apierrors.IsConflict(err) {
				return ctrl.Result{RequeueAfter: time.Second}, nil
			}
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{RequeueAfter: hotfixRecordRequeue(now, expires)}, nil
}

// hotfixRecordRequeue is the resync period, shortened to the next expiry boundary.
func hotfixRecordRequeue(now, expires time.Time) time.Duration {
	requeue := hotfixRecordResync
	for _, boundary := range []time.Time{expires.Add(-hotfixExpiringWindow), expires} {
		if wait := boundary.Sub(now); wait > 0 && wait < requeue {
			requeue = wait
		}
	}
	return requeue
}

// deleteHotfixRecordSeries removes every metric series of a record.
func deleteHotfixRecordSeries(record string) {
	for _, vec := range []*prometheus.GaugeVec{metrics.HotfixActive, metrics.HotfixExpiresTimestamp, metrics.HotfixUncoveredNodes, metrics.HotfixRevertedNodes} {
		vec.DeletePartialMatch(prometheus.Labels{"record": record})
	}
}

// stageInFlight reports whether the last apply or rollback session of the
// record is still running.
func (r *HotfixRecordReconciler) stageInFlight(ctx context.Context, record *breakglassv1alpha1.HotfixRecord) (bool, error) {
	for i := len(record.Spec.Sessions) - 1; i >= 0; i-- {
		session := record.Spec.Sessions[i]
		if session.Stage != breakglassv1alpha1.HotfixStageApply && session.Stage != breakglassv1alpha1.HotfixStageRollback &&
			session.Stage != breakglassv1alpha1.HotfixStageClose {
			continue
		}
		ds := &breakglassv1alpha1.DebugSession{}
		if err := r.client.Get(ctx, ctrlclient.ObjectKey{Namespace: record.Namespace, Name: session.Name}, ds); err != nil {
			return false, ctrlclient.IgnoreNotFound(err)
		}
		if string(ds.UID) != session.UID {
			return false, nil
		}
		switch ds.Status.State {
		case breakglassv1alpha1.DebugSessionStateTerminated, breakglassv1alpha1.DebugSessionStateFailed, breakglassv1alpha1.DebugSessionStateExpired:
			// Wait for its cleanup, but not forever if the target stays unreachable.
			unreleased := ds.Status.Hotfix != nil && ds.Status.Hotfix.OperationID != "" && !ds.Status.Hotfix.Released
			return unreleased && r.now().Sub(session.At.Time) < time.Hour, nil
		}
		return true, nil
	}
	return false, nil
}

// observeNodes compares the target cluster with the record:
//   - an applied node of the same UID without the annotation is reverted;
//   - an applied node that was removed from the cluster leaves the record;
//   - a node with a known name but a new UID (replaced) is uncovered;
//   - a selected node the record does not know as applied or skipped is uncovered.
func (r *HotfixRecordReconciler) observeNodes(ctx context.Context, record *breakglassv1alpha1.HotfixRecord) (int, int, error) {
	if r.ccProvider == nil {
		return 0, 0, fmt.Errorf("no target cluster provider")
	}
	cfg, configured, err := r.ccProvider.GetRESTConfigForPrivilegedOperation(ctx, record.Spec.Cluster)
	if err != nil {
		return 0, 0, err
	}
	defer r.ccProvider.ReleasePrivilegedOperationClusterConfig(configured)
	var target ctrlclient.Client
	if r.targetClientFactory != nil {
		target, err = r.targetClientFactory(cfg)
	} else {
		target, err = ctrlclient.New(cfg, ctrlclient.Options{})
	}
	if err != nil {
		return 0, 0, err
	}
	var selected []corev1.Node
	if selection := record.Spec.NodeSelection; len(selection.Names) != 0 {
		for _, name := range selection.Names {
			node := corev1.Node{}
			if err := target.Get(ctx, ctrlclient.ObjectKey{Name: name}, &node); err == nil {
				selected = append(selected, node)
			} else if !apierrors.IsNotFound(err) {
				return 0, 0, err
			}
		}
	} else if selection.Selector != nil {
		selector, err := metav1.LabelSelectorAsSelector(selection.Selector)
		if err != nil {
			return 0, 0, err
		}
		list := &corev1.NodeList{}
		if err := target.List(ctx, list, ctrlclient.MatchingLabelsSelector{Selector: selector}); err != nil {
			return 0, 0, err
		}
		selected = list.Items
	}
	key := hotfixAnnotationKey(record.Name)
	marked := func(node *corev1.Node) bool {
		return strings.HasPrefix(node.Annotations[key], record.Namespace+"/"+record.Name+"@")
	}
	byName := map[string]*corev1.Node{}
	for i := range selected {
		byName[selected[i].Name] = &selected[i]
	}
	now := metav1.NewTime(r.now())
	known := map[string]bool{}
	var kept []breakglassv1alpha1.HotfixRecordNode
	for _, entry := range record.Status.Nodes {
		node := byName[entry.Name]
		switch entry.State {
		case breakglassv1alpha1.HotfixNodeApplied, breakglassv1alpha1.HotfixNodeReverted:
			if node == nil {
				// Not selected any more (relabelled or renamed selection): look it up directly.
				current := &corev1.Node{}
				if err := target.Get(ctx, ctrlclient.ObjectKey{Name: entry.Name}, current); apierrors.IsNotFound(err) {
					continue // removed from the cluster: nothing carries the hotfix
				} else if err != nil {
					return 0, 0, err
				}
				node = current
			}
			if string(node.UID) != entry.UID {
				continue // replaced: the new node is handled as uncovered below
			}
			known[entry.Name] = true
			if marked(node) {
				if entry.State == breakglassv1alpha1.HotfixNodeReverted {
					entry.State, entry.At, entry.Message = breakglassv1alpha1.HotfixNodeApplied, now, ""
				}
			} else if entry.State != breakglassv1alpha1.HotfixNodeReverted {
				entry.State, entry.At, entry.Message = breakglassv1alpha1.HotfixNodeReverted, now, "the hotfix annotation is gone"
			}
		case breakglassv1alpha1.HotfixNodeUncovered:
			if node == nil || marked(node) {
				continue // resolved: no longer selected, or it carries the hotfix now
			}
			known[entry.Name] = true
			entry.UID = string(node.UID)
		default:
			known[entry.Name] = node == nil || string(node.UID) == entry.UID
			if !known[entry.Name] {
				continue // a skipped, failed or rolled back node was replaced
			}
		}
		kept = append(kept, entry)
	}
	for i := range selected {
		node := &selected[i]
		if known[node.Name] || marked(node) {
			continue
		}
		kept = append(kept, breakglassv1alpha1.HotfixRecordNode{Name: node.Name, UID: string(node.UID),
			State: breakglassv1alpha1.HotfixNodeUncovered, At: now, Message: "selected node without the hotfix"})
	}
	record.Status.Nodes = kept
	uncovered, reverted := 0, 0
	for _, entry := range kept {
		switch entry.State {
		case breakglassv1alpha1.HotfixNodeUncovered:
			uncovered++
		case breakglassv1alpha1.HotfixNodeReverted:
			reverted++
		}
	}
	return uncovered, reverted, nil
}
