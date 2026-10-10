// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"slices"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/clusterconfiglookup"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// SessionRequestContext captures immutable identity from the object an emitter
// observed, including its original controlling escalation after deletion.
func SessionRequestContext(session metav1.Object) *RequestContext {
	rc := &RequestContext{SessionName: session.GetName(), SessionUID: string(session.GetUID())}
	if _, debug := session.(*breakglassv1alpha1.DebugSession); debug {
		rc.DebugSessionName, rc.DebugSessionUID = session.GetName(), string(session.GetUID())
	}
	captureEscalationOwner(session, rc)
	return rc
}

func captureEscalationOwner(session metav1.Object, rc *RequestContext) {
	if owner := metav1.GetControllerOf(session); owner != nil &&
		owner.Kind == "BreakglassEscalation" &&
		schema.FromAPIVersionAndKind(owner.APIVersion, owner.Kind).Group == breakglassv1alpha1.GroupVersion.Group {
		rc.EscalationName, rc.EscalationUID = owner.Name, string(owner.UID)
	}
}

// Capture identity at emission, not delivery: retrying a name must never resolve
// a replacement object's UID. Missing or ambiguous resources stay uncorrelated.
func (s *Service) enrichResourceIdentity(ctx context.Context, event *Event) {
	if s.client == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	rc := event.RequestContext
	if rc == nil {
		rc = &RequestContext{}
	}
	name, debug := rc.SessionName, event.Target.Kind == "DebugSession"
	if rc.DebugSessionName != "" {
		name, debug = rc.DebugSessionName, true
	}
	if name == "" && (event.Target.Kind == "BreakglassSession" || debug) {
		name = event.Target.Name
	}
	// A name lookup cannot prove which object the emitter originally observed.
	// Only validate/enrich identities captured at the object-bearing source.
	if name != "" && rc.SessionUID == "" && rc.DebugSessionUID == "" &&
		(event.Target.UID == "" || (event.Target.Kind != "BreakglassSession" && event.Target.Kind != "DebugSession")) {
		return
	}
	var session client.Object
	if name != "" {
		if debug {
			if event.Target.Namespace != "" {
				obj := &breakglassv1alpha1.DebugSession{}
				if err := s.client.Get(ctx, client.ObjectKey{Namespace: event.Target.Namespace, Name: name}, obj); err == nil {
					session = obj
				}
			} else {
				list := &breakglassv1alpha1.DebugSessionList{}
				if err := s.client.List(ctx, list, client.InNamespace(event.Target.Namespace)); err == nil {
					for i := range list.Items {
						if list.Items[i].Name == name {
							if session != nil {
								return
							}
							session = &list.Items[i]
						}
					}
				}
			}
		} else {
			if event.Target.Namespace != "" {
				obj := &breakglassv1alpha1.BreakglassSession{}
				if err := s.client.Get(ctx, client.ObjectKey{Namespace: event.Target.Namespace, Name: name}, obj); err == nil {
					session = obj
				}
			} else {
				list := &breakglassv1alpha1.BreakglassSessionList{}
				if err := s.client.List(ctx, list, client.InNamespace(event.Target.Namespace)); err == nil {
					for i := range list.Items {
						if list.Items[i].Name == name {
							if session != nil {
								return
							}
							session = &list.Items[i]
						}
					}
				}
			}
		}
	}
	if session != nil {
		uid := string(session.GetUID())
		// Never replace an identity already captured by the emission site.
		if (rc.SessionUID != "" && rc.SessionUID != uid) ||
			(rc.DebugSessionUID != "" && rc.DebugSessionUID != uid) ||
			(event.Target.Name == name && event.Target.UID != "" && event.Target.UID != uid) {
			return
		}
		rc.SessionUID = uid
		if debug {
			rc.DebugSessionName, rc.DebugSessionUID = name, uid
		} else {
			rc.SessionName = name
		}
		if event.Target.Name == name && (event.Target.Kind == "BreakglassSession" || event.Target.Kind == "DebugSession") {
			event.Target.UID = uid
			event.Target.Namespace = session.GetNamespace()
		}
		switch obj := session.(type) {
		case *breakglassv1alpha1.DebugSession:
			if event.Target.Cluster == "" {
				event.Target.Cluster = obj.Spec.Cluster
			}
			if event.Actor.Groups == nil && event.Actor.User == obj.Spec.RequestedBy &&
				obj.Status.AuthenticatedUserGroupsCaptured {
				event.Actor.Groups = slices.Clone(obj.Status.AuthenticatedUserGroups)
			}
		case *breakglassv1alpha1.BreakglassSession:
			if event.Target.Cluster == "" {
				event.Target.Cluster = obj.Spec.Cluster
			}
		}
	}
	if session != nil && rc.EscalationUID == "" {
		captureEscalationOwner(session, rc)
	}
	if event.Target.Cluster != "" && event.Target.ClusterUID == "" && session != nil {
		clusterName := event.Target.Cluster
		if obj, ok := session.(*breakglassv1alpha1.BreakglassSession); ok && obj.Spec.ClusterConfigRef != "" {
			clusterName = obj.Spec.ClusterConfigRef
		}
		clusters := &breakglassv1alpha1.ClusterConfigList{}
		if err := s.client.List(ctx, clusters); err == nil {
			if cluster, lookupErr := clusterconfiglookup.SingleByName(clusters.Items, clusterName); lookupErr == nil && cluster != nil {
				event.Target.ClusterUID = string(cluster.UID)
			}
		}
	}
	if session != nil {
		event.RequestContext = rc
	} else if name != "" {
		s.logger.Debug("audit session identity unavailable", zap.String("session", name))
	}
}
