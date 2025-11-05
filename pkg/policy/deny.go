package policy

import (
	"context"
	"path/filepath"
	"strings"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// Action represents attributes of an attempted request for deny evaluation.
type Action struct {
	Verb        string
	APIGroup    string
	Resource    string
	Namespace   string
	Name        string
	Subresource string
	ClusterID   string
	Tenant      string
	Session     string
}

type Evaluator struct {
	c   ctrlclient.Client
	log *zap.SugaredLogger
}

func NewEvaluator(c ctrlclient.Client, log *zap.SugaredLogger) *Evaluator {
	return &Evaluator{c: c, log: log}
}

// Match iterates all DenyPolicies (initial naive implementation). Returns (denied, policyName, error).
func (e *Evaluator) Match(ctx context.Context, act Action) (bool, string, error) {
	list := telekomv1alpha1.DenyPolicyList{}
	if err := e.c.List(ctx, &list); err != nil {
		return false, "", err
	}
	for _, pol := range list.Items {
		if !scopeMatches(pol.Spec.AppliesTo, act) {
			continue
		}
		for _, r := range pol.Spec.Rules {
			if ruleMatches(r, act) {
				return true, pol.Name, nil
			}
		}
	}
	return false, "", nil
}

func scopeMatches(s *telekomv1alpha1.DenyPolicyScope, act Action) bool {
	if s == nil {
		return true
	}
	if len(s.Clusters) > 0 && !contains(s.Clusters, act.ClusterID) {
		return false
	}
	if len(s.Tenants) > 0 && !contains(s.Tenants, act.Tenant) {
		return false
	}
	if len(s.Sessions) > 0 && !contains(s.Sessions, act.Session) {
		return false
	}
	return true
}

func ruleMatches(r telekomv1alpha1.DenyRule, act Action) bool {
	if !contains(r.Verbs, act.Verb) {
		return false
	}
	if !contains(r.APIGroups, act.APIGroup) {
		return false
	}
	if !contains(r.Resources, act.Resource) {
		return false
	}
	if len(r.Subresources) > 0 && !contains(r.Subresources, act.Subresource) && !contains(r.Subresources, "*") {
		return false
	}
	if len(r.Namespaces) > 0 && !matchAny(r.Namespaces, act.Namespace) {
		return false
	}
	if len(r.ResourceNames) > 0 && !matchAny(r.ResourceNames, act.Name) {
		return false
	}
	return true
}

func contains(sl []string, v string) bool {
	for _, s := range sl {
		if s == v || s == "*" {
			return true
		}
	}
	return false
}

// matchAny supports shell style * wildcard using filepath.Match
func matchAny(patterns []string, value string) bool {
	for _, p := range patterns {
		if p == "*" {
			return true
		}
		ok, _ := filepath.Match(p, value)
		if ok {
			return true
		}
		if strings.Contains(p, "*") && value == "" {
			continue
		}
	}
	return false
}
