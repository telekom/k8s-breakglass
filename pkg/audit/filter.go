/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package audit

import (
	"context"
	"path"
	"strings"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/utils"
)

// EventFilterConfig controls which events pass through a sink or manager.
type EventFilterConfig struct {
	// IncludeEventTypes allows only matching event types. Empty means all.
	IncludeEventTypes []string

	// ExcludeEventTypes blocks matching event types and takes precedence.
	ExcludeEventTypes []string

	// MinSeverity blocks events below this severity. Empty disables severity filtering.
	MinSeverity Severity

	// IncludeUsers allows only matching actor users. Empty means all.
	IncludeUsers []string

	// ExcludeUsers blocks matching actor users and takes precedence.
	ExcludeUsers []string

	// IncludeNamespaces allows only matching target namespaces. Empty means all.
	IncludeNamespaces *breakglassv1alpha1.NamespaceFilter

	// ExcludeNamespaces blocks matching target namespaces and takes precedence.
	ExcludeNamespaces *breakglassv1alpha1.NamespaceFilter

	// IncludeResources allows only matching target resource kinds. Empty means all.
	IncludeResources []string

	// ExcludeResources blocks matching target resource kinds and takes precedence.
	ExcludeResources []string

	includeNamespaceMatcher *utils.NamespaceMatcher
	excludeNamespaceMatcher *utils.NamespaceMatcher
}

// NewFilteredSink wraps a sink with the configured audit event filters.
func NewFilteredSink(sink Sink, filter EventFilterConfig) Sink {
	filtered := &filteredSink{
		sink:   sink,
		filter: filter.compile(),
	}
	if batchSink, ok := sink.(BatchSink); ok {
		return &filteredBatchSink{
			filteredSink: filtered,
			batchSink:    batchSink,
		}
	}
	return filtered
}

type filteredSink struct {
	sink   Sink
	filter EventFilterConfig
}

func (s *filteredSink) Write(ctx context.Context, event *Event) error {
	if !s.filter.allows(event) {
		return nil
	}
	return s.sink.Write(ctx, event)
}

func (s *filteredSink) Close() error {
	return s.sink.Close()
}

func (s *filteredSink) Name() string {
	return s.sink.Name()
}

type filteredBatchSink struct {
	*filteredSink
	batchSink BatchSink
}

func (s *filteredBatchSink) WriteBatch(ctx context.Context, events []*Event) error {
	filtered := make([]*Event, 0, len(events))
	for _, event := range events {
		if s.filter.allows(event) {
			filtered = append(filtered, event)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	return s.batchSink.WriteBatch(ctx, filtered)
}

// Allows returns true when an event passes the configured filters.
func (f EventFilterConfig) Allows(event *Event) bool {
	return f.compile().allows(event)
}

func (f EventFilterConfig) compile() EventFilterConfig {
	if f.IncludeNamespaces != nil && !f.IncludeNamespaces.IsEmpty() {
		f.includeNamespaceMatcher = utils.NewNamespaceMatcher(f.IncludeNamespaces)
	}
	if f.ExcludeNamespaces != nil && !f.ExcludeNamespaces.IsEmpty() {
		f.excludeNamespaceMatcher = utils.NewNamespaceMatcher(f.ExcludeNamespaces)
	}
	return f
}

func (f EventFilterConfig) allows(event *Event) bool {
	if event == nil {
		return false
	}
	if !eventTypeAllowed(event.Type, f.IncludeEventTypes, f.ExcludeEventTypes) {
		return false
	}
	if !patternFilterAllowed(event.Actor.User, f.IncludeUsers, f.ExcludeUsers) {
		return false
	}
	if !f.namespaceFilterAllowed(event.Target.Namespace, event.Target.NamespaceLabels) {
		return false
	}
	if !resourceFilterAllowed(event.Target.Kind, f.IncludeResources, f.ExcludeResources) {
		return false
	}
	if f.MinSeverity == "" {
		return true
	}
	return severityRank(eventSeverity(event)) >= severityRank(f.MinSeverity)
}

func eventTypeAllowed(eventType EventType, includePatterns, excludePatterns []string) bool {
	if matchesEventType(excludePatterns, eventType) {
		return false
	}
	if len(includePatterns) == 0 {
		return true
	}
	return matchesEventType(includePatterns, eventType)
}

func matchesEventType(patterns []string, eventType EventType) bool {
	value := string(eventType)
	return matchesPattern(patterns, value)
}

func patternFilterAllowed(value string, includePatterns, excludePatterns []string) bool {
	if matchesPattern(excludePatterns, value) {
		return false
	}
	if len(includePatterns) == 0 {
		return true
	}
	return matchesPattern(includePatterns, value)
}

func resourceFilterAllowed(kind string, includePatterns, excludePatterns []string) bool {
	if len(includePatterns) == 0 && len(excludePatterns) == 0 {
		return true
	}
	candidates := resourceFilterCandidates(kind)
	if matchesAnyPattern(excludePatterns, candidates) {
		return false
	}
	if len(includePatterns) == 0 {
		return true
	}
	return matchesAnyPattern(includePatterns, candidates)
}

func resourceFilterCandidates(kind string) []string {
	if kind == "" {
		return []string{""}
	}
	candidates := make([]string, 0, 6)
	seen := make(map[string]struct{}, 6)
	add := func(value string) {
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		candidates = append(candidates, value)
	}

	lower := strings.ToLower(kind)
	singular := singularResourceName(lower)
	plural := pluralResourceName(singular)

	add(kind)
	add(lower)
	add(singular)
	add(plural)
	add(titleResourceName(singular))
	add(titleResourceName(plural))

	return candidates
}

func singularResourceName(lower string) string {
	switch {
	case strings.HasSuffix(lower, "ies") && len(lower) > len("ies"):
		return strings.TrimSuffix(lower, "ies") + "y"
	case strings.HasSuffix(lower, "sses") && len(lower) > len("es"):
		return strings.TrimSuffix(lower, "es")
	case strings.HasSuffix(lower, "s") && !strings.HasSuffix(lower, "ss") && len(lower) > 1:
		return strings.TrimSuffix(lower, "s")
	default:
		return lower
	}
}

func pluralResourceName(singular string) string {
	switch {
	case strings.HasSuffix(singular, "y") && len(singular) > 1:
		return strings.TrimSuffix(singular, "y") + "ies"
	case strings.HasSuffix(singular, "s"):
		return singular + "es"
	default:
		return singular + "s"
	}
}

func titleResourceName(value string) string {
	if value == "" {
		return ""
	}
	return strings.ToUpper(value[:1]) + value[1:]
}

func matchesAnyPattern(patterns []string, values []string) bool {
	for _, value := range values {
		if matchesPattern(patterns, value) {
			return true
		}
	}
	return false
}

func matchesPattern(patterns []string, value string) bool {
	for _, pattern := range patterns {
		if pattern == value {
			return true
		}
		if matched, err := path.Match(pattern, value); err == nil && matched {
			return true
		}
	}
	return false
}

func (f EventFilterConfig) namespaceFilterAllowed(namespace string, namespaceLabels map[string]string) bool {
	if namespaceFilterMatches(f.excludeNamespaceMatcher, namespace, namespaceLabels) {
		return false
	}
	if f.includeNamespaceMatcher == nil {
		return true
	}
	return namespaceFilterMatches(f.includeNamespaceMatcher, namespace, namespaceLabels)
}

func namespaceFilterMatches(matcher *utils.NamespaceMatcher, namespace string, namespaceLabels map[string]string) bool {
	if matcher == nil {
		return false
	}
	if namespaceLabels != nil {
		return matcher.MatchesWithLabels(namespace, namespaceLabels)
	}
	return matcher.Matches(namespace)
}

func eventSeverity(event *Event) Severity {
	if event.Severity != "" {
		return event.Severity
	}
	return SeverityForEventType(event.Type)
}

func severityRank(severity Severity) int {
	switch severity {
	case SeverityCritical:
		return 2
	case SeverityWarning:
		return 1
	default:
		return 0
	}
}
