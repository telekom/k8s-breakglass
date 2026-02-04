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

package ssa

import (
	"context"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	ac "github.com/telekom/k8s-breakglass/api/v1alpha1/applyconfiguration/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ApplyIdentityProviderStatus applies a status update to an IdentityProvider using native SSA.
func ApplyIdentityProviderStatus(ctx context.Context, c client.Client, idp *telekomv1alpha1.IdentityProvider) error {
	applyConfig := ac.IdentityProvider(idp.Name, idp.Namespace).
		WithStatus(IdentityProviderStatusFrom(&idp.Status))

	return applyStatusViaUnstructured(ctx, c, applyConfig)
}

// ApplyClusterConfigStatus applies a status update to a ClusterConfig using native SSA.
func ApplyClusterConfigStatus(ctx context.Context, c client.Client, cc *telekomv1alpha1.ClusterConfig) error {
	applyConfig := ac.ClusterConfig(cc.Name, cc.Namespace).
		WithStatus(ClusterConfigStatusFrom(&cc.Status))

	return applyStatusViaUnstructured(ctx, c, applyConfig)
}

// ApplyMailProviderStatus applies a status update to a MailProvider using native SSA.
func ApplyMailProviderStatus(ctx context.Context, c client.Client, mp *telekomv1alpha1.MailProvider) error {
	applyConfig := ac.MailProvider(mp.Name, mp.Namespace).
		WithStatus(MailProviderStatusFrom(&mp.Status))

	return applyStatusViaUnstructured(ctx, c, applyConfig)
}

// ApplyAuditConfigStatus applies a status update to an AuditConfig using native SSA.
func ApplyAuditConfigStatus(ctx context.Context, c client.Client, auditCfg *telekomv1alpha1.AuditConfig) error {
	applyConfig := ac.AuditConfig(auditCfg.Name, auditCfg.Namespace).
		WithStatus(AuditConfigStatusFrom(&auditCfg.Status))

	return applyStatusViaUnstructured(ctx, c, applyConfig)
}

// IdentityProviderStatusFrom converts an IdentityProviderStatus to its ApplyConfiguration.
func IdentityProviderStatusFrom(status *telekomv1alpha1.IdentityProviderStatus) *ac.IdentityProviderStatusApplyConfiguration {
	if status == nil {
		return nil
	}

	result := ac.IdentityProviderStatus()

	if status.ObservedGeneration > 0 {
		result.WithObservedGeneration(status.ObservedGeneration)
	}

	for i := range status.Conditions {
		result.WithConditions(ConditionFrom(&status.Conditions[i]))
	}

	return result
}

// ClusterConfigStatusFrom converts a ClusterConfigStatus to its ApplyConfiguration.
func ClusterConfigStatusFrom(status *telekomv1alpha1.ClusterConfigStatus) *ac.ClusterConfigStatusApplyConfiguration {
	if status == nil {
		return nil
	}

	result := ac.ClusterConfigStatus()

	if status.ObservedGeneration > 0 {
		result.WithObservedGeneration(status.ObservedGeneration)
	}

	for i := range status.Conditions {
		result.WithConditions(ConditionFrom(&status.Conditions[i]))
	}

	return result
}

// MailProviderStatusFrom converts a MailProviderStatus to its ApplyConfiguration.
func MailProviderStatusFrom(status *telekomv1alpha1.MailProviderStatus) *ac.MailProviderStatusApplyConfiguration {
	if status == nil {
		return nil
	}

	result := ac.MailProviderStatus()

	if status.ObservedGeneration > 0 {
		result.WithObservedGeneration(status.ObservedGeneration)
	}

	for i := range status.Conditions {
		result.WithConditions(ConditionFrom(&status.Conditions[i]))
	}

	if status.LastHealthCheck != nil {
		result.WithLastHealthCheck(*status.LastHealthCheck)
	}
	if status.LastSendAttempt != nil {
		result.WithLastSendAttempt(*status.LastSendAttempt)
	}
	if status.LastSendError != "" {
		result.WithLastSendError(status.LastSendError)
	}

	return result
}

// AuditConfigStatusFrom converts an AuditConfigStatus to its ApplyConfiguration.
func AuditConfigStatusFrom(status *telekomv1alpha1.AuditConfigStatus) *ac.AuditConfigStatusApplyConfiguration {
	if status == nil {
		return nil
	}

	result := ac.AuditConfigStatus()

	if status.ObservedGeneration > 0 {
		result.WithObservedGeneration(status.ObservedGeneration)
	}

	for i := range status.Conditions {
		result.WithConditions(ConditionFrom(&status.Conditions[i]))
	}

	if len(status.ActiveSinks) > 0 {
		result.WithActiveSinks(status.ActiveSinks...)
	}

	if status.EventsProcessed > 0 {
		result.WithEventsProcessed(status.EventsProcessed)
	}
	if status.EventsDropped > 0 {
		result.WithEventsDropped(status.EventsDropped)
	}
	if status.LastEventTime != nil {
		result.WithLastEventTime(*status.LastEventTime)
	}

	for i := range status.SinkStatuses {
		result.WithSinkStatuses(AuditSinkStatusFrom(&status.SinkStatuses[i]))
	}

	return result
}

// AuditSinkStatusFrom converts an AuditSinkStatus to its ApplyConfiguration.
func AuditSinkStatusFrom(status *telekomv1alpha1.AuditSinkStatus) *ac.AuditSinkStatusApplyConfiguration {
	if status == nil {
		return nil
	}

	result := ac.AuditSinkStatus().
		WithName(status.Name).
		WithReady(status.Ready)

	if status.LastError != "" {
		result.WithLastError(status.LastError)
	}
	if status.LastSuccessTime != nil {
		result.WithLastSuccessTime(*status.LastSuccessTime)
	}
	if status.EventsWritten > 0 {
		result.WithEventsWritten(status.EventsWritten)
	}

	return result
}
