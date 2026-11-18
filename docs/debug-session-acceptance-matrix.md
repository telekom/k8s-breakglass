<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
-->

# DebugSession acceptance matrix

Traceable map from each generic DebugSession safety requirement to the test that
fails when the enforcement is removed. Scope is the generic contract (create,
approve, activate, renew, terminate, expire, target operations); mode-specific
suites (node maintenance, hotfix, traffic mirror, admission recipe) keep their
own tests and are cited here only where they prove a generic rule.

Every test reference is written as file path, two colons, test function name.
`make verify-acceptance-matrix` (run in the CI `lint` job) fails when a
reference points to a file or test function that no longer exists. Rows marked
**new** were added with this matrix; each was mutation-checked (see the last
section). Tests that need `KUBEBUILDER_ASSETS` (envtest) skip without it and run
in the CI unit-test lanes.

## Requester-supplied input

| # | Requirement | Enforcement | Tests |
|---|---|---|---|
| R1 | A requester cannot inject Secrets, volumes, env, image, command/args, hostPath, hostNetwork/PID/IPC, privileged/capabilities, runtimeClass or serviceAccount through the create request; unknown or runtime fields are refused, nothing is persisted | `jsonutil.DecodeStrict` on the create request type, which declares only template, cluster, binding, duration, reason, namespace, scheduling option, node selector, participants and template variables | **new** ``pkg/breakglass/debug/debug_session_acceptance_contract_test.go::TestAcceptanceCreateRejectsRequesterSuppliedRuntimeFields``; ``pkg/breakglass/debug/debug_session_api_test.go::TestDebugSessionAPIController_HandleCreateDebugSession`` (subtest "unknown field") |
| R2 | The same holds for target operations (inject, pod copy, node debug) and node-maintenance/hotfix requests | strict decoding; typed requests only | ``pkg/breakglass/debug/debug_session_api_handlers_test.go::TestDebugKubectlOperationsStrictJSON``; ``pkg/breakglass/debug/debug_session_hotfix_test.go::TestHotfixAPIRejectsGenericOverrides``; ``pkg/breakglass/debug/debug_session_node_maintenance_test.go::TestNodeMaintenanceAPIRejectsRawOverridesBeforeNormalization`` |
| R3 | Injected container security context is bounded by the approved template | pre-intent validation against the resolved template | ``pkg/breakglass/debug/debug_session_api_handlers_test.go::TestHandleInjectEphemeralContainer_RejectsUnsafeSecurityContextBeforeIntent`` |
| R4 | A requester cannot override node placement or add arbitrary resources to the rendered workload | renderer allows only declared overrides | ``pkg/breakglass/debug/pod_template_rendering_test.go::TestBuildPodSpec_RejectsSessionNodeSelectorOverride``; ``pkg/breakglass/debug/pod_template_rendering_test.go::TestBuildPodSpec_RestrictedCatalogueOverridesStayWithinDeclaredBoundary``; ``pkg/breakglass/debug/pod_template_rendering_test.go::TestBuildPodSpec_RestrictedCatalogueRejectsArbitraryAdditionalResources`` |
| R5 | Running debug pods and their pod specs cannot be rewritten by tenants (image, ephemeral containers, grace period) | optional runtime-label-reservation ValidatingAdmissionPolicy | ``pkg/breakglass/debug/runtime_label_reservation_policy_envtest_test.go::TestPlatformRuntimeLabelReservationPolicyEnvtest`` (subtests "debug pod specs are frozen for everyone else", "debug pods may not outlive the session through a long grace period") |

Accepted residual: a template that references `.Vars.<name>` for a variable it
does not declare lets a requester supply that value when no binding restricts
variables (`ValidateExtraDeployValueNames` only rejects unknown names under a
binding with variable constraints). Variables live in their own `.Vars`
namespace, so this cannot override built-in context, and it needs the template
author to reference an undeclared variable.

## Ownership and controller-reserved metadata

| # | Requirement | Enforcement | Tests |
|---|---|---|---|
| O1 | Forged `breakglass.telekom.com/debug-session*` labels and annotations (pods, workload templates, ControllerRevisions, Bindings) are denied for everyone but the controller | runtime-label-reservation ValidatingAdmissionPolicy | ``pkg/breakglass/debug/runtime_label_reservation_policy_envtest_test.go::TestPlatformRuntimeLabelReservationPolicyEnvtest`` (subtests "forged pod labels and annotations are denied", "updates may not add, change or remove reserved keys", "binding annotations are reserved", "workload pod templates are reserved") |
| O2 | The controller never adopts or recovers a resource owned by another session or recreated UID | session UID and operation marker fences | ``pkg/breakglass/debug/auxiliary_policy_exception_test.go::TestAuxiliaryRecoveryRejectsForeignPodTemplateSessionUID``; ``pkg/breakglass/debug/auxiliary_policy_exception_test.go::TestAuxiliaryCreateDoesNotAdoptConcurrentForeignResource`` |
| O3 | Admission-policy version annotation on a session is immutable | `DebugSession.ValidateUpdate` | ``api/v1alpha1/debug_session_types_test.go::TestDebugSessionValidateUpdateProtectsAdmissionPolicyVersion`` |
| O4 | Only the controller may write cleanup acknowledgements | cleanup-acknowledgement ValidatingAdmissionPolicy | ``pkg/breakglass/debug/cleanup_acknowledgement_policy_envtest_test.go::TestPlatformCleanupAcknowledgementActorPolicyEnvtest``; ``pkg/breakglass/debug/cleanup_acknowledgement_test.go::TestStaleWriterCannotRestoreAcknowledgedAuxiliaryDeletion`` |

## Target replacement after approval

| # | Requirement | Enforcement | Tests |
|---|---|---|---|
| T1 | Cluster, template, binding, namespace, node selector, node-maintenance target node/UID, identity and template variables cannot change after creation, in any state | `DebugSession.ValidateUpdate` rejects every spec change | **new** ``api/v1alpha1/debug_session_acceptance_contract_test.go::TestDebugSessionValidateUpdateRejectsTargetReplacement`` |
| T2 | The approved template and binding snapshot are frozen | status immutability checks | ``api/v1alpha1/debug_session_types_test.go::TestDebugSessionValidateUpdateFreezesBindingSnapshotAfterTemplatePersistence`` |
| T3 | A same-name replacement session (new UID) is never written to by a stale operation | UID fence on every status patch | ``pkg/breakglass/debug/debug_session_residual_fence_test.go::TestKubectlDebugStatusPatchRejectsReplacementSession``; ``pkg/breakglass/debug/resource_identity_test.go::TestAllowedPodRefreshRejectsReplacementUnlessWorkloadOwnsIt`` |
| T4 | Changing the target cluster configuration or credentials between approval and write aborts the write | pre-write cluster-config fence | ``pkg/breakglass/debug/debug_session_reconciler_workload_fence_test.go::TestDeployDebugResourcesRejectsClusterConfigRotationBeforeWrite`` |
| T5 | Live target changes (node, UID) fail the final fence of an approved node operation | final fence | ``pkg/breakglass/debug/debug_session_node_maintenance_test.go::TestNodeMaintenanceFinalFenceRejectsLiveChanges`` |

## Stale status after rejection or expiry

| # | Requirement | Enforcement | Tests |
|---|---|---|---|
| S1 | A Rejected, Expired, Terminated, Failed or never-approved session denies renew, join, terminate (where terminal) and every target operation (inject, pod copy, node debug), even when a stale snapshot shows a future `expiresAt`; state, deadline and operation history stay unchanged | state and deadline gate in each handler | **new** ``pkg/breakglass/debug/debug_session_acceptance_contract_test.go::TestAcceptanceInactiveSessionDeniesEveryOperation`` |
| S2 | A rejected or expired session cannot be resurrected to Active or have its deadline extended | `DebugSession.ValidateUpdate` terminal-state rule | ``api/v1alpha1/debug_session_types_test.go::TestDebugSessionValidateUpdateRejectsRejectedResurrection``; ``api/v1alpha1/debug_session_types_test.go::TestDebugSessionValidateUpdateKeepsTerminalStateAndElapsedExpiry`` |
| S3 | The reconciler never activates a rejected session; it only cleans up | reconcile state switch | ``pkg/breakglass/debug/debug_session_reconciler_test.go::TestDebugSessionController_RejectedCleanupAndLegacyRejectedMetadata`` |
| S4 | Expired active session is refused by target operations and by the terminal route | expiry gate | ``pkg/breakglass/debug/debug_session_api_handlers_test.go::TestHandleInjectEphemeralContainer_ActiveSessionExpired``; ``pkg/breakglass/debug/debug_session_api_handlers_test.go::TestHandleCreatePodCopy_ActiveSessionExpired``; ``pkg/breakglass/debug/debug_session_api_handlers_test.go::TestHandleCreateNodeDebugPod_ActiveSessionExpired``; ``pkg/breakglass/debug/terminal_recording_api_test.go::TestTerminalRouteRejectsActiveSessionWithoutExpiry``; ``pkg/breakglass/debug/debug_session_lifecycle_limits_test.go::TestActiveSessionActionsRejectMissingExpiry`` |
| S5 | Live revocation or expiry stops an open terminal and denies new ones | live authority check | ``pkg/breakglass/debug/terminal_recording_authorization_test.go::TestTerminalAuthorityRejectsLiveRevocation``; ``pkg/breakglass/debug/recording_test.go::TestStreamTerminalWithLeaseStopsAtBindingExpiryAndKeepsEvidence`` |
| S6 | Activation stops when the session expired or was deleted mid-deploy | pre-write fence | ``pkg/breakglass/debug/debug_session_reconciler_workload_fence_test.go::TestDeployDebugResourcesRejectsIdleExpiryBeforeWrite`` |

## Hard-expiry deadline boundary

| # | Requirement | Enforcement | Tests |
|---|---|---|---|
| E1 | Usable strictly before `status.expiresAt`; expired at that instant and after (just before / at / after), for the hard deadline and the idle deadline | `isDebugSessionExpired`, `DebugSessionIdleExpired` (all other gates use `!now.Before(expiresAt)`) | **new** ``pkg/breakglass/debug/debug_session_acceptance_contract_test.go::TestAcceptanceExpiryDeadlineBoundary`` |
| E2 | A renewal may land exactly on `startsAt + maxDuration` and not one second later; an elapsed deadline cannot be renewed | max-duration check in the renew handler (checked again on the live re-read) | **new** ``pkg/breakglass/debug/debug_session_acceptance_contract_test.go::TestAcceptanceRenewMaxDurationBoundary`` |

## Concurrent renew, terminate and expire

| # | Requirement | Enforcement | Tests |
|---|---|---|---|
| C1 | Renew, terminate and the reconciler's expiry write racing on one session commit at most one terminal outcome; a renewal never revives a terminal session or moves its deadline | status patch bound to the live resourceVersion plus terminal-state monotonicity | **new** ``pkg/breakglass/debug/debug_session_acceptance_contract_test.go::TestAcceptanceConcurrentRenewTerminateExpire`` (run with `-race`) |
| C2 | Renew re-reads the live session after slow side calls (lease, job) and aborts if it was revoked, deleted or expired meanwhile | live re-read before commit | ``pkg/breakglass/debug/debug_session_lifecycle_limits_test.go::TestRenewRejectsIdleExpiryDuringFinalRead``; ``pkg/breakglass/debug/debug_session_renewal_fence_test.go::TestRenewDebugSessionDeadlineFenceRejectsRevocationDuringJobGet``; ``pkg/breakglass/debug/connection_lease_test.go::TestRenewSessionRechecksLiveSessionAfterLeaseRead`` |
| C3 | A stale reconciler snapshot never expires a session that was renewed meanwhile; activity cannot revive an idle-expired session | live status decision | ``pkg/breakglass/debug/debug_session_reconciler_test.go::TestDebugSessionReconciler_HandleActiveDoesNotExpireRenewedStaleSnapshot``; ``pkg/breakglass/debug/debug_session_lifecycle_limits_test.go::TestActivityCannotReviveSessionAfterLiveReadCrossesIdleDeadline`` |

## Stale token and replay after termination

| # | Requirement | Enforcement | Tests |
|---|---|---|---|
| P1 | Replaying an earlier inject, pod-copy, node-debug, join or renew request after termination is refused and leaves no trace | state gate (see S1, `Terminated` rows) | **new** ``pkg/breakglass/debug/debug_session_acceptance_contract_test.go::TestAcceptanceInactiveSessionDeniesEveryOperation`` |
| P2 | A revoked or missing connection lease denies target mutations | lease validation on every mutation | ``pkg/breakglass/debug/debug_session_api_handlers_test.go::TestKubectlDebugMutationHandlersRejectMissingOrRevokedLease``; ``pkg/breakglass/debug/connection_lease_test.go::TestConnectionLeaseDeletingFinalizerDeniesCapabilityAfterRevoke`` |
| P3 | A stale holder cannot revoke or renew a lease that was taken over or expired | epoch and holder fences | ``pkg/breakglass/debug/connection_lease_test.go::TestConnectionLeaseStaleRevokeCannotDeleteTakeover``; ``pkg/breakglass/debug/connection_lease_test.go::TestConnectionLeaseRenewRejectsExpiredLease`` |
| P4 | A second terminal claim or a stale close cannot disturb the current terminal | exclusive terminal lease | ``pkg/breakglass/debug/terminal_recording_lease_test.go::TestTerminalLeaseExclusiveClaimAndStaleClose`` |
| P5 | An ambiguous earlier ephemeral-container operation is never replayed | operation identity record | ``pkg/breakglass/debug/debug_session_kubectl_test.go::TestKubectlDebugHandler_PrepareEphemeralOperationRejectsRetainedUnknownReplay`` |

## Mutation checks

Each new test was run against a temporary change of the enforcement and failed:

- `jsonutil.DecodeStrict` without `DisallowUnknownFields`: R1 fails.
- `DebugSession.ValidateUpdate` without the spec-immutability check: T1 fails.
- `isDebugSessionExpired` treating the deadline instant as still valid: E1 fails.
- Max-duration comparison loosened or made inclusive: E2 fails.
- Status patch without the resourceVersion fence and terminal-state guard: C1 fails.
