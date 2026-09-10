# Debug session lifecycle security

Debug session status records Kubernetes UIDs from creation/apply responses.
Deletion uses UID preconditions. A same-name replacement is preserved, while
inventory for the original is retired. Auxiliary readiness evaluates the same
UID-checked object snapshot, rather than fetching by name again.

Copied-pod inventory uses the persisted `status.copiedPods[].uid` as its
canonical merge identity, with the historical `copyUID` field as a legacy
fallback. This preserves a same-name replacement recorded concurrently while
cleanup still handles sessions written by older versions.

Tracked cleanup inventory identity also includes the persisted
`createOperationID`. A concurrent same-coordinate resource created by a
different operation therefore remains tracked when cleanup removes its older
predecessor.

An interrupted create with an operation identity but no recorded UID remains a
durable cleanup intent and is retried until its outcome can be resolved. Cleanup
never adopts a same-name replacement from labels, copied markers, or names
alone. Resources explicitly configured with `deleteAfter: false` remain
retained by policy and are excluded from cleanup-failure residuals.

Pod labels are discovery hints. Direct debug Pods require their recorded UID.
DaemonSet and Deployment children require a live, UID-matched controller chain
(including the Deployment's ReplicaSet) and matching immutable workload
configuration. Non-controller owner references and unrelated Pod specifications
cannot manufacture membership. Kubernetes scheduling and default service-account
volume additions are accounted for; other mutating-admission additions must be
represented in the debug template or access fails closed. Restrict metadata and
workload write permissions in debug namespaces; ownership metadata is not a
substitute for namespace RBAC isolation.

Webhook operations read the Pod from the target cluster and require its UID to
match the grant. Ephemeral-container grants therefore stop authorizing when the
original Pod is deleted or replaced. Legacy grants without recorded UIDs fail
closed; terminate and recreate these sessions after upgrading.

## Recovering legacy cleanup inventory

Sessions may lack resource UIDs when an older status schema was used or when a
target create succeeded but the outcome status write was interrupted. Missing
resources are automatically removed from cleanup inventory. Existing resources
are never adopted solely from their names, mutable labels, or copied create
operation markers. An operator must verify ownership and either delete the
original resource manually or record the approved original UID in the session's
`breakglass.t-caas.telekom.com/legacy-cleanup-uids` annotation. The annotation is a
JSON object keyed by `apiVersion/kind/namespace/name`; for example:

```yaml
metadata:
  annotations:
    breakglass.t-caas.telekom.com/legacy-cleanup-uids: '{"v1/Pod/debug/session-copy":"original-pod-uid","apps/v1/DaemonSet/debug/session-workload":"original-workload-uid"}'
```

Only operators authorized to recover that session should update this annotation.
The next cleanup retry uses the approved UID as a deletion precondition. If that
instance has already disappeared, its replacement is left untouched. Malformed
or missing approval retains inventory with an actionable error. Do not copy a
replacement's UID without verifying it is the resource intended for cleanup.
Missing ClusterConfig also retains inventory; restore cluster access and retry
cleanup before deregistering a cluster.

## Scheduling compatibility

`deniedNodes` now accepts exact node names. Unsupported glob patterns are rejected
at template, binding, and scheduling-option validation, and defensively during
rendering for existing objects. Older versions silently omitted these globs from
hard scheduling constraints. Before upgrading, replace glob entries with exact
node names or stable `deniedNodeLabels` selectors; the latter still supports `*`
for any label value. Existing sessions whose persisted constraints contain globs
must be recreated using the corrected configuration. Mandatory restrictions are
never silently ignored.

Deployment records take their UID from the server response to the apply request. The controller uses the supported typed or unstructured Apply API and retains that response directly, avoiding a second name lookup that could observe a replacement.

`TestTrackedApplyRetainsResponseIdentity` covers typed and GVK-bearing unstructured objects, asserting that the original object receives the apply response UID without a fallback GET.

Workload matching tolerates configurable durations for the standard not-ready and unreachable `Exists`/`NoExecute` admission tolerations. Live DaemonSet and Deployment Pods can also contain scheduling defaults absent from their controller templates. The no-class defaults (`priority: 0`, `preemptionPolicy: PreemptLowerPriority`) are recognized directly. For a named class, added values must match a `PriorityClass` read from the target cluster. The class must match the explicitly configured name, or have `globalDefault: true` when the template omits a name. Explicitly configured fields, executable configuration, and the ReplicaSet-to-Deployment template comparison remain strict.

Verifying named-class defaults requires the spoke credential to have `get` access to `scheduling.k8s.io/priorityclasses`. An already matching Pod specification needs no additional lookup. A denied read, missing class, or changed class that no longer explains the Pod's values fails closed; restore the matching class or terminate and recreate affected sessions after a class change. `TestTrackedWorkloadAdmittedPodMembership` exercises both controller paths and rejects modified ReplicaSet templates and container images.

Pod-operation authorization lazily reads one live target Pod snapshot per request and reuses it across recorded references, including failed lookups. Each new request performs a fresh lookup.

New `Prepared` kubectl-debug operations must use the supported
ephemeral-container kind and include complete target Pod identity, container
identity and digests, actor, and preparation timestamp fields. Existing legacy
entries are preserved unchanged for recovery compatibility.

Node-debug creation evaluates exact denied node names, denied label matches,
and required node affinity, including `metadata.name` field requirements, both
before constructing the debug Pod and again after the final live Node read.
Hard pod anti-affinity and `DoNotSchedule` topology-spread constraints are
rejected for node-debug requests because direct `NodeName` binding cannot
evaluate those scheduler-wide constraints; soft `ScheduleAnyway` preferences
remain nonbinding.

Ephemeral-container requests with `allowPrivileged: false` reject explicit
privilege escalation, Windows host processes, non-default proc mounts,
unconfined AppArmor or seccomp profiles, and unsafe SELinux user, role, or type
settings before intent is persisted. `requireNonRoot` also rejects an explicit
root `runAsUser`. Safe fields are forwarded unchanged; `allowPrivileged: true`
preserves the existing template policy for these explicit settings. These
checks cover the listed request fields and do not claim complete Pod Security
Standards Restricted profile conformance.

## Debug session namespace selection

The request `namespace` field is a deprecated alias for `targetNamespace`; it
never selects the hub namespace of the DebugSession object. Omit both fields
to use the template target namespace. Fixed template targets reject a different
requested namespace. E2E fixtures keep hub resource lookup and cleanup namespaces
separate from workload targets, and verify both on the creation response.

Auxiliary readiness errors for legacy resources without recorded UIDs direct
operators to terminate the legacy session and request a new one. Readiness does
not adopt a resource by name or infer its original identity.
