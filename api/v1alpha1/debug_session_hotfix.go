// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// HotfixPayloadType is one typed kind of persistent node change.
// +kubebuilder:validation:Enum=node-file;node-deb;static-pod-image;host-container-image
type HotfixPayloadType string

const (
	// HotfixPayloadNodeFile replaces or patches one regular file on each node.
	HotfixPayloadNodeFile HotfixPayloadType = "node-file"
	// HotfixPayloadNodeDeb installs one dpkg transaction of pinned .deb files.
	HotfixPayloadNodeDeb HotfixPayloadType = "node-deb"
	// HotfixPayloadStaticPodImage pre-pulls a pinned image and patches one
	// control-plane static Pod manifest, one node at a time.
	HotfixPayloadStaticPodImage HotfixPayloadType = "static-pod-image"
	// HotfixPayloadHostContainerImage swaps the image of a container that runs
	// on the host outside Kubernetes, such as cra-vsr.
	HotfixPayloadHostContainerImage HotfixPayloadType = "host-container-image"
)

// HotfixStage is one four-eyes step of the hotfix lifecycle.
// +kubebuilder:validation:Enum=plan;apply;rollback;reconfirm;close
type HotfixStage string

const (
	// HotfixStagePlan is a read-only dry run on every selected node.
	HotfixStagePlan HotfixStage = "plan"
	// HotfixStageApply executes exactly one succeeded, unexpired plan.
	HotfixStageApply HotfixStage = "apply"
	// HotfixStageRollback reverts the nodes of a HotfixRecord.
	HotfixStageRollback HotfixStage = "rollback"
	// HotfixStageReconfirm extends the expiry of an active HotfixRecord.
	HotfixStageReconfirm HotfixStage = "reconfirm"
	// HotfixStageClose ends drift tracking after the regular release has the fix.
	HotfixStageClose HotfixStage = "close"
)

// HotfixFileMode selects how a node-file payload computes the new content.
// +kubebuilder:validation:Enum=replace;sed;diff
type HotfixFileMode string

const (
	// HotfixFileReplace writes pinned full content.
	HotfixFileReplace HotfixFileMode = "replace"
	// HotfixFileSed applies GNU sed -E substitution commands in sandbox mode.
	HotfixFileSed HotfixFileMode = "sed"
	// HotfixFileDiff applies one single-file unified diff without fuzz.
	HotfixFileDiff HotfixFileMode = "diff"
)

// HotfixRolloutStrategy selects how nodes are grouped into batches.
// +kubebuilder:validation:Enum=canary;all-at-once
type HotfixRolloutStrategy string

const (
	// HotfixRolloutCanary runs canary nodes first, then maxUnavailable batches.
	HotfixRolloutCanary HotfixRolloutStrategy = "canary"
	// HotfixRolloutAllAtOnce runs every worker node in one batch. It needs a reason.
	HotfixRolloutAllAtOnce HotfixRolloutStrategy = "all-at-once"
)

const (
	// HotfixMaxInlineBytes bounds inline file content and diffs. Inline content is
	// recorded in the audit trail, so it must never contain secrets.
	HotfixMaxInlineBytes = 64 * 1024
	// HotfixMaxSessionDuration bounds every hotfix session, including rollouts.
	HotfixMaxSessionDuration = 6 * time.Hour
	// HotfixPlanValidity is how long a succeeded plan can be applied.
	HotfixPlanValidity = 2 * time.Hour
	// HotfixMaxLifetime caps the lifetime of a hotfix before it must be
	// reconfirmed, rolled back or closed.
	HotfixMaxLifetime = 30 * 24 * time.Hour
	// HotfixDefaultLifetime is used when a plan does not request a lifetime.
	HotfixDefaultLifetime = 14 * 24 * time.Hour
	// HotfixMaxPlanBytes bounds the canonical plan so it fits in a DebugSession status.
	HotfixMaxPlanBytes = 512 * 1024
	// HotfixStateDir holds per-hotfix backups and evidence on each node.
	HotfixStateDir = "/var/lib/breakglass-hotfix"
)

// DebugSessionHotfix is the operator-owned profile for platform hotfix
// sessions. Requesters choose a payload within these limits; they cannot
// choose commands, capabilities, mounts or the executor image.
type DebugSessionHotfix struct {
	// suspended rejects new plan and apply sessions and stops further batches
	// of running ones. Rollback, reconfirm and close stay possible so an
	// active hotfix can always be revoked.
	// +optional
	Suspended bool `json:"suspended,omitempty"`
	// executorImage is the node-maintenance image by manifest digest.
	// +kubebuilder:validation:Pattern=`^.+@sha256:[a-f0-9]{64}$`
	ExecutorImage string `json:"executorImage"`
	// payloadTypes are the payload kinds this profile enables.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=4
	// +listType=set
	PayloadTypes []HotfixPayloadType `json:"payloadTypes"`
	// allowedPaths are absolute file paths, or directory prefixes ending in
	// "/", that node-file payloads may change. The hard denylist applies even
	// when an entry covers a denied path.
	// +optional
	// +kubebuilder:validation:MaxItems=64
	// +listType=set
	AllowedPaths []string `json:"allowedPaths,omitempty"`
	// restartableServices are the systemd units a payload may restart.
	// +optional
	// +kubebuilder:validation:MaxItems=5
	// +listType=set
	RestartableServices []HotfixService `json:"restartableServices,omitempty"`
	// staticPods are the control-plane static Pods a static-pod-image payload may patch.
	// +optional
	// +kubebuilder:validation:MaxItems=4
	// +listType=set
	StaticPods []HotfixStaticPod `json:"staticPods,omitempty"`
	// hostContainers are the host containers a host-container-image payload may swap.
	// +optional
	// +kubebuilder:validation:MaxItems=8
	// +listType=map
	// +listMapKey=name
	HostContainers []HotfixHostContainer `json:"hostContainers,omitempty"`
	// allowAllAtOnce permits the all-at-once strategy. It still needs a reason,
	// a plan and health gates.
	// +optional
	AllowAllAtOnce bool `json:"allowAllAtOnce,omitempty"`
	// maxBatchPercent caps the share of selected nodes changed per batch.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100
	MaxBatchPercent int32 `json:"maxBatchPercent,omitempty"`
	// minSoakSeconds is the minimum wait after each batch before the next one.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=3600
	MinSoakSeconds int32 `json:"minSoakSeconds,omitempty"`
	// maxNodes caps the number of nodes one hotfix may select.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=1000
	MaxNodes int32 `json:"maxNodes,omitempty"`
	// nodeDeadlineSeconds bounds each per-node executor Pod.
	// +optional
	// +kubebuilder:validation:Minimum=60
	// +kubebuilder:validation:Maximum=1800
	NodeDeadlineSeconds int32 `json:"nodeDeadlineSeconds,omitempty"`
	// maxLifetime caps the lifetime of a hotfix until reconfirm, rollback or close.
	// +optional
	// +kubebuilder:validation:Pattern="^((([0-9]+([.][0-9]*)?|[.][0-9]+)(ns|us|µs|μs|ms|s|m|h))+|([0-9]+([.][0-9]+)?(ns|us|µs|ms|s|m|h)|[0-9]+(d|w|y))+)$"
	MaxLifetime string `json:"maxLifetime,omitempty"`
}

// HotfixService is a systemd unit that a hotfix may restart.
// systemd-networkd is supported but must be listed explicitly.
// +kubebuilder:validation:Enum=containerd.service;kubelet.service;ssh.service;chrony.service;systemd-networkd.service
type HotfixService string

// HotfixStaticPod is a kubeadm control-plane static Pod.
// +kubebuilder:validation:Enum=kube-apiserver;kube-controller-manager;kube-scheduler;etcd
type HotfixStaticPod string

// HotfixHostContainer describes a container that systemd runs on the host
// with nerdctl, outside Kubernetes. The unit reads the image reference from
// imageRefFile on start (for cra-vsr: cra.service, containerd namespace hbr,
// /etc/cra/image).
type HotfixHostContainer struct {
	// name is the fixed container name.
	// +kubebuilder:validation:MaxLength=63
	Name string `json:"name"`
	// containerdNamespace holds the container's images.
	// +kubebuilder:validation:MaxLength=63
	ContainerdNamespace string `json:"containerdNamespace"`
	// unit is the systemd unit that starts the container.
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9@_.-]{1,240}\.service$`
	Unit string `json:"unit"`
	// imageRefFile is the absolute path of the file that holds the image reference.
	// +kubebuilder:validation:MaxLength=4096
	ImageRefFile string `json:"imageRefFile"`
}

// DebugSessionHotfixRequest is the typed request of one hotfix stage.
type DebugSessionHotfixRequest struct {
	// stage selects the lifecycle step.
	Stage HotfixStage `json:"stage"`
	// payload is the change to plan. Required for plan only.
	// +optional
	Payload *HotfixPayload `json:"payload,omitempty"`
	// nodes selects the nodes to plan. Required for plan only.
	// +optional
	Nodes *HotfixNodeSelection `json:"nodes,omitempty"`
	// rollout selects batches for the later apply. Plan only.
	// +optional
	Rollout *HotfixRollout `json:"rollout,omitempty"`
	// lifetime is the requested time until expiry (plan and reconfirm).
	// +optional
	// +kubebuilder:validation:Pattern="^((([0-9]+([.][0-9]*)?|[.][0-9]+)(ns|us|µs|μs|ms|s|m|h))+|([0-9]+([.][0-9]+)?(ns|us|µs|ms|s|m|h)|[0-9]+(d|w|y))+)$"
	Lifetime string `json:"lifetime,omitempty"`
	// fixedIn names the regular release that will contain the fix. Plan only.
	// +optional
	// +kubebuilder:validation:MaxLength=256
	FixedIn string `json:"fixedIn,omitempty"`
	// planRef is the name of the succeeded plan session. Apply only.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	PlanRef string `json:"planRef,omitempty"`
	// planHash is the hash of the plan that the approvers reviewed. Apply only.
	// +optional
	// +kubebuilder:validation:Pattern=`^[a-f0-9]{64}$`
	PlanHash string `json:"planHash,omitempty"`
	// recordName is the HotfixRecord to roll back, reconfirm or close.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	RecordName string `json:"recordName,omitempty"`
}

// HotfixPayload is exactly one typed change.
type HotfixPayload struct {
	// type selects the payload kind.
	Type HotfixPayloadType `json:"type"`
	// file is the node-file payload.
	// +optional
	File *HotfixFilePayload `json:"file,omitempty"`
	// debs are installed in one dpkg transaction (node-deb).
	// +optional
	// +kubebuilder:validation:MaxItems=16
	// +listType=atomic
	Debs []HotfixDeb `json:"debs,omitempty"`
	// rollbackDebs reinstall the previous versions on rollback (node-deb).
	// Packages that the hotfix newly installed are purged on rollback.
	// +optional
	// +kubebuilder:validation:MaxItems=16
	// +listType=atomic
	RollbackDebs []HotfixDeb `json:"rollbackDebs,omitempty"`
	// image is the static-pod-image or host-container-image payload.
	// +optional
	Image *HotfixImagePayload `json:"image,omitempty"`
	// restart lists units to restart after a node-file or node-deb change.
	// Each must be in the profile's restartableServices.
	// +optional
	// +kubebuilder:validation:MaxItems=5
	// +listType=set
	Restart []HotfixService `json:"restart,omitempty"`
}

// HotfixFilePayload changes one regular file.
type HotfixFilePayload struct {
	// path is the absolute, clean path of an existing regular file.
	// +kubebuilder:validation:MaxLength=4096
	Path string `json:"path"`
	// mode selects full replacement, sed substitution or a unified diff.
	Mode HotfixFileMode `json:"mode"`
	// beforeSHA256 lists accepted current file hashes. Required for replace;
	// optional for sed and diff, where the plan records each node's hash.
	// +optional
	// +kubebuilder:validation:MaxItems=16
	// +listType=set
	BeforeSHA256 []string `json:"beforeSHA256,omitempty"`
	// afterSHA256 is the hash of the new content. Required for replace.
	// +optional
	// +kubebuilder:validation:Pattern=`^[a-f0-9]{64}$`
	AfterSHA256 string `json:"afterSHA256,omitempty"`
	// content is inline new content for replace. It is recorded in the audit
	// trail and must not contain secrets. Exclusive with url.
	// +optional
	// +kubebuilder:validation:MaxLength=65536
	Content string `json:"content,omitempty"`
	// url is an HTTPS source of the new content for replace, checked against afterSHA256.
	// +optional
	// +kubebuilder:validation:MaxLength=2048
	URL string `json:"url,omitempty"`
	// sedExpressions are GNU sed -E substitution commands (s/re/repl/flags)
	// applied in sandbox mode.
	// +optional
	// +kubebuilder:validation:MaxItems=16
	// +listType=atomic
	SedExpressions []string `json:"sedExpressions,omitempty"`
	// diff is a unified diff of exactly this one file, applied without fuzz.
	// +optional
	// +kubebuilder:validation:MaxLength=65536
	Diff string `json:"diff,omitempty"`
}

// HotfixDeb is one pinned Debian package file.
type HotfixDeb struct {
	// url is the HTTPS source of the .deb file.
	// +kubebuilder:validation:MaxLength=2048
	URL string `json:"url"`
	// sha256 is the lowercase hash of the .deb file.
	// +kubebuilder:validation:Pattern=`^[a-f0-9]{64}$`
	SHA256 string `json:"sha256"`
	// package is the Debian package name in the control file.
	// +kubebuilder:validation:Pattern=`^[a-z0-9][a-z0-9+.-]{1,62}$`
	Package string `json:"package"`
	// version is the exact Debian version in the control file.
	// +kubebuilder:validation:Pattern=`^[0-9A-Za-z.+~:-]{1,128}$`
	Version string `json:"version"`
}

// HotfixImagePayload names one image swap. Exactly one of staticPod or hostContainer is set.
type HotfixImagePayload struct {
	// staticPod is the control-plane static Pod whose container image is replaced.
	// +optional
	StaticPod HotfixStaticPod `json:"staticPod,omitempty"`
	// hostContainer is the name of a profile host container.
	// +optional
	// +kubebuilder:validation:MaxLength=63
	HostContainer string `json:"hostContainer,omitempty"`
	// image is the new image by manifest digest, without a tag.
	// +kubebuilder:validation:MaxLength=512
	Image string `json:"image"`
}

// HotfixNodeSelection selects nodes by exact names or by a label selector.
// The plan resolves the selection to exact Node name and UID pairs.
type HotfixNodeSelection struct {
	// names are exact Node names.
	// +optional
	// +kubebuilder:validation:MaxItems=1000
	// +listType=set
	Names []string `json:"names,omitempty"`
	// selector selects Nodes by labels.
	// +optional
	Selector *metav1.LabelSelector `json:"selector,omitempty"`
}

// HotfixRollout configures batches for the apply stage.
type HotfixRollout struct {
	// strategy defaults to canary.
	// +optional
	Strategy HotfixRolloutStrategy `json:"strategy,omitempty"`
	// canaryNodes is the size of the first batch (default 1).
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=10
	CanaryNodes int32 `json:"canaryNodes,omitempty"`
	// maxUnavailable is the batch size after the canary, as a count or a
	// percentage of selected nodes (default 10%).
	// +optional
	MaxUnavailable *intstr.IntOrString `json:"maxUnavailable,omitempty"`
	// soakSeconds is the wait after each batch (at least the profile minimum).
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=3600
	SoakSeconds int32 `json:"soakSeconds,omitempty"`
	// allAtOnceReason is mandatory for the all-at-once strategy.
	// +optional
	// +kubebuilder:validation:MaxLength=700
	AllAtOnceReason string `json:"allAtOnceReason,omitempty"`
}

// HotfixPlan is the reviewed result of a plan session. Its hash binds the apply stage.
type HotfixPlan struct {
	// payload is the planned change.
	Payload HotfixPayload `json:"payload"`
	// rollout is the effective rollout with defaults applied.
	Rollout HotfixRollout `json:"rollout"`
	// lifetime is the effective lifetime.
	// +optional
	Lifetime string `json:"lifetime,omitempty"`
	// fixedIn names the regular release that will contain the fix.
	// +optional
	FixedIn string `json:"fixedIn,omitempty"`
	// diffs are the distinct reviewed changes, one per pre-image hash.
	// +optional
	// +kubebuilder:validation:MaxItems=16
	// +listType=atomic
	Diffs []HotfixPlannedDiff `json:"diffs,omitempty"`
	// nodes are the planned nodes in batch order. A plan in progress has none yet.
	// +optional
	// +kubebuilder:validation:MaxItems=1000
	// +listType=atomic
	Nodes []HotfixPlannedNode `json:"nodes,omitempty"`
}

// HotfixPlannedDiff is one reviewed change shared by all nodes with the same pre-image.
type HotfixPlannedDiff struct {
	// beforeSHA256 is the pre-image hash.
	BeforeSHA256 string `json:"beforeSHA256"`
	// afterSHA256 is the planned result hash.
	AfterSHA256 string `json:"afterSHA256"`
	// diff is the unified diff for review, truncated to about 2.5 KiB.
	// +kubebuilder:validation:MaxLength=4096
	Diff string `json:"diff"`
}

// HotfixPlannedAction is the planned action on one node.
// +kubebuilder:validation:Enum=apply;skip
type HotfixPlannedAction string

const (
	// HotfixPlannedApply changes the node.
	HotfixPlannedApply HotfixPlannedAction = "apply"
	// HotfixPlannedSkip leaves a node that already has the result.
	HotfixPlannedSkip HotfixPlannedAction = "skip"
)

// HotfixPlannedNode is the planned action on one Node incarnation.
type HotfixPlannedNode struct {
	// name is the Node name.
	Name string `json:"name"`
	// uid is the Node UID.
	UID string `json:"uid"`
	// controlPlane marks nodes that run in their own batch with control-plane gates.
	// +optional
	ControlPlane bool `json:"controlPlane,omitempty"`
	// batch is the zero-based batch index.
	Batch int32 `json:"batch"`
	// action is apply, or skip when the node already has the target state.
	Action HotfixPlannedAction `json:"action"`
	// beforeSHA256 is the observed pre-image hash (file, manifest or image reference).
	// +optional
	BeforeSHA256 string `json:"beforeSHA256,omitempty"`
	// afterSHA256 is the planned result hash.
	// +optional
	AfterSHA256 string `json:"afterSHA256,omitempty"`
	// newPackages lists the Debian packages that are new on this node (node-deb),
	// so rollback can purge them.
	// +optional
	// +listType=atomic
	NewPackages []string `json:"newPackages,omitempty"`
}

// HotfixStatus records the plan and execution of a hotfix session.
type HotfixStatus struct {
	// plan is set by a succeeded plan session.
	// +optional
	Plan *HotfixPlan `json:"plan,omitempty"`
	// planHash is the hash of plan.
	// +optional
	PlanHash string `json:"planHash,omitempty"`
	// plannedAt is when the plan succeeded.
	// +optional
	PlannedAt *metav1.Time `json:"plannedAt,omitempty"`
	// appliedBy is the apply session that consumed this plan. A plan is applied at most once.
	// +optional
	AppliedBy string `json:"appliedBy,omitempty"`
}

var (
	hotfixSHA256Pattern     = regexp.MustCompile(`^[a-f0-9]{64}$`)
	hotfixPackagePattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{1,62}$`)
	hotfixVersionPattern    = regexp.MustCompile(`^[0-9A-Za-z.+~:-]{1,128}$`)
	hotfixImagePattern      = regexp.MustCompile(`^((localhost|[a-z0-9-]+(\.[a-z0-9-]+)+)(:[0-9]{1,5})?|[a-z0-9-]+:[0-9]{1,5})(/[a-z0-9]([a-z0-9._-]*[a-z0-9])?)+@sha256:[a-f0-9]{64}$`)
	hotfixPathPattern       = regexp.MustCompile(`^/[A-Za-z0-9._@+/-]*$`)
	hotfixUnitPattern       = regexp.MustCompile(`^[a-zA-Z0-9@_.-]{1,240}\.service$`)
	hotfixSedFlagsPattern   = regexp.MustCompile(`^[gI0-9]*$`)
	hotfixDiffHunkPattern   = regexp.MustCompile(`^@@ -[0-9]+(?:,([0-9]+))? \+[0-9]+(?:,([0-9]+))? @@`)
	hotfixDefaultMaxUnavail = intstr.FromString("10%")
)

var (
	hotfixServices   = []HotfixService{"containerd.service", "kubelet.service", "ssh.service", "chrony.service", "systemd-networkd.service"}
	hotfixStaticPods = []HotfixStaticPod{"kube-apiserver", "kube-controller-manager", "kube-scheduler", "etcd"}
)

// hotfixDeniedPrefixes are never writable by a hotfix, whatever the profile
// allows: credentials, kubeconfigs, account databases, SSH keys and the
// hotfix's own backup state.
var hotfixDeniedPrefixes = []string{
	"/etc/kubernetes/pki/", "/var/lib/kubelet/pki/", "/etc/shadow", "/etc/gshadow",
	"/etc/sudoers", "/root/", "/proc/", "/sys/", "/dev/", "/run/secrets/",
	HotfixStateDir + "/", "/var/lib/kyverno/", "/var/lib/breakglass", "/etc/breakglass",
}

// HotfixPathDenied reports whether a clean absolute path is on the hard denylist.
func HotfixPathDenied(p string) bool {
	for _, prefix := range hotfixDeniedPrefixes {
		if strings.HasPrefix(p, prefix) || p+"/" == prefix {
			return true
		}
	}
	base := path.Base(p)
	// Kubeconfigs in /etc/kubernetes (admin.conf, kubelet.conf, ...) and the kubelet's kubeconfig.
	if (path.Dir(p) == "/etc/kubernetes" && strings.HasSuffix(base, ".conf")) || p == "/var/lib/kubelet/kubeconfig" {
		return true
	}
	// SSH host keys and any user's SSH directory.
	if (path.Dir(p) == "/etc/ssh" && strings.Contains(base, "_key")) || strings.Contains(p, "/.ssh/") {
		return true
	}
	return false
}

func validateHotfixPath(p string) error {
	if len(p) < 2 || len(p) > 4096 || !hotfixPathPattern.MatchString(p) || path.Clean(p) != p {
		return fmt.Errorf("path %q must be absolute, clean and use only [A-Za-z0-9._@+/-]", p)
	}
	if HotfixPathDenied(p) {
		return fmt.Errorf("path %q is on the hotfix denylist", p)
	}
	return nil
}

// hotfixPathAllowed matches exact entries and directory prefixes ending in "/".
func hotfixPathAllowed(allowed []string, p string) bool {
	for _, entry := range allowed {
		if entry == p || (strings.HasSuffix(entry, "/") && strings.HasPrefix(p, entry)) {
			return true
		}
	}
	return false
}

func validateHotfixImage(image string) error {
	if len(image) > 512 || !hotfixImagePattern.MatchString(image) {
		return fmt.Errorf("image %q must be registry-host/repository@sha256:<64 hex> without a tag", image)
	}
	return nil
}

// validateHotfixURL accepts HTTPS URLs without credentials, so audit records
// never contain secrets.
func validateHotfixURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.Fragment != "" || parsed.RawQuery != "" || parsed.ForceQuery || strings.ContainsAny(raw, " \t\r\n") {
		return fmt.Errorf("url %q must be an https URL without credentials, query or fragment", raw)
	}
	return nil
}

// validateHotfixSed accepts only s commands with the flags g, I and a number.
// The executor also runs sed in sandbox mode, which rejects e, r and w.
func validateHotfixSed(expression string) error {
	if len(expression) < 4 || len(expression) > 1024 || expression[0] != 's' || strings.ContainsAny(expression, "\n\r\x00") {
		return fmt.Errorf("sed expression %q must be a single-line s command", expression)
	}
	delimiter := expression[1]
	if delimiter == '\\' || delimiter == ' ' || (delimiter >= 'a' && delimiter <= 'z') ||
		(delimiter >= 'A' && delimiter <= 'Z') || (delimiter >= '0' && delimiter <= '9') {
		return fmt.Errorf("sed expression %q has an invalid delimiter", expression)
	}
	parts, escaped, current := 0, false, 2
	for i := 2; i < len(expression) && parts < 2; i++ {
		switch {
		case escaped:
			escaped = false
		case expression[i] == '\\':
			escaped = true
		case expression[i] == delimiter:
			parts++
			current = i + 1
		}
	}
	if parts != 2 || escaped || !hotfixSedFlagsPattern.MatchString(expression[current:]) {
		return fmt.Errorf("sed expression %q must be s<d>regex<d>replacement<d>[gI0-9]", expression)
	}
	return nil
}

// validateHotfixDiff accepts exactly one file header pair followed by hunks.
func validateHotfixDiff(diff string) error {
	if len(diff) == 0 || len(diff) > HotfixMaxInlineBytes || strings.Contains(diff, "\x00") {
		return fmt.Errorf("diff must be 1..%d bytes", HotfixMaxInlineBytes)
	}
	lines := strings.Split(strings.TrimSuffix(diff, "\n"), "\n")
	if len(lines) < 4 || !strings.HasPrefix(lines[0], "--- ") || !strings.HasPrefix(lines[1], "+++ ") {
		return fmt.Errorf("diff must start with one ---/+++ header pair")
	}
	hunks, oldLeft, newLeft := 0, 0, 0
	for _, line := range lines[2:] {
		// Inside a hunk, its header counts decide what is content, so a
		// removed line that reads "--- x" is still content.
		if oldLeft > 0 || newLeft > 0 {
			if line == "" {
				return fmt.Errorf("diff has an empty line inside a hunk; context lines start with a space")
			}
			switch line[0] {
			case ' ':
				oldLeft--
				newLeft--
			case '-':
				oldLeft--
			case '+':
				newLeft--
			default:
				return fmt.Errorf("unexpected diff line %q", line)
			}
			if oldLeft < 0 || newLeft < 0 {
				return fmt.Errorf("hunk line counts do not match its header")
			}
			continue
		}
		match := hotfixDiffHunkPattern.FindStringSubmatch(line)
		if match == nil {
			return fmt.Errorf("diff must contain only hunks of one file; unexpected line %q", line)
		}
		oldLeft, newLeft = 1, 1
		if match[1] != "" {
			oldLeft, _ = strconv.Atoi(match[1])
		}
		if match[2] != "" {
			newLeft, _ = strconv.Atoi(match[2])
		}
		if oldLeft == 0 && newLeft == 0 {
			return fmt.Errorf("diff has an empty hunk")
		}
		hunks++
	}
	if hunks == 0 || oldLeft != 0 || newLeft != 0 {
		return fmt.Errorf("diff has no hunks or a truncated hunk")
	}
	return nil
}

func validateHotfixDeb(deb *HotfixDeb) error {
	if err := validateHotfixURL(deb.URL); err != nil {
		return err
	}
	if !hotfixSHA256Pattern.MatchString(deb.SHA256) || !hotfixPackagePattern.MatchString(deb.Package) ||
		!hotfixVersionPattern.MatchString(deb.Version) {
		return fmt.Errorf("deb %q needs a lowercase sha256, an exact package name and version", deb.URL)
	}
	return nil
}

func hotfixMaxLifetime(profile *DebugSessionHotfix) (time.Duration, error) {
	if profile.MaxLifetime == "" {
		return HotfixMaxLifetime, nil
	}
	lifetime, err := ParseDuration(profile.MaxLifetime)
	if err != nil || lifetime <= 0 || lifetime > HotfixMaxLifetime {
		return 0, fmt.Errorf("hotfix maxLifetime %q must be positive and at most %s", profile.MaxLifetime, HotfixMaxLifetime)
	}
	return lifetime, nil
}

// HotfixLifetime returns the effective lifetime of a plan or reconfirm request.
func HotfixLifetime(profile *DebugSessionHotfix, requested string) (time.Duration, error) {
	maxLifetime, err := hotfixMaxLifetime(profile)
	if err != nil {
		return 0, err
	}
	if requested == "" {
		return min(HotfixDefaultLifetime, maxLifetime), nil
	}
	lifetime, err := ParseDuration(requested)
	if err != nil || lifetime <= 0 || lifetime > maxLifetime {
		return 0, fmt.Errorf("hotfix lifetime %q must be positive and at most %s", requested, maxLifetime)
	}
	return lifetime, nil
}

// ValidateHotfixProfile checks the operator profile itself.
func ValidateHotfixProfile(profile *DebugSessionHotfix) error {
	if profile == nil {
		return nil
	}
	if !maintenanceImagePattern.MatchString(profile.ExecutorImage) || strings.ContainsAny(profile.ExecutorImage, " \t\r\n") {
		return fmt.Errorf("hotfix executorImage must be pinned by digest")
	}
	if len(profile.PayloadTypes) == 0 {
		return fmt.Errorf("hotfix requires at least one payload type")
	}
	for _, payloadType := range profile.PayloadTypes {
		switch payloadType {
		case HotfixPayloadNodeFile:
			if len(profile.AllowedPaths) == 0 {
				return fmt.Errorf("hotfix node-file requires allowedPaths")
			}
		case HotfixPayloadNodeDeb:
		case HotfixPayloadStaticPodImage:
			if len(profile.StaticPods) == 0 {
				return fmt.Errorf("hotfix static-pod-image requires staticPods")
			}
		case HotfixPayloadHostContainerImage:
			if len(profile.HostContainers) == 0 {
				return fmt.Errorf("hotfix host-container-image requires hostContainers")
			}
		default:
			return fmt.Errorf("unsupported hotfix payload type %q", payloadType)
		}
	}
	for _, entry := range profile.AllowedPaths {
		if entry == "/" {
			return fmt.Errorf("hotfix allowedPaths must not allow the whole filesystem")
		}
		if err := validateHotfixPath(strings.TrimSuffix(entry, "/")); err != nil {
			return fmt.Errorf("invalid hotfix allowedPaths entry: %w", err)
		}
	}
	for _, service := range profile.RestartableServices {
		if !slices.Contains(hotfixServices, service) {
			return fmt.Errorf("unsupported restartable service %q", service)
		}
	}
	for _, pod := range profile.StaticPods {
		if !slices.Contains(hotfixStaticPods, pod) {
			return fmt.Errorf("unsupported static Pod %q", pod)
		}
	}
	for _, container := range profile.HostContainers {
		if len(validation.IsDNS1123Label(container.Name)) != 0 || len(validation.IsDNS1123Subdomain(container.ContainerdNamespace)) != 0 ||
			container.ContainerdNamespace == "k8s.io" || container.ContainerdNamespace == "moby" || !hotfixUnitPattern.MatchString(container.Unit) {
			return fmt.Errorf("hotfix host container %q needs a DNS label name, a non-Kubernetes containerd namespace and a .service unit", container.Name)
		}
		if err := validateHotfixPath(container.ImageRefFile); err != nil {
			return fmt.Errorf("hotfix host container %q: %w", container.Name, err)
		}
	}
	if _, err := hotfixMaxLifetime(profile); err != nil {
		return err
	}
	return nil
}

// ValidateHotfixPayload checks a payload against the profile.
func ValidateHotfixPayload(profile *DebugSessionHotfix, payload *HotfixPayload) error {
	if payload == nil {
		return fmt.Errorf("hotfix payload is required")
	}
	if !slices.Contains(profile.PayloadTypes, payload.Type) {
		return fmt.Errorf("hotfix payload type %q is not enabled by the template", payload.Type)
	}
	for _, service := range payload.Restart {
		if !slices.Contains(profile.RestartableServices, service) {
			return fmt.Errorf("service %q is not restartable in this template", service)
		}
	}
	hasFile, hasDebs, hasImage := payload.File != nil, len(payload.Debs)+len(payload.RollbackDebs) > 0, payload.Image != nil
	switch payload.Type {
	case HotfixPayloadNodeFile:
		if !hasFile || hasDebs || hasImage {
			return fmt.Errorf("node-file payload needs file only")
		}
		return validateHotfixFile(profile, payload.File)
	case HotfixPayloadNodeDeb:
		if hasFile || hasImage || len(payload.Debs) == 0 {
			return fmt.Errorf("node-deb payload needs debs only")
		}
		seen := map[string]bool{}
		for i := range payload.Debs {
			if err := validateHotfixDeb(&payload.Debs[i]); err != nil {
				return err
			}
			if seen[payload.Debs[i].Package] {
				return fmt.Errorf("deb package %q is listed twice", payload.Debs[i].Package)
			}
			seen[payload.Debs[i].Package] = true
		}
		for i := range payload.RollbackDebs {
			if err := validateHotfixDeb(&payload.RollbackDebs[i]); err != nil {
				return fmt.Errorf("rollbackDebs: %w", err)
			}
			if !seen[payload.RollbackDebs[i].Package] {
				return fmt.Errorf("rollback deb %q is not part of the hotfix", payload.RollbackDebs[i].Package)
			}
		}
		return nil
	case HotfixPayloadStaticPodImage, HotfixPayloadHostContainerImage:
		if hasFile || hasDebs || !hasImage || len(payload.Restart) != 0 {
			return fmt.Errorf("%s payload needs image only and restarts its own target", payload.Type)
		}
		if err := validateHotfixImage(payload.Image.Image); err != nil {
			return err
		}
		if payload.Type == HotfixPayloadStaticPodImage {
			if payload.Image.HostContainer != "" || !slices.Contains(profile.StaticPods, payload.Image.StaticPod) {
				return fmt.Errorf("static Pod %q is not enabled by the template", payload.Image.StaticPod)
			}
			return nil
		}
		if payload.Image.StaticPod != "" || !slices.ContainsFunc(profile.HostContainers, func(c HotfixHostContainer) bool { return c.Name == payload.Image.HostContainer }) {
			return fmt.Errorf("host container %q is not enabled by the template", payload.Image.HostContainer)
		}
		return nil
	}
	return fmt.Errorf("unsupported hotfix payload type %q", payload.Type)
}

func validateHotfixFile(profile *DebugSessionHotfix, file *HotfixFilePayload) error {
	if err := validateHotfixPath(file.Path); err != nil {
		return err
	}
	if !hotfixPathAllowed(profile.AllowedPaths, file.Path) {
		return fmt.Errorf("path %q is not in the template allowedPaths", file.Path)
	}
	if len(file.BeforeSHA256) > 16 {
		return fmt.Errorf("at most 16 beforeSHA256 values")
	}
	for _, sum := range file.BeforeSHA256 {
		if !hotfixSHA256Pattern.MatchString(sum) {
			return fmt.Errorf("beforeSHA256 %q must be 64 lowercase hex characters", sum)
		}
	}
	switch file.Mode {
	case HotfixFileReplace:
		if (file.Content == "") == (file.URL == "") || len(file.SedExpressions) != 0 || file.Diff != "" {
			return fmt.Errorf("replace needs exactly one of content or url")
		}
		if len(file.Content) > HotfixMaxInlineBytes {
			return fmt.Errorf("inline content exceeds %d bytes", HotfixMaxInlineBytes)
		}
		if file.URL != "" {
			if err := validateHotfixURL(file.URL); err != nil {
				return err
			}
		}
		if len(file.BeforeSHA256) == 0 || !hotfixSHA256Pattern.MatchString(file.AfterSHA256) {
			return fmt.Errorf("replace needs beforeSHA256 and afterSHA256")
		}
		if file.Content != "" {
			sum := sha256.Sum256([]byte(file.Content))
			if hex.EncodeToString(sum[:]) != file.AfterSHA256 {
				return fmt.Errorf("afterSHA256 does not match the inline content")
			}
		}
		if slices.Contains(file.BeforeSHA256, file.AfterSHA256) {
			return fmt.Errorf("afterSHA256 must differ from every beforeSHA256")
		}
	case HotfixFileSed:
		if len(file.SedExpressions) == 0 || len(file.SedExpressions) > 16 || file.Content != "" || file.URL != "" ||
			file.Diff != "" || file.AfterSHA256 != "" {
			return fmt.Errorf("sed needs 1..16 sedExpressions only; the plan computes the result hash")
		}
		for _, expression := range file.SedExpressions {
			if err := validateHotfixSed(expression); err != nil {
				return err
			}
		}
	case HotfixFileDiff:
		if file.Diff == "" || file.Content != "" || file.URL != "" || len(file.SedExpressions) != 0 || file.AfterSHA256 != "" {
			return fmt.Errorf("diff needs a diff only; the plan computes the result hash")
		}
		return validateHotfixDiff(file.Diff)
	default:
		return fmt.Errorf("unsupported file mode %q", file.Mode)
	}
	return nil
}

// ValidateHotfixRollout checks a rollout against the profile and payload.
func ValidateHotfixRollout(profile *DebugSessionHotfix, payload *HotfixPayload, rollout *HotfixRollout) error {
	if rollout == nil {
		return nil
	}
	switch rollout.Strategy {
	case "", HotfixRolloutCanary:
		if rollout.AllAtOnceReason != "" {
			return fmt.Errorf("allAtOnceReason is only valid for the all-at-once strategy")
		}
	case HotfixRolloutAllAtOnce:
		if !profile.AllowAllAtOnce {
			return fmt.Errorf("the template does not allow the all-at-once strategy")
		}
		if reason := strings.TrimSpace(rollout.AllAtOnceReason); len(reason) < 30 || len(rollout.AllAtOnceReason) > 700 {
			return fmt.Errorf("all-at-once needs an allAtOnceReason of 30..700 characters")
		}
		if payload != nil && payload.Type == HotfixPayloadStaticPodImage {
			return fmt.Errorf("static-pod-image changes control-plane nodes one at a time; all-at-once is not allowed")
		}
		if rollout.CanaryNodes != 0 || rollout.MaxUnavailable != nil {
			return fmt.Errorf("all-at-once does not use canaryNodes or maxUnavailable")
		}
	default:
		return fmt.Errorf("unsupported rollout strategy %q", rollout.Strategy)
	}
	if rollout.CanaryNodes < 0 || rollout.CanaryNodes > 10 || rollout.SoakSeconds < 0 || rollout.SoakSeconds > 3600 {
		return fmt.Errorf("canaryNodes must be 1..10 and soakSeconds 0..3600")
	}
	if rollout.SoakSeconds != 0 && rollout.SoakSeconds < profile.MinSoakSeconds {
		return fmt.Errorf("soakSeconds must be at least the template minimum %d", profile.MinSoakSeconds)
	}
	if rollout.MaxUnavailable != nil {
		if _, err := HotfixBatchSize(profile, rollout, 100); err != nil {
			return err
		}
	}
	return nil
}

// HotfixEffectiveRollout applies defaults to a validated rollout.
func HotfixEffectiveRollout(profile *DebugSessionHotfix, rollout *HotfixRollout) HotfixRollout {
	effective := HotfixRollout{}
	if rollout != nil {
		effective = *rollout.DeepCopy()
	}
	if effective.Strategy == "" {
		effective.Strategy = HotfixRolloutCanary
	}
	if effective.Strategy == HotfixRolloutCanary {
		if effective.CanaryNodes == 0 {
			effective.CanaryNodes = 1
		}
		if effective.MaxUnavailable == nil {
			value := hotfixDefaultMaxUnavail
			effective.MaxUnavailable = &value
		}
	}
	floor := profile.MinSoakSeconds
	if floor == 0 {
		floor = 60
	}
	effective.SoakSeconds = max(effective.SoakSeconds, floor)
	return effective
}

// HotfixBatchSize returns the batch size after the canary for n selected nodes.
// The template's maxBatchPercent (default 25) caps it; the result is at least 1.
func HotfixBatchSize(profile *DebugSessionHotfix, rollout *HotfixRollout, n int) (int, error) {
	value := hotfixDefaultMaxUnavail
	if rollout.MaxUnavailable != nil {
		value = *rollout.MaxUnavailable
	}
	if value.Type == intstr.String {
		percent, err := strconv.Atoi(strings.TrimSuffix(value.StrVal, "%"))
		if !strings.HasSuffix(value.StrVal, "%") || err != nil || percent < 1 || percent > 100 {
			return 0, fmt.Errorf("maxUnavailable %q must be a count or a percentage of 1..100", value.StrVal)
		}
	}
	size, err := intstr.GetScaledValueFromIntOrPercent(&value, n, false)
	if err != nil || size < 0 || (value.Type == intstr.Int && value.IntVal < 1) {
		return 0, fmt.Errorf("maxUnavailable must be a positive count or percentage")
	}
	percent := profile.MaxBatchPercent
	if percent == 0 {
		percent = 25
	}
	capSize := n * int(percent) / 100
	return max(1, min(size, capSize)), nil
}

func validateHotfixNodes(profile *DebugSessionHotfix, nodes *HotfixNodeSelection) error {
	if nodes == nil || (len(nodes.Names) == 0) == (nodes.Selector == nil) {
		return fmt.Errorf("hotfix needs exactly one of nodes.names or nodes.selector")
	}
	maxNodes := int(profile.MaxNodes)
	if maxNodes == 0 {
		maxNodes = 500
	}
	if len(nodes.Names) > maxNodes {
		return fmt.Errorf("hotfix selects more than %d nodes", maxNodes)
	}
	for _, name := range nodes.Names {
		if len(validation.IsDNS1123Subdomain(name)) != 0 {
			return fmt.Errorf("invalid node name %q", name)
		}
	}
	if nodes.Selector != nil {
		if len(nodes.Selector.MatchLabels)+len(nodes.Selector.MatchExpressions) == 0 {
			return fmt.Errorf("nodes.selector must not be empty; select all nodes explicitly with an Exists expression")
		}
		if _, err := metav1.LabelSelectorAsSelector(nodes.Selector); err != nil {
			return fmt.Errorf("invalid node selector: %w", err)
		}
	}
	return nil
}

// ValidateHotfixRequest checks a typed request against the template profile.
func ValidateHotfixRequest(profile *DebugSessionHotfix, request *DebugSessionHotfixRequest) error {
	if profile == nil {
		if request != nil {
			return fmt.Errorf("template does not enable hotfix")
		}
		return nil
	}
	if request == nil {
		return fmt.Errorf("hotfix template requires a typed hotfix request")
	}
	if err := ValidateHotfixProfile(profile); err != nil {
		return err
	}
	if profile.Suspended && (request.Stage == HotfixStagePlan || request.Stage == HotfixStageApply) {
		return fmt.Errorf("hotfix template is suspended; only rollback, reconfirm and close are allowed")
	}
	planOnly := request.Payload != nil || request.Nodes != nil || request.Rollout != nil || request.FixedIn != ""
	switch request.Stage {
	case HotfixStagePlan:
		if request.PlanRef != "" || request.PlanHash != "" || request.RecordName != "" {
			return fmt.Errorf("plan does not take planRef, planHash or recordName")
		}
		if err := ValidateHotfixPayload(profile, request.Payload); err != nil {
			return err
		}
		if err := validateHotfixNodes(profile, request.Nodes); err != nil {
			return err
		}
		if err := ValidateHotfixRollout(profile, request.Payload, request.Rollout); err != nil {
			return err
		}
		if strings.TrimSpace(request.FixedIn) == "" || len(request.FixedIn) > 256 {
			return fmt.Errorf("plan needs fixedIn (1..256 characters): the release that will contain the fix")
		}
		_, err := HotfixLifetime(profile, request.Lifetime)
		return err
	case HotfixStageApply:
		if planOnly || request.Lifetime != "" || request.RecordName != "" ||
			len(validation.IsDNS1123Subdomain(request.PlanRef)) != 0 || !hotfixSHA256Pattern.MatchString(request.PlanHash) {
			return fmt.Errorf("apply takes only planRef and planHash")
		}
	case HotfixStageRollback, HotfixStageClose:
		if planOnly || request.Lifetime != "" || request.PlanRef != "" || request.PlanHash != "" ||
			len(validation.IsDNS1123Subdomain(request.RecordName)) != 0 {
			return fmt.Errorf("%s takes only recordName", request.Stage)
		}
	case HotfixStageReconfirm:
		if planOnly || request.PlanRef != "" || request.PlanHash != "" || len(validation.IsDNS1123Subdomain(request.RecordName)) != 0 {
			return fmt.Errorf("reconfirm takes only recordName and lifetime")
		}
		_, err := HotfixLifetime(profile, request.Lifetime)
		return err
	default:
		return fmt.Errorf("unsupported hotfix stage %q", request.Stage)
	}
	return nil
}

// ValidateHotfixTemplate applies the fixed-executor template contract to a hotfix profile.
func ValidateHotfixTemplate(spec *DebugSessionTemplateSpec) error {
	if spec.Hotfix == nil {
		return nil
	}
	if spec.NodeMaintenance != nil {
		return fmt.Errorf("hotfix and nodeMaintenance are mutually exclusive")
	}
	if err := validateFixedExecutorTemplate(spec, "hotfix"); err != nil {
		return err
	}
	if spec.BlockSelfApproval == nil || !*spec.BlockSelfApproval {
		return fmt.Errorf("hotfix requires blockSelfApproval: true; self-approval is never allowed")
	}
	if duration, _ := ParseDuration(spec.Constraints.MaxDuration); duration > HotfixMaxSessionDuration {
		return fmt.Errorf("hotfix maxDuration must be at most %s", HotfixMaxSessionDuration)
	}
	return ValidateHotfixProfile(spec.Hotfix)
}

// ValidateHotfixSession forbids request-side generic workload inputs.
func ValidateHotfixSession(spec *DebugSessionTemplateSpec, request *DebugSessionSpec) error {
	if err := ValidateHotfixRequest(spec.Hotfix, request.Hotfix); err != nil {
		return err
	}
	if spec.Hotfix == nil {
		return nil
	}
	if err := ValidateHotfixTemplate(spec); err != nil {
		return err
	}
	if request.NodeMaintenance != nil || len(request.ExtraDeployValues) != 0 || len(request.NodeSelector) != 0 ||
		request.SelectedSchedulingOption != "" || request.ResolvedSchedulingConstraints != nil ||
		len(request.SelectedAuxiliaryResources) != 0 || len(request.InvitedParticipants) != 0 ||
		(request.TargetNamespace != "" && request.TargetNamespace != NodeMaintenanceNamespace) {
		return fmt.Errorf("hotfix accepts only the typed hotfix request, not generic workload overrides")
	}
	return nil
}

// HotfixPlanHash is the SHA-256 of the canonical JSON of a plan. Approvers of
// the apply stage review this exact hash; any change to payload, rollout,
// lifetime, nodes, node UIDs or planned hashes changes it.
func HotfixPlanHash(plan *HotfixPlan) (string, error) {
	if plan == nil {
		return "", fmt.Errorf("hotfix plan is missing")
	}
	data, err := json.Marshal(plan)
	if err != nil {
		return "", err
	}
	if len(data) > HotfixMaxPlanBytes {
		return "", fmt.Errorf("hotfix plan is %d bytes; at most %d fit in a session status", len(data), HotfixMaxPlanBytes)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// ValidateHotfixPlanBinding checks that an apply request names an unexpired,
// succeeded plan of the same cluster and template whose hash matches.
func ValidateHotfixPlanBinding(profile *DebugSessionHotfix, apply *DebugSession, plan *DebugSession, now time.Time) error {
	if profile == nil || apply.Spec.Hotfix == nil || apply.Spec.Hotfix.Stage != HotfixStageApply {
		return fmt.Errorf("not a hotfix apply request")
	}
	if profile.Suspended {
		return fmt.Errorf("hotfix template is suspended")
	}
	if plan == nil || plan.Name != apply.Spec.Hotfix.PlanRef || plan.Namespace != apply.Namespace ||
		plan.Spec.Hotfix == nil || plan.Spec.Hotfix.Stage != HotfixStagePlan {
		return fmt.Errorf("planRef does not name a hotfix plan session")
	}
	if plan.Spec.Cluster != apply.Spec.Cluster || plan.Spec.TemplateRef != apply.Spec.TemplateRef {
		return fmt.Errorf("plan targets another cluster or template")
	}
	status := plan.Status.Hotfix
	if status == nil || status.Plan == nil || status.PlannedAt == nil || len(status.Plan.Nodes) == 0 {
		return fmt.Errorf("plan has not succeeded")
	}
	if now.Sub(status.PlannedAt.Time) > HotfixPlanValidity || now.Before(status.PlannedAt.Time) {
		return fmt.Errorf("plan is older than %s; plan again", HotfixPlanValidity)
	}
	hash, err := HotfixPlanHash(status.Plan)
	if err != nil {
		return err
	}
	if hash != status.PlanHash || hash != apply.Spec.Hotfix.PlanHash {
		return fmt.Errorf("planHash does not match the reviewed plan")
	}
	if status.AppliedBy != "" && status.AppliedBy != apply.Name {
		return fmt.Errorf("plan was already applied by %s; plan again", status.AppliedBy)
	}
	// The template may have been narrowed since the plan; the plan must still fit it.
	if err := ValidateHotfixPayload(profile, &status.Plan.Payload); err != nil {
		return fmt.Errorf("plan no longer fits the template: %w", err)
	}
	if err := ValidateHotfixRollout(profile, &status.Plan.Payload, &status.Plan.Rollout); err != nil {
		return fmt.Errorf("plan no longer fits the template: %w", err)
	}
	return nil
}

// validateHotfixTemplateField reports hotfix template errors at spec.hotfix.
func validateHotfixTemplateField(spec *DebugSessionTemplateSpec, specPath *field.Path) field.ErrorList {
	if spec.Hotfix == nil {
		return nil
	}
	if err := ValidateHotfixTemplate(spec); err != nil {
		return field.ErrorList{field.Invalid(specPath.Child("hotfix"), "", err.Error())}
	}
	return nil
}
