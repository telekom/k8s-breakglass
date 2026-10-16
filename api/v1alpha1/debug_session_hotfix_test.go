// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	kptr "k8s.io/utils/ptr"
)

func hotfixSum(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

var hotfixDigest = "@sha256:" + strings.Repeat("a", 64)

func testHotfixProfile() *DebugSessionHotfix {
	return &DebugSessionHotfix{
		ExecutorImage:       "ghcr.io/telekom/k8s-breakglass/utils/node-maintenance" + hotfixDigest,
		PayloadTypes:        []HotfixPayloadType{HotfixPayloadNodeFile, HotfixPayloadNodeDeb, HotfixPayloadStaticPodImage, HotfixPayloadHostContainerImage},
		AllowedPaths:        []string{"/etc/containerd/config.toml", "/etc/kubernetes/manifests/", "/etc/ssh/"},
		RestartableServices: []HotfixService{"containerd.service", "kubelet.service"},
		StaticPods:          []HotfixStaticPod{"kube-apiserver", "etcd"},
		HostContainers:      []HotfixHostContainer{{Name: "cra-vsr", ContainerdNamespace: "hbr", Unit: "cra.service", ImageRefFile: "/etc/cra/image"}},
		AllowAllAtOnce:      true,
		MinSoakSeconds:      60,
	}
}

func testHotfixPlanRequest() *DebugSessionHotfixRequest {
	content := "version = 3\n"
	return &DebugSessionHotfixRequest{
		Stage: HotfixStagePlan,
		Payload: &HotfixPayload{Type: HotfixPayloadNodeFile, Restart: []HotfixService{"containerd.service"}, File: &HotfixFilePayload{
			Path: "/etc/containerd/config.toml", Mode: HotfixFileReplace, Content: content,
			BeforeSHA256: []string{strings.Repeat("b", 64)}, AfterSHA256: hotfixSum(content),
		}},
		Nodes:   &HotfixNodeSelection{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"node-role.kubernetes.io/worker": ""}}},
		FixedIn: "node image 2026.10.2",
	}
}

func TestHotfixRequestValidation(t *testing.T) {
	require.NoError(t, ValidateHotfixRequest(testHotfixProfile(), testHotfixPlanRequest()))
	require.NoError(t, ValidateHotfixRequest(nil, nil))
	require.Error(t, ValidateHotfixRequest(nil, testHotfixPlanRequest()), "template without hotfix")
	require.Error(t, ValidateHotfixRequest(testHotfixProfile(), nil), "hotfix template without request")

	diff := "--- a/etc/ssh/sshd_config\n+++ b/etc/ssh/sshd_config\n@@ -1,2 +1,2 @@\n Port 22\n-PermitRootLogin yes\n+PermitRootLogin no\n"
	for _, tc := range []struct {
		name   string
		mutate func(*DebugSessionHotfix, *DebugSessionHotfixRequest)
		ok     bool
	}{
		{"sed", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Payload.File = &HotfixFilePayload{Path: "/etc/ssh/sshd_config", Mode: HotfixFileSed, SedExpressions: []string{`s/^#?PermitRootLogin .*/PermitRootLogin no/`, `s|a\|b|c|g2`}}
		}, true},
		{"diff", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Payload.File = &HotfixFilePayload{Path: "/etc/ssh/sshd_config", Mode: HotfixFileDiff, Diff: diff}
		}, true},
		{"replace by url", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Payload.File.Content, r.Payload.File.URL = "", "https://artifactory.example/hotfix/config.toml"
		}, true},
		{"deb with new package", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Payload = &HotfixPayload{Type: HotfixPayloadNodeDeb, Debs: []HotfixDeb{
				{URL: "https://mirror.example/openssh-server.deb", SHA256: strings.Repeat("c", 64), Package: "openssh-server", Version: "1:9.6p1-3ubuntu13.99"},
				{URL: "https://mirror.example/libnew.deb", SHA256: strings.Repeat("d", 64), Package: "libnew1", Version: "2.0~rc1-1"},
			}, RollbackDebs: []HotfixDeb{{URL: "https://mirror.example/openssh-old.deb", SHA256: strings.Repeat("e", 64), Package: "openssh-server", Version: "1:9.6p1-3ubuntu13.5"}}}
		}, true},
		{"static pod image incl. etcd", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Payload = &HotfixPayload{Type: HotfixPayloadStaticPodImage, Image: &HotfixImagePayload{StaticPod: "etcd", Image: "registry.k8s.io/etcd" + hotfixDigest}}
		}, true},
		{"host container image with registry port", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Payload = &HotfixPayload{Type: HotfixPayloadHostContainerImage, Image: &HotfixImagePayload{HostContainer: "cra-vsr", Image: "registry.example:5000/t-caas/cra-vsr" + hotfixDigest}}
		}, true},
		{"all-at-once with reason", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Rollout = &HotfixRollout{Strategy: HotfixRolloutAllAtOnce, AllAtOnceReason: "actively exploited CVE in containerd, SOC ticket 4711"}
		}, true},
		{"node names", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Nodes = &HotfixNodeSelection{Names: []string{"worker-1", "worker-2"}}
		}, true},
		{"lifetime at cap", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) { r.Lifetime = "30d" }, true},
		{"diff removing a line that reads like a header", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Payload.File = &HotfixFilePayload{Path: "/etc/ssh/sshd_config", Mode: HotfixFileDiff,
				Diff: "--- a/f\n+++ b/f\n@@ -1,2 +1,2 @@\n--- old\n+++ new\n x\n"}
		}, true},
		{"url with query", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Payload.File.Content, r.Payload.File.URL = "", "https://s3.example/config.toml?X-Amz-Signature=secret"
		}, false},
		{"empty selector", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Nodes = &HotfixNodeSelection{Selector: &metav1.LabelSelector{}}
		}, false},
		{"maxUnavailable 0%", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Rollout = &HotfixRollout{MaxUnavailable: kptr.To(intstr.FromString("0%"))}
		}, false},
		{"maxUnavailable 150%", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Rollout = &HotfixRollout{MaxUnavailable: kptr.To(intstr.FromString("150%"))}
		}, false},
		{"template maxLifetime above 30d", func(p *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			p.MaxLifetime = "60d"
			r.Lifetime = "40d"
		}, false},
		{"truncated hunk", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Payload.File = &HotfixFilePayload{Path: "/etc/ssh/sshd_config", Mode: HotfixFileDiff, Diff: "--- a/f\n+++ b/f\n@@ -1,3 +1,3 @@\n x\n-y\n+z\n"}
		}, false},

		// Pinning.
		{"image tag", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Payload = &HotfixPayload{Type: HotfixPayloadStaticPodImage, Image: &HotfixImagePayload{StaticPod: "etcd", Image: "registry.k8s.io/etcd:3.6.5"}}
		}, false},
		{"image without registry host", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Payload = &HotfixPayload{Type: HotfixPayloadHostContainerImage, Image: &HotfixImagePayload{HostContainer: "cra-vsr", Image: "t-caas/cra-vsr" + hotfixDigest}}
		}, false},
		{"image tag plus digest", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Payload = &HotfixPayload{Type: HotfixPayloadStaticPodImage, Image: &HotfixImagePayload{StaticPod: "etcd", Image: "registry.k8s.io/etcd:3.6.5" + hotfixDigest}}
		}, false},
		{"uppercase sha", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Payload.File.BeforeSHA256 = []string{strings.Repeat("B", 64)}
		}, false},
		{"short sha", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Payload.File.BeforeSHA256 = []string{"abc"}
		}, false},
		{"after hash does not match content", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Payload.File.AfterSHA256 = strings.Repeat("f", 64)
		}, false},
		{"after equals before", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Payload.File.BeforeSHA256 = []string{r.Payload.File.AfterSHA256}
		}, false},
		{"replace without before", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) { r.Payload.File.BeforeSHA256 = nil }, false},
		{"content and url", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) { r.Payload.File.URL = "https://a.example/x" }, false},
		{"content too large", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Payload.File.Content = strings.Repeat("x", HotfixMaxInlineBytes+1)
			r.Payload.File.AfterSHA256 = hotfixSum(r.Payload.File.Content)
		}, false},
		{"http url", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Payload.File.Content, r.Payload.File.URL = "", "http://artifactory.example/config.toml"
		}, false},
		{"url with credentials", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Payload.File.Content, r.Payload.File.URL = "", "https://user:secret@artifactory.example/config.toml"
		}, false},

		// Paths.
		{"traversal", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) { r.Payload.File.Path = "/etc/ssh/../shadow" }, false},
		{"relative", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) { r.Payload.File.Path = "etc/ssh/sshd_config" }, false},
		{"trailing slash", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) { r.Payload.File.Path = "/etc/ssh/" }, false},
		{"not allowlisted", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) { r.Payload.File.Path = "/etc/hosts" }, false},
		{"denied ssh host key under allowed dir", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Payload.File.Path = "/etc/ssh/ssh_host_ed25519_key"
		}, false},
		{"denied pki even if allowlisted", func(p *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			p.AllowedPaths = append(p.AllowedPaths, "/etc/kubernetes/")
			r.Payload.File.Path = "/etc/kubernetes/pki/ca.key"
		}, false},
		{"denied kubeconfig", func(p *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			p.AllowedPaths = []string{"/etc/kubernetes/admin.conf"}
		}, false},
		{"denied allowlist of state dir", func(p *DebugSessionHotfix, _ *DebugSessionHotfixRequest) {
			p.AllowedPaths = append(p.AllowedPaths, HotfixStateDir+"/")
		}, false},
		{"allowlist root", func(p *DebugSessionHotfix, _ *DebugSessionHotfixRequest) {
			p.AllowedPaths = append(p.AllowedPaths, "/")
		}, false},

		// Sed and diff.
		{"sed execute flag", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Payload.File = &HotfixFilePayload{Path: "/etc/ssh/sshd_config", Mode: HotfixFileSed, SedExpressions: []string{"s/a/id/e"}}
		}, false},
		{"sed write flag", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Payload.File = &HotfixFilePayload{Path: "/etc/ssh/sshd_config", Mode: HotfixFileSed, SedExpressions: []string{"s/a/b/w /etc/shadow"}}
		}, false},
		{"sed other command", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Payload.File = &HotfixFilePayload{Path: "/etc/ssh/sshd_config", Mode: HotfixFileSed, SedExpressions: []string{"1d"}}
		}, false},
		{"sed two commands", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Payload.File = &HotfixFilePayload{Path: "/etc/ssh/sshd_config", Mode: HotfixFileSed, SedExpressions: []string{"s/a/b/;e id"}}
		}, false},
		{"sed with after hash", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Payload.File = &HotfixFilePayload{Path: "/etc/ssh/sshd_config", Mode: HotfixFileSed, SedExpressions: []string{"s/a/b/"}, AfterSHA256: strings.Repeat("a", 64)}
		}, false},
		{"diff of two files", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Payload.File = &HotfixFilePayload{Path: "/etc/ssh/sshd_config", Mode: HotfixFileDiff, Diff: diff + "--- a/etc/passwd\n+++ b/etc/passwd\n@@ -1 +1 @@\n-a\n+b\n"}
		}, false},
		{"git diff header", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Payload.File = &HotfixFilePayload{Path: "/etc/ssh/sshd_config", Mode: HotfixFileDiff, Diff: "diff --git a/x b/x\n" + diff}
		}, false},
		{"diff with no-newline marker", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Payload.File = &HotfixFilePayload{Path: "/etc/ssh/sshd_config", Mode: HotfixFileDiff, Diff: diff + "\\ No newline at end of file\n"}
		}, false},
		{"diff without hunk", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Payload.File = &HotfixFilePayload{Path: "/etc/ssh/sshd_config", Mode: HotfixFileDiff, Diff: "--- a\n+++ b\n x\n y\n"}
		}, false},

		// Payload shape and profile limits.
		{"payload type disabled", func(p *DebugSessionHotfix, _ *DebugSessionHotfixRequest) {
			p.PayloadTypes = []HotfixPayloadType{HotfixPayloadNodeDeb}
		}, false},
		{"restart not allowed", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Payload.Restart = []HotfixService{"ssh.service"}
		}, false},
		{"file plus debs", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Payload.Debs = []HotfixDeb{{URL: "https://m.example/a.deb", SHA256: strings.Repeat("c", 64), Package: "aa", Version: "1"}}
		}, false},
		{"duplicate deb package", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			deb := HotfixDeb{URL: "https://m.example/a.deb", SHA256: strings.Repeat("c", 64), Package: "aa", Version: "1"}
			r.Payload = &HotfixPayload{Type: HotfixPayloadNodeDeb, Debs: []HotfixDeb{deb, deb}}
		}, false},
		{"rollback deb for other package", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			deb := HotfixDeb{URL: "https://m.example/a.deb", SHA256: strings.Repeat("c", 64), Package: "aa", Version: "1"}
			other := deb
			other.Package = "bb"
			r.Payload = &HotfixPayload{Type: HotfixPayloadNodeDeb, Debs: []HotfixDeb{deb}, RollbackDebs: []HotfixDeb{other}}
		}, false},
		{"deb bad version", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Payload = &HotfixPayload{Type: HotfixPayloadNodeDeb, Debs: []HotfixDeb{{URL: "https://m.example/a.deb", SHA256: strings.Repeat("c", 64), Package: "aa", Version: "1; rm -rf /"}}}
		}, false},
		{"static pod not allowed", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Payload = &HotfixPayload{Type: HotfixPayloadStaticPodImage, Image: &HotfixImagePayload{StaticPod: "kube-scheduler", Image: "registry.k8s.io/kube-scheduler" + hotfixDigest}}
		}, false},
		{"unknown host container", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Payload = &HotfixPayload{Type: HotfixPayloadHostContainerImage, Image: &HotfixImagePayload{HostContainer: "other", Image: "registry.example/x" + hotfixDigest}}
		}, false},
		{"image payload with restart", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Payload = &HotfixPayload{Type: HotfixPayloadStaticPodImage, Restart: []HotfixService{"kubelet.service"}, Image: &HotfixImagePayload{StaticPod: "etcd", Image: "registry.k8s.io/etcd" + hotfixDigest}}
		}, false},

		// Rollout.
		{"all-at-once without reason", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Rollout = &HotfixRollout{Strategy: HotfixRolloutAllAtOnce}
		}, false},
		{"all-at-once short reason", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Rollout = &HotfixRollout{Strategy: HotfixRolloutAllAtOnce, AllAtOnceReason: "urgent                              "}
		}, false},
		{"all-at-once not allowed by template", func(p *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			p.AllowAllAtOnce = false
			r.Rollout = &HotfixRollout{Strategy: HotfixRolloutAllAtOnce, AllAtOnceReason: strings.Repeat("r", 40)}
		}, false},
		{"all-at-once for control plane", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Payload = &HotfixPayload{Type: HotfixPayloadStaticPodImage, Image: &HotfixImagePayload{StaticPod: "kube-apiserver", Image: "registry.k8s.io/kube-apiserver" + hotfixDigest}}
			r.Rollout = &HotfixRollout{Strategy: HotfixRolloutAllAtOnce, AllAtOnceReason: strings.Repeat("r", 40)}
		}, false},
		{"reason with canary", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Rollout = &HotfixRollout{AllAtOnceReason: strings.Repeat("r", 40)}
		}, false},
		{"soak below template minimum", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) { r.Rollout = &HotfixRollout{SoakSeconds: 10} }, false},
		{"zero maxUnavailable", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Rollout = &HotfixRollout{MaxUnavailable: kptr.To(intstr.FromInt32(0))}
		}, false},
		{"maxUnavailable string without percent", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			r.Rollout = &HotfixRollout{MaxUnavailable: kptr.To(intstr.FromString("5"))}
		}, false},

		// Nodes, lifetime and stage shape.
		{"names and selector", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) { r.Nodes.Names = []string{"worker-1"} }, false},
		{"no nodes", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) { r.Nodes = nil }, false},
		{"too many nodes", func(p *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			p.MaxNodes = 1
			r.Nodes = &HotfixNodeSelection{Names: []string{"a", "b"}}
		}, false},
		{"lifetime above cap", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) { r.Lifetime = "31d" }, false},
		{"lifetime above template cap", func(p *DebugSessionHotfix, r *DebugSessionHotfixRequest) {
			p.MaxLifetime = "7d"
			r.Lifetime = "8d"
		}, false},
		{"missing fixedIn", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) { r.FixedIn = "  " }, false},
		{"plan with planHash", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) { r.PlanHash = strings.Repeat("a", 64) }, false},
		{"suspended template refuses plan", func(p *DebugSessionHotfix, _ *DebugSessionHotfixRequest) { p.Suspended = true }, false},
		{"unknown stage", func(_ *DebugSessionHotfix, r *DebugSessionHotfixRequest) { r.Stage = "execute" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile, request := testHotfixProfile(), testHotfixPlanRequest()
			tc.mutate(profile, request)
			err := ValidateHotfixRequest(profile, request)
			if tc.ok {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestHotfixStageRequests(t *testing.T) {
	profile := testHotfixProfile()
	hash := strings.Repeat("a", 64)
	require.NoError(t, ValidateHotfixRequest(profile, &DebugSessionHotfixRequest{Stage: HotfixStageApply, PlanRef: "plan-1", PlanHash: hash}))
	require.Error(t, ValidateHotfixRequest(profile, &DebugSessionHotfixRequest{Stage: HotfixStageApply, PlanRef: "plan-1"}), "apply without hash")
	require.Error(t, ValidateHotfixRequest(profile, &DebugSessionHotfixRequest{Stage: HotfixStageApply, PlanRef: "plan-1", PlanHash: hash,
		Payload: testHotfixPlanRequest().Payload}), "apply cannot change the payload")
	for _, stage := range []HotfixStage{HotfixStageRollback, HotfixStageClose} {
		require.NoError(t, ValidateHotfixRequest(profile, &DebugSessionHotfixRequest{Stage: stage, RecordName: "hotfix-1"}))
		require.Error(t, ValidateHotfixRequest(profile, &DebugSessionHotfixRequest{Stage: stage}))
		require.Error(t, ValidateHotfixRequest(profile, &DebugSessionHotfixRequest{Stage: stage, RecordName: "hotfix-1", Lifetime: "1d"}))
	}
	require.NoError(t, ValidateHotfixRequest(profile, &DebugSessionHotfixRequest{Stage: HotfixStageReconfirm, RecordName: "hotfix-1", Lifetime: "7d"}))
	require.Error(t, ValidateHotfixRequest(profile, &DebugSessionHotfixRequest{Stage: HotfixStageReconfirm, RecordName: "hotfix-1", Lifetime: "60d"}))

	// A suspended template still lets operators revoke an active hotfix.
	profile.Suspended = true
	require.Error(t, ValidateHotfixRequest(profile, &DebugSessionHotfixRequest{Stage: HotfixStageApply, PlanRef: "plan-1", PlanHash: hash}))
	for _, stage := range []HotfixStage{HotfixStageRollback, HotfixStageClose} {
		require.NoError(t, ValidateHotfixRequest(profile, &DebugSessionHotfixRequest{Stage: stage, RecordName: "hotfix-1"}))
	}
}

func TestHotfixProfileValidation(t *testing.T) {
	require.NoError(t, ValidateHotfixProfile(testHotfixProfile()))
	for name, mutate := range map[string]func(*DebugSessionHotfix){
		"executor tag":            func(p *DebugSessionHotfix) { p.ExecutorImage = "ghcr.io/x/node-maintenance:v1" },
		"no payload types":        func(p *DebugSessionHotfix) { p.PayloadTypes = nil },
		"file without paths":      func(p *DebugSessionHotfix) { p.AllowedPaths = nil },
		"static pod without pods": func(p *DebugSessionHotfix) { p.StaticPods = nil },
		"host container in k8s.io": func(p *DebugSessionHotfix) {
			p.HostContainers[0].ContainerdNamespace = "k8s.io"
		},
		"host container denied ref file": func(p *DebugSessionHotfix) { p.HostContainers[0].ImageRefFile = "/etc/shadow" },
		"host container bad unit":        func(p *DebugSessionHotfix) { p.HostContainers[0].Unit = "cra.service; reboot" },
		"bad max lifetime":               func(p *DebugSessionHotfix) { p.MaxLifetime = "forever" },
		"unknown service":                func(p *DebugSessionHotfix) { p.RestartableServices = []HotfixService{"sshd.socket"} },
	} {
		t.Run(name, func(t *testing.T) {
			profile := testHotfixProfile()
			mutate(profile)
			require.Error(t, ValidateHotfixProfile(profile))
		})
	}
}

func TestHotfixPathDenylist(t *testing.T) {
	for _, denied := range []string{
		"/etc/kubernetes/pki", "/etc/kubernetes/pki/etcd/ca.key", "/etc/kubernetes/admin.conf", "/etc/kubernetes/super-admin.conf",
		"/var/lib/kubelet/pki/kubelet-client-current.pem", "/var/lib/kubelet/kubeconfig", "/etc/shadow", "/etc/shadow-", "/etc/gshadow",
		"/etc/sudoers", "/etc/sudoers.d/90-cloud", "/root/.bashrc", "/home/ubuntu/.ssh/authorized_keys", "/etc/ssh/ssh_host_rsa_key.pub",
		"/var/lib/breakglass-hotfix/x/backup", "/proc/sys/kernel/panic", "/sys/kernel/x",
	} {
		require.True(t, HotfixPathDenied(denied), denied)
	}
	for _, allowed := range []string{"/etc/ssh/sshd_config", "/etc/containerd/config.toml", "/etc/kubernetes/manifests/etcd.yaml", "/usr/bin/containerd", "/etc/cra/image"} {
		require.False(t, HotfixPathDenied(allowed), allowed)
	}
}

func TestHotfixBatchSize(t *testing.T) {
	profile := testHotfixProfile()
	for _, tc := range []struct {
		maxUnavailable *intstr.IntOrString
		percent        int32
		nodes, want    int
	}{
		{nil, 0, 100, 10},
		{nil, 0, 3, 1},
		{kptr.To(intstr.FromString("50%")), 0, 100, 25},
		{kptr.To(intstr.FromString("50%")), 60, 100, 50},
		{kptr.To(intstr.FromInt32(7)), 0, 100, 7},
		{kptr.To(intstr.FromInt32(40)), 0, 100, 25},
		{kptr.To(intstr.FromString("1%")), 0, 10, 1},
	} {
		profile.MaxBatchPercent = tc.percent
		size, err := HotfixBatchSize(profile, &HotfixRollout{MaxUnavailable: tc.maxUnavailable}, tc.nodes)
		require.NoError(t, err)
		require.Equal(t, tc.want, size)
	}
	profile.MaxLifetime = "7d"
	lifetime, err := HotfixLifetime(profile, "")
	require.NoError(t, err)
	require.Equal(t, 7*24*time.Hour, lifetime, "default is capped by the template maximum")
	profile.MaxLifetime = ""
	effective := HotfixEffectiveRollout(profile, nil)
	require.Equal(t, HotfixRolloutCanary, effective.Strategy)
	require.EqualValues(t, 1, effective.CanaryNodes)
	require.EqualValues(t, 60, effective.SoakSeconds)
	require.Equal(t, "10%", effective.MaxUnavailable.StrVal)
}

func testHotfixTemplateSpec() *DebugSessionTemplateSpec {
	return &DebugSessionTemplateSpec{
		TargetNamespace:   NodeMaintenanceNamespace,
		Approvers:         &DebugSessionApprovers{Groups: []string{"platform-emergency"}},
		BlockSelfApproval: kptr.To(true),
		Constraints:       &DebugSessionConstraints{MaxDuration: "4h"},
		Hotfix:            testHotfixProfile(),
	}
}

func TestHotfixTemplateContract(t *testing.T) {
	require.NoError(t, ValidateHotfixTemplate(testHotfixTemplateSpec()))
	for name, mutate := range map[string]func(*DebugSessionTemplateSpec){
		"no approvers":           func(s *DebugSessionTemplateSpec) { s.Approvers = nil },
		"auto approve":           func(s *DebugSessionTemplateSpec) { s.Approvers.AutoApproveFor = &AutoApproveConfig{} },
		"self approval":          func(s *DebugSessionTemplateSpec) { s.BlockSelfApproval = kptr.To(false) },
		"self approval unset":    func(s *DebugSessionTemplateSpec) { s.BlockSelfApproval = nil },
		"no max duration":        func(s *DebugSessionTemplateSpec) { s.Constraints = nil },
		"max duration over 6h":   func(s *DebugSessionTemplateSpec) { s.Constraints.MaxDuration = "7h" },
		"idle timeout":           func(s *DebugSessionTemplateSpec) { s.Constraints.IdleTimeout = "10m" },
		"other namespace":        func(s *DebugSessionTemplateSpec) { s.TargetNamespace = "kube-system" },
		"pod template":           func(s *DebugSessionTemplateSpec) { s.PodTemplateString = "containers: []" },
		"with node maintenance":  func(s *DebugSessionTemplateSpec) { s.NodeMaintenance = &DebugSessionNodeMaintenance{} },
		"invalid hotfix profile": func(s *DebugSessionTemplateSpec) { s.Hotfix.ExecutorImage = "x:latest" },
	} {
		t.Run(name, func(t *testing.T) {
			spec := testHotfixTemplateSpec()
			mutate(spec)
			require.Error(t, ValidateHotfixTemplate(spec))
		})
	}

	spec := testHotfixTemplateSpec()
	session := &DebugSessionSpec{Hotfix: testHotfixPlanRequest()}
	require.NoError(t, ValidateHotfixSession(spec, session))
	session.NodeSelector = map[string]string{"kubernetes.io/hostname": "x"}
	require.Error(t, ValidateHotfixSession(spec, session), "generic overrides are refused")
	session.NodeSelector = nil
	session.TargetNamespace = "kube-system"
	require.Error(t, ValidateHotfixSession(spec, session), "the fixed namespace cannot be overridden")
	require.Error(t, ValidateHotfixSession(&DebugSessionTemplateSpec{}, &DebugSessionSpec{Hotfix: testHotfixPlanRequest()}))
}

func TestHotfixPlanBinding(t *testing.T) {
	now := time.Date(2026, 10, 14, 10, 0, 0, 0, time.UTC)
	plan := &HotfixPlan{
		Payload: *testHotfixPlanRequest().Payload, Rollout: HotfixEffectiveRollout(testHotfixProfile(), nil), Lifetime: "336h", FixedIn: "next",
		Nodes: []HotfixPlannedNode{{Name: "worker-1", UID: "uid-1", Action: "apply", BeforeSHA256: strings.Repeat("b", 64), AfterSHA256: strings.Repeat("c", 64)}},
	}
	hash, err := HotfixPlanHash(plan)
	require.NoError(t, err)
	planSession := func() *DebugSession {
		return &DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: "plan-1", Namespace: "breakglass"},
			Spec:       DebugSessionSpec{Cluster: "c1", TemplateRef: "hotfix", Hotfix: testHotfixPlanRequest()},
			Status:     DebugSessionStatus{Hotfix: &HotfixStatus{Plan: plan.DeepCopy(), PlanHash: hash, PlannedAt: &metav1.Time{Time: now.Add(-time.Hour)}}},
		}
	}
	apply := &DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "apply-1", Namespace: "breakglass"},
		Spec:       DebugSessionSpec{Cluster: "c1", TemplateRef: "hotfix", Hotfix: &DebugSessionHotfixRequest{Stage: HotfixStageApply, PlanRef: "plan-1", PlanHash: hash}},
	}
	require.NoError(t, ValidateHotfixPlanBinding(testHotfixProfile(), apply, planSession(), now))

	for name, mutate := range map[string]func(*DebugSession){
		"stale plan":       func(p *DebugSession) { p.Status.Hotfix.PlannedAt.Time = now.Add(-3 * time.Hour) },
		"future plan":      func(p *DebugSession) { p.Status.Hotfix.PlannedAt.Time = now.Add(time.Hour) },
		"other cluster":    func(p *DebugSession) { p.Spec.Cluster = "prd" },
		"other template":   func(p *DebugSession) { p.Spec.TemplateRef = "other" },
		"not succeeded":    func(p *DebugSession) { p.Status.Hotfix = nil },
		"node uid changed": func(p *DebugSession) { p.Status.Hotfix.Plan.Nodes[0].UID = "replacement" },
		"payload changed":  func(p *DebugSession) { p.Status.Hotfix.Plan.Payload.Restart = nil },
		"not a plan":       func(p *DebugSession) { p.Spec.Hotfix.Stage = HotfixStageApply },
		"other name":       func(p *DebugSession) { p.Name = "plan-2" },
		"other namespace":  func(p *DebugSession) { p.Namespace = "other" },
		"no nodes":         func(p *DebugSession) { p.Status.Hotfix.Plan.Nodes = nil },
		"tampered hash":    func(p *DebugSession) { p.Status.Hotfix.PlanHash = strings.Repeat("1", 64) },
		"already applied":  func(p *DebugSession) { p.Status.Hotfix.AppliedBy = "apply-0" },
	} {
		t.Run(name, func(t *testing.T) {
			p := planSession()
			mutate(p)
			require.Error(t, ValidateHotfixPlanBinding(testHotfixProfile(), apply, p, now))
		})
	}
	applied := planSession()
	applied.Status.Hotfix.AppliedBy = "apply-1"
	require.NoError(t, ValidateHotfixPlanBinding(testHotfixProfile(), apply, applied, now), "the consuming session may re-check its own plan")
	narrowed := testHotfixProfile()
	narrowed.AllowedPaths = []string{"/etc/ssh/"}
	require.Error(t, ValidateHotfixPlanBinding(narrowed, apply, planSession(), now), "plan must still fit a narrowed template")
	suspended := testHotfixProfile()
	suspended.Suspended = true
	require.Error(t, ValidateHotfixPlanBinding(suspended, apply, planSession(), now))
	wrongHash := apply.DeepCopy()
	wrongHash.Spec.Hotfix.PlanHash = strings.Repeat("0", 64)
	require.Error(t, ValidateHotfixPlanBinding(testHotfixProfile(), wrongHash, planSession(), now))
}
