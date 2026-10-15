// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var digest = "@sha256:" + strings.Repeat("a", 64)

// fakeHost records host commands and answers them from a table.
type fakeHost struct {
	calls   []string
	answers map[string]string
	fail    map[string]bool
	// onCall lets a test observe host state at the time of a command.
	onCall func(call string)
}

func (f *fakeHost) run(_ context.Context, env []string, stdin []byte, name string, args ...string) ([]byte, error) {
	if name != "nsenter" {
		return runCommand(context.Background(), env, stdin, name, args...)
	}
	// Strip "nsenter -t 1 ... -- env -i PATH=..." down to the host argv.
	i := 0
	for i < len(args) && args[i] != "--" {
		i++
	}
	argv := args[i+4:] // after "-- env -i PATH=..."
	for len(argv) > 0 && strings.Contains(argv[0], "=") {
		argv = argv[1:]
	}
	call := strings.Join(argv, " ")
	f.calls = append(f.calls, call)
	if f.onCall != nil {
		f.onCall(call)
	}
	for prefix, failed := range f.fail {
		if failed && strings.HasPrefix(call, prefix) {
			return nil, errors.New("injected failure: " + call)
		}
	}
	for prefix, answer := range f.answers {
		if strings.HasPrefix(call, prefix) {
			return []byte(answer), nil
		}
	}
	return nil, nil
}

func newTestExecutor(t *testing.T, hostExec bool) (*executor, *fakeHost) {
	t.Helper()
	fake := &fakeHost{answers: map[string]string{}, fail: map[string]bool{}}
	ex := &executor{root: t.TempDir(), hostExec: hostExec, work: t.TempDir(), run: fake.run, now: time.Now, poll: time.Millisecond}
	return ex, fake
}

func writeHost(t *testing.T, ex *executor, p, content string) {
	t.Helper()
	require(t, os.MkdirAll(filepath.Dir(ex.host(p)), 0o755))
	require(t, os.WriteFile(ex.host(p), []byte(content), 0o640))
}

func readHost(t *testing.T, ex *executor, p string) string {
	t.Helper()
	data, err := os.ReadFile(ex.host(p))
	require(t, err)
	return string(data)
}

func require(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func fileRequest(stage string, f filePayload) *request {
	return &request{Stage: stage, HotfixID: "hf-1", DeadlineUnix: time.Now().Add(time.Hour).Unix(),
		AllowedPaths: []string{"/etc/ssh/", "/etc/containerd/config.toml"}, Restartable: []string{"containerd.service"},
		Payload: payload{Type: payloadFile, File: &f}}
}

const sshd = "Port 22\nPermitRootLogin yes\nUsePAM yes\n"
const sshdFixed = "Port 22\nPermitRootLogin no\nUsePAM yes\n"

func TestFileReplacePlanApplyRollback(t *testing.T) {
	ex, _ := newTestExecutor(t, false)
	writeHost(t, ex, "/etc/ssh/sshd_config", sshd)
	f := filePayload{Path: "/etc/ssh/sshd_config", Mode: "replace", Content: sshdFixed, BeforeSHA256: []string{sum([]byte(sshd))}, AfterSHA256: sum([]byte(sshdFixed))}

	plan, err := ex.execute(fileRequest(stagePlan, f))
	require(t, err)
	if plan.Action != "apply" || plan.BeforeSHA256 != sum([]byte(sshd)) || plan.AfterSHA256 != sum([]byte(sshdFixed)) ||
		!strings.Contains(plan.Diff, "+PermitRootLogin no") {
		t.Fatalf("unexpected plan %+v", plan)
	}
	if readHost(t, ex, "/etc/ssh/sshd_config") != sshd {
		t.Fatal("plan changed the file")
	}

	apply := fileRequest(stageApply, f)
	apply.Expected = &expected{BeforeSHA256: plan.BeforeSHA256, AfterSHA256: plan.AfterSHA256}
	out, err := ex.execute(apply)
	require(t, err)
	if out.Result != "applied" || readHost(t, ex, "/etc/ssh/sshd_config") != sshdFixed {
		t.Fatalf("apply failed: %+v", out)
	}
	info, err := os.Stat(ex.host("/etc/ssh/sshd_config"))
	require(t, err)
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode not preserved: %v", info.Mode())
	}
	if entries, _ := os.ReadDir(ex.host("/etc/ssh")); len(entries) != 1 {
		t.Fatalf("temporary file left behind: %v", entries)
	}
	if _, err := os.Stat(ex.host(ex.backupPath(apply, f.Path) + ".json")); err != nil {
		t.Fatalf("backup metadata missing: %v", err)
	}

	// Single attempt is idempotent: a second apply skips.
	again, err := ex.execute(apply)
	require(t, err)
	if again.Result != "skipped" {
		t.Fatalf("second apply must skip, got %+v", again)
	}

	rollback := fileRequest(stageRollback, f)
	rollback.Expected = apply.Expected
	back, err := ex.execute(rollback)
	require(t, err)
	if back.Result != "rolledBack" || readHost(t, ex, "/etc/ssh/sshd_config") != sshd {
		t.Fatalf("rollback failed: %+v", back)
	}
}

func TestFileApplyRefusesChangedPreImage(t *testing.T) {
	ex, _ := newTestExecutor(t, false)
	writeHost(t, ex, "/etc/ssh/sshd_config", sshd)
	f := filePayload{Path: "/etc/ssh/sshd_config", Mode: "replace", Content: sshdFixed, BeforeSHA256: []string{sum([]byte(sshd))}, AfterSHA256: sum([]byte(sshdFixed))}
	apply := fileRequest(stageApply, f)
	apply.Expected = &expected{BeforeSHA256: sum([]byte(sshd)), AfterSHA256: sum([]byte(sshdFixed))}
	writeHost(t, ex, "/etc/ssh/sshd_config", sshd+"# local edit\n")
	if _, err := ex.execute(apply); err == nil || !strings.Contains(err.Error(), "changed since the plan") {
		t.Fatalf("expected pre-image refusal, got %v", err)
	}

	// A plan refuses an unaccepted pre-image too.
	if _, err := ex.execute(fileRequest(stagePlan, f)); err == nil {
		t.Fatal("plan must refuse an unaccepted beforeSHA256")
	}

	// Rollback refuses a file that drifted after the hotfix.
	rollback := fileRequest(stageRollback, f)
	rollback.Expected = apply.Expected
	if _, err := ex.execute(rollback); err == nil || !strings.Contains(err.Error(), "not restoring") {
		t.Fatalf("expected drift refusal, got %v", err)
	}
}

func TestFileSedAndDiff(t *testing.T) {
	ex, _ := newTestExecutor(t, false)
	writeHost(t, ex, "/etc/ssh/sshd_config", sshd)
	sed := filePayload{Path: "/etc/ssh/sshd_config", Mode: "sed", SedExpressions: []string{`s/^#?PermitRootLogin .*/PermitRootLogin no/`}}
	plan, err := ex.execute(fileRequest(stagePlan, sed))
	require(t, err)
	if plan.AfterSHA256 != sum([]byte(sshdFixed)) || plan.Action != "apply" {
		t.Fatalf("sed plan %+v", plan)
	}

	diff := "--- a/etc/ssh/sshd_config\n+++ b/etc/ssh/sshd_config\n@@ -1,3 +1,3 @@\n Port 22\n-PermitRootLogin yes\n+PermitRootLogin no\n UsePAM yes\n"
	patch := filePayload{Path: "/etc/ssh/sshd_config", Mode: "diff", Diff: diff}
	plan2, err := ex.execute(fileRequest(stagePlan, patch))
	require(t, err)
	if plan2.AfterSHA256 != plan.AfterSHA256 {
		t.Fatal("sed and diff must produce the same result")
	}
	apply := fileRequest(stageApply, patch)
	apply.Expected = &expected{BeforeSHA256: plan2.BeforeSHA256, AfterSHA256: plan2.AfterSHA256}
	_, err = ex.execute(apply)
	require(t, err)
	if readHost(t, ex, "/etc/ssh/sshd_config") != sshdFixed {
		t.Fatal("diff not applied")
	}
	// Re-planning the applied file: the sed result equals the input.
	again, err := ex.execute(fileRequest(stagePlan, sed))
	require(t, err)
	if again.Action != "skip" {
		t.Fatalf("already patched node must be skipped, got %+v", again)
	}

	// sed runs in sandbox mode, so even a crafted expression cannot write files.
	evil := filePayload{Path: "/etc/ssh/sshd_config", Mode: "sed", SedExpressions: []string{"s/a/b/w /tmp/hotfix-sed-escape"}}
	if _, err := ex.newContent(&evil, []byte("a\n")); err == nil {
		t.Fatal("sed --sandbox must reject the w flag")
	}
}

func TestApplyUnifiedDiffIsStrict(t *testing.T) {
	old := []byte("a\nb\nc\nd\n")
	for name, diff := range map[string]string{
		"context mismatch": "--- a\n+++ b\n@@ -1,2 +1,2 @@\n x\n-b\n+B\n",
		"wrong counts":     "--- a\n+++ b\n@@ -2,2 +2,2 @@\n-b\n+B\n",
		"offset needed":    "--- a\n+++ b\n@@ -1,1 +1,1 @@\n-c\n+C\n",
		"beyond file":      "--- a\n+++ b\n@@ -9,1 +9,1 @@\n-z\n+Z\n",
		"no newline mark":  "--- a\n+++ b\n@@ -4,1 +4,1 @@\n-d\n+D\n\\ No newline at end of file\n",
	} {
		if _, err := applyUnifiedDiff(old, diff); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	out, err := applyUnifiedDiff(old, "--- a\n+++ b\n@@ -2,1 +2,2 @@\n-b\n+B\n+B2\n@@ -4,0 +5,1 @@\n+e\n")
	require(t, err)
	if string(out) != "a\nB\nB2\nc\nd\ne\n" {
		t.Fatalf("got %q", out)
	}
}

func TestFileRefusesSymlinksDenylistAndUnallowedPaths(t *testing.T) {
	ex, _ := newTestExecutor(t, false)
	writeHost(t, ex, "/etc/real/sshd_config", sshd)
	require(t, os.Symlink(ex.host("/etc/real"), ex.host("/etc/ssh")))
	f := filePayload{Path: "/etc/ssh/sshd_config", Mode: "sed", SedExpressions: []string{"s/a/b/"}}
	if _, err := ex.execute(fileRequest(stagePlan, f)); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink refusal, got %v", err)
	}
	for _, p := range []string{"/etc/ssh/ssh_host_rsa_key", "/etc/kubernetes/pki/ca.key", "/etc/shadow", "/etc/hosts", "/etc/ssh/../shadow"} {
		req := fileRequest(stagePlan, filePayload{Path: p, Mode: "sed", SedExpressions: []string{"s/a/b/"}})
		req.AllowedPaths = append(req.AllowedPaths, "/etc/kubernetes/", "/etc/shadow")
		if _, err := ex.execute(req); err == nil {
			t.Errorf("%s must be refused", p)
		}
	}
	writeHost(t, ex, "/etc/containerd/config.toml", "x\n")
	require(t, os.Remove(ex.host("/etc/containerd/config.toml")))
	require(t, os.Mkdir(ex.host("/etc/containerd/config.toml"), 0o755))
	if _, err := ex.execute(fileRequest(stagePlan, filePayload{Path: "/etc/containerd/config.toml", Mode: "sed", SedExpressions: []string{"s/a/b/"}})); err == nil {
		t.Fatal("a directory must be refused")
	}
}

func TestMutationNeverStartsWithoutBudget(t *testing.T) {
	ex, _ := newTestExecutor(t, false)
	writeHost(t, ex, "/etc/ssh/sshd_config", sshd)
	f := filePayload{Path: "/etc/ssh/sshd_config", Mode: "replace", Content: sshdFixed, BeforeSHA256: []string{sum([]byte(sshd))}, AfterSHA256: sum([]byte(sshdFixed))}
	apply := fileRequest(stageApply, f)
	apply.Expected = &expected{BeforeSHA256: sum([]byte(sshd)), AfterSHA256: sum([]byte(sshdFixed))}
	apply.DeadlineUnix = time.Now().Add(deadlineMargin + 10*time.Second).Unix()
	if _, err := ex.execute(apply); err == nil || !strings.Contains(err.Error(), "step budget") {
		t.Fatalf("expected budget refusal, got %v", err)
	}
	if readHost(t, ex, "/etc/ssh/sshd_config") != sshd {
		t.Fatal("file changed without budget")
	}
	apply.DeadlineUnix = time.Now().Add(-time.Minute).Unix()
	if _, err := ex.execute(apply); err == nil {
		t.Fatal("expired deadline must fail")
	}
}

func TestRestartNeedsHostExecutorAndAllowlist(t *testing.T) {
	ex, _ := newTestExecutor(t, false)
	writeHost(t, ex, "/etc/containerd/config.toml", "a = 1\n")
	f := filePayload{Path: "/etc/containerd/config.toml", Mode: "sed", SedExpressions: []string{"s/1/2/"}}
	req := fileRequest(stageApply, f)
	req.Payload.Restart = []string{"containerd.service"}
	req.Expected = &expected{BeforeSHA256: sum([]byte("a = 1\n")), AfterSHA256: sum([]byte("a = 2\n"))}
	if _, err := ex.execute(req); err == nil || !strings.Contains(err.Error(), "host-namespace executor") {
		t.Fatalf("restart must need the host executor, got %v", err)
	}

	hostEx, fake := newTestExecutor(t, true)
	writeHost(t, hostEx, "/etc/containerd/config.toml", "a = 1\n")
	fake.answers["systemctl is-active containerd.service"] = "active\n"
	out, err := hostEx.execute(req)
	require(t, err)
	if out.Result != "applied" || strings.Join(fake.calls, ";") != "systemctl restart containerd.service;systemctl is-active containerd.service" {
		t.Fatalf("unexpected restart calls %v / %+v", fake.calls, out)
	}

	req.Payload.Restart = []string{"kubelet.service"}
	if _, err := hostEx.execute(req); err == nil {
		t.Fatal("unit outside the profile must be refused")
	}
}

func debRequest(stage string) *request {
	return &request{Stage: stage, HotfixID: "hf-2", DeadlineUnix: time.Now().Add(time.Hour).Unix(),
		Restartable: []string{"ssh.service"},
		Payload: payload{Type: payloadDeb, Debs: []deb{
			{URL: "https://mirror.example/openssh.deb", SHA256: strings.Repeat("c", 64), Package: "openssh-server", Version: "1:9.6p1-3ubuntu13.99"},
			{URL: "https://mirror.example/libnew.deb", SHA256: strings.Repeat("d", 64), Package: "libnew1", Version: "2.0-1"},
		}}}
}

func TestDebInstallUsesPolicyRCAndReassertsHold(t *testing.T) {
	ex, fake := newTestExecutor(t, true)
	req := debRequest(stageApply)
	require(t, os.MkdirAll(ex.host("/usr/sbin"), 0o755))
	// Stage the debs as a plan would have downloaded them.
	for i := range req.Payload.Debs {
		req.Payload.Debs[i].SHA256 = sum([]byte("deb-" + req.Payload.Debs[i].Package))
		writeHost(t, ex, ex.debPath(req, req.Payload.Debs[i]), "deb-"+req.Payload.Debs[i].Package)
		fake.answers["dpkg-deb -f "+ex.debPath(req, req.Payload.Debs[i])] = fmt.Sprintf("Package: %s\nVersion: %s\n", req.Payload.Debs[i].Package, req.Payload.Debs[i].Version)
	}
	installed := false
	fake.answers["dpkg-query -W -f=${Status} openssh-server"] = "hold ok installed"
	fake.answers["findmnt"] = "rw,relatime"
	policySeen := false
	fake.onCall = func(call string) {
		if strings.HasPrefix(call, "dpkg --force-hold --force-confold -i") {
			data, err := os.ReadFile(ex.host(policyRC))
			policySeen = err == nil && strings.Contains(string(data), "exit 101")
			installed = true
		}
		if strings.HasPrefix(call, "dpkg-query -W -f=${db:Status-Abbrev}") {
			if installed {
				fake.answers["dpkg-query -W -f=${db:Status-Abbrev} ${Version} openssh-server"] = "hi  1:9.6p1-3ubuntu13.99"
				fake.answers["dpkg-query -W -f=${db:Status-Abbrev} ${Version} libnew1"] = "ii  2.0-1"
			} else {
				fake.answers["dpkg-query -W -f=${db:Status-Abbrev} ${Version} openssh-server"] = "hi  1:9.6p1-3ubuntu13.5"
			}
		}
	}
	before := packageState(req.Payload.Debs, func(d deb) string {
		if d.Package == "openssh-server" {
			return "1:9.6p1-3ubuntu13.5"
		}
		return ""
	})
	after := packageState(req.Payload.Debs, func(d deb) string { return d.Version })
	req.Expected = &expected{BeforeSHA256: before, AfterSHA256: after, NewPackages: []string{"libnew1"}}
	out, err := ex.execute(req)
	require(t, err)
	if out.Result != "applied" || !policySeen {
		t.Fatalf("result %+v, policy-rc.d during install: %v", out, policySeen)
	}
	if _, err := os.Stat(ex.host(policyRC)); !os.IsNotExist(err) {
		t.Fatal("policy-rc.d must be removed after the install")
	}
	joined := strings.Join(fake.calls, "\n")
	for _, want := range []string{"apt-mark hold openssh-server", "dpkg --audit"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in %s", want, joined)
		}
	}
}

func TestDebRefusesReadOnlyUsrAndControlMismatch(t *testing.T) {
	ex, fake := newTestExecutor(t, true)
	req := debRequest(stagePlan)
	fake.answers["findmnt"] = "ro,relatime"
	if _, err := ex.execute(req); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("expected read-only refusal, got %v", err)
	}
	fake.answers["findmnt"] = "rw"
	req.Payload.Debs = req.Payload.Debs[:1]
	req.Payload.Debs[0].SHA256 = sum([]byte("deb"))
	writeHost(t, ex, ex.debPath(req, req.Payload.Debs[0]), "deb")
	fake.answers["dpkg-deb -f"] = "Package: openssh-server\nVersion: 1:9.6p1-3ubuntu13.98\n"
	if _, err := ex.execute(req); err == nil || !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("expected control field mismatch, got %v", err)
	}
	if strings.Contains(strings.Join(fake.calls, ";"), "dpkg -i") {
		t.Fatal("plan must never install")
	}
}

func TestDebDryRunFailureBlocksPlan(t *testing.T) {
	ex, fake := newTestExecutor(t, true)
	req := debRequest(stagePlan)
	req.Payload.Debs = req.Payload.Debs[:1]
	req.Payload.Debs[0].SHA256 = sum([]byte("deb"))
	writeHost(t, ex, ex.debPath(req, req.Payload.Debs[0]), "deb")
	fake.answers["findmnt"] = "rw"
	fake.answers["dpkg-deb -f"] = "Package: openssh-server\nVersion: 1:9.6p1-3ubuntu13.99\n"
	fake.fail["dpkg --dry-run"] = true
	if _, err := ex.execute(req); err == nil || !strings.Contains(err.Error(), "dependency check") {
		t.Fatalf("expected dependency failure, got %v", err)
	}
}

const apiserverManifest = `apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
spec:
  containers:
  - command:
    - kube-apiserver
    image: registry.k8s.io/kube-apiserver:v1.36.4
    name: kube-apiserver
`

func TestStaticPodImageSwap(t *testing.T) {
	ex, fake := newTestExecutor(t, true)
	writeHost(t, ex, manifestPath("kube-apiserver"), apiserverManifest)
	image := "registry.k8s.io/kube-apiserver" + digest
	req := &request{Stage: stagePlan, HotfixID: "hf-3", DeadlineUnix: time.Now().Add(time.Hour).Unix(),
		Payload: payload{Type: payloadStaticPod, Image: &imagePayload{StaticPod: "kube-apiserver", Image: image}}}
	plan, err := ex.execute(req)
	require(t, err)
	if plan.Action != "apply" || !strings.Contains(plan.Diff, "+    image: "+image) {
		t.Fatalf("plan %+v", plan)
	}
	req.Stage = stageApply
	req.Expected = &expected{BeforeSHA256: plan.BeforeSHA256, AfterSHA256: plan.AfterSHA256}
	fake.answers["crictl inspecti"] = `{"status":{"id":"sha256:new","repoDigests":["registry.k8s.io/kube-apiserver` + digest + `"]}}`
	fake.answers["crictl ps --name ^kube-apiserver$"] = `{"containers":[{"id":"c1","imageRef":"sha256:new"}]}`
	out, err := ex.execute(req)
	require(t, err)
	if out.Result != "applied" || !strings.Contains(readHost(t, ex, manifestPath("kube-apiserver")), "image: "+image) {
		t.Fatalf("apply %+v", out)
	}
	if !strings.HasPrefix(fake.calls[0], "crictl pull "+image) {
		t.Fatalf("image must be pre-pulled before the manifest changes: %v", fake.calls)
	}
	entries, _ := os.ReadDir(ex.host("/etc/kubernetes/manifests"))
	if len(entries) != 1 {
		t.Fatalf("no extra file may appear in the manifest directory: %v", entries)
	}
}

func TestEtcdSwapRequiresQuorum(t *testing.T) {
	ex, fake := newTestExecutor(t, true)
	manifest := strings.ReplaceAll(apiserverManifest, "kube-apiserver", "etcd")
	writeHost(t, ex, manifestPath("etcd"), manifest)
	image := "registry.k8s.io/etcd" + digest
	updated, err := patchImage([]byte(manifest), image)
	require(t, err)
	req := &request{Stage: stageApply, HotfixID: "hf-4", DeadlineUnix: time.Now().Add(time.Hour).Unix(),
		Payload:  payload{Type: payloadStaticPod, Image: &imagePayload{StaticPod: "etcd", Image: image}},
		Expected: &expected{BeforeSHA256: sum([]byte(manifest)), AfterSHA256: sum(updated)}}
	fake.answers["crictl ps --name ^etcd$"] = "e1\n"
	fake.answers["crictl exec e1 etcdctl"] = ""
	fake.onCall = func(call string) {
		if strings.HasSuffix(call, "member list") {
			fake.answers["crictl exec e1 etcdctl"] = `{"members":[{"ID":1},{"ID":2},{"ID":3}]}`
		}
		if strings.HasSuffix(call, "endpoint status --cluster") {
			fake.answers["crictl exec e1 etcdctl"] = `[{"Endpoint":"a","Status":{"header":{"member_id":1},"leader":7}},{"Endpoint":"b","Status":{"header":{"member_id":2},"leader":7}}]`
		}
	}
	if _, err := ex.execute(req); err == nil || !strings.Contains(err.Error(), "quorum") {
		t.Fatalf("2 of 3 members must refuse, got %v", err)
	}
	if strings.Contains(strings.Join(fake.calls, ";"), "crictl pull") {
		t.Fatal("nothing may be pulled or changed without quorum")
	}
	if readHost(t, ex, manifestPath("etcd")) != manifest {
		t.Fatal("manifest changed without quorum")
	}
}

func TestHostContainerSwap(t *testing.T) {
	ex, fake := newTestExecutor(t, true)
	writeHost(t, ex, "/etc/cra/image", "cit-t-caas-oci/images/t-caas/cra-vsr-6wind-ubi:3.12.3.1\n")
	image := "registry.example/t-caas/cra-vsr" + digest
	c := &hostContainer{Name: "cra-vsr", ContainerdNamespace: "hbr", Unit: "cra.service", ImageRefFile: "/etc/cra/image"}
	req := &request{Stage: stagePlan, HotfixID: "hf-5", DeadlineUnix: time.Now().Add(time.Hour).Unix(), HostContainer: c,
		Payload: payload{Type: payloadHostContainer, Image: &imagePayload{HostContainer: "cra-vsr", Image: image}}}
	plan, err := ex.execute(req)
	require(t, err)
	req.Stage = stageApply
	req.Expected = &expected{BeforeSHA256: plan.BeforeSHA256, AfterSHA256: plan.AfterSHA256}
	fake.answers["nerdctl --namespace hbr inspect"] = image + " true\n"
	out, err := ex.execute(req)
	require(t, err)
	joined := strings.Join(fake.calls, ";")
	if out.Result != "applied" || readHost(t, ex, "/etc/cra/image") != image+"\n" ||
		!strings.Contains(joined, "ctr -n hbr images pull --hosts-dir /etc/containerd/certs.d "+image) ||
		!strings.Contains(joined, "systemctl restart cra.service") {
		t.Fatalf("apply %+v %s", out, joined)
	}

	// A container that does not come back with the new image fails the node.
	writeHost(t, ex, "/etc/cra/image", "cit-t-caas-oci/images/t-caas/cra-vsr-6wind-ubi:3.12.3.1\n")
	fake.answers["nerdctl --namespace hbr inspect"] = image + " false\n"
	if _, err := ex.execute(req); err == nil {
		t.Fatal("a stopped container must fail the node")
	}

	req.HostContainer = &hostContainer{Name: "cra-vsr", ContainerdNamespace: "k8s.io", Unit: "cra.service", ImageRefFile: "/etc/cra/image"}
	if _, err := ex.execute(req); err == nil {
		t.Fatal("the Kubernetes containerd namespace must be refused")
	}
}

func TestRequestValidation(t *testing.T) {
	base := func() *request {
		return fileRequest(stagePlan, filePayload{Path: "/etc/ssh/sshd_config", Mode: "sed", SedExpressions: []string{"s/a/b/"}})
	}
	for name, mutate := range map[string]func(*request){
		"bad id":           func(r *request) { r.HotfixID = "../x" },
		"bad stage":        func(r *request) { r.Stage = "execute" },
		"apply no hashes":  func(r *request) { r.Stage = stageApply },
		"sed newline":      func(r *request) { r.Payload.File.SedExpressions = []string{"s/a/b/\ne /bin/sh"} },
		"sed other cmd":    func(r *request) { r.Payload.File.SedExpressions = []string{"1d"} },
		"restart unlisted": func(r *request) { r.Payload.Restart = []string{"kubelet.service"} },
		"image tag": func(r *request) {
			r.Payload = payload{Type: payloadStaticPod, Image: &imagePayload{StaticPod: "etcd", Image: "registry.k8s.io/etcd:3.6"}}
		},
		"http deb": func(r *request) {
			r.Payload = payload{Type: payloadDeb, Debs: []deb{{URL: "http://m/a.deb", SHA256: strings.Repeat("a", 64), Package: "aa", Version: "1"}}}
		},
	} {
		req := base()
		mutate(req)
		if err := validateRequest(req); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if err := validateRequest(base()); err != nil {
		t.Fatal(err)
	}
}

// stageDebs writes the debs of req as a plan would have downloaded them.
func stageTestDebs(t *testing.T, ex *executor, fake *fakeHost, req *request, debs []deb) {
	t.Helper()
	require(t, os.MkdirAll(ex.host("/usr/sbin"), 0o755))
	for i := range debs {
		debs[i].SHA256 = sum([]byte("deb-" + debs[i].Package + debs[i].Version))
		writeHost(t, ex, ex.debPath(req, debs[i]), "deb-"+debs[i].Package+debs[i].Version)
		fake.answers["dpkg-deb -f "+ex.debPath(req, debs[i])] = fmt.Sprintf("Package: %s\nVersion: %s\n", debs[i].Package, debs[i].Version)
	}
}

func TestDebInstallFailureRestoresPolicyRC(t *testing.T) {
	ex, fake := newTestExecutor(t, true)
	req := debRequest(stageApply)
	req.Payload.Debs = req.Payload.Debs[:1]
	stageTestDebs(t, ex, fake, req, req.Payload.Debs)
	writeHost(t, ex, policyRC, "#!/bin/sh\nexit 0\n")
	fake.answers["findmnt"] = "rw"
	fake.answers["dpkg-query -W -f=${db:Status-Abbrev} ${Version} openssh-server"] = "ii  1:9.6p1-3ubuntu13.5"
	fake.fail["dpkg --force-hold"] = true
	before := packageState(req.Payload.Debs, func(deb) string { return "1:9.6p1-3ubuntu13.5" })
	req.Expected = &expected{BeforeSHA256: before, AfterSHA256: packageState(req.Payload.Debs, func(d deb) string { return d.Version })}
	if _, err := ex.execute(req); err == nil || !strings.Contains(err.Error(), "dpkg --configure -a") {
		t.Fatalf("expected install failure with recovery hint, got %v", err)
	}
	if readHost(t, ex, policyRC) != "#!/bin/sh\nexit 0\n" {
		t.Fatal("the previous policy-rc.d must be restored after a failed install")
	}
}

func TestLeftoverPolicyRCIsRecovered(t *testing.T) {
	ex, _ := newTestExecutor(t, true)
	writeHost(t, ex, policyRC, "#!/bin/sh\n"+policyRCMarker+"\nexit 101\n")
	writeHost(t, ex, policyRCNone, "")
	require(t, ex.recoverServiceStarts())
	if _, err := os.Stat(ex.host(policyRC)); !os.IsNotExist(err) {
		t.Fatal("a policy-rc.d left by a killed executor must be removed")
	}
}

func TestDebRollbackPurgesAndVerifies(t *testing.T) {
	ex, fake := newTestExecutor(t, true)
	req := debRequest(stageRollback)
	old := deb{URL: "https://mirror.example/openssh-old.deb", Package: "openssh-server", Version: "1:9.6p1-3ubuntu13.5"}
	req.Payload.RollbackDebs = []deb{old}
	stageTestDebs(t, ex, fake, req, req.Payload.RollbackDebs)
	fake.answers["findmnt"] = "rw"
	state := "applied"
	fake.onCall = func(call string) {
		switch {
		case strings.HasPrefix(call, "dpkg --force-hold --force-confold --force-downgrade -i"):
			state = "downgraded"
		case call == "dpkg --purge libnew1":
			state = "purged"
		}
		ssh, lib := "ii  1:9.6p1-3ubuntu13.99", "ii  2.0-1"
		if state != "applied" {
			ssh = "ii  1:9.6p1-3ubuntu13.5"
		}
		if state == "purged" {
			lib = "rc  2.0-1"
		}
		fake.answers["dpkg-query -W -f=${db:Status-Abbrev} ${Version} openssh-server"] = ssh
		fake.answers["dpkg-query -W -f=${db:Status-Abbrev} ${Version} libnew1"] = lib
	}
	before := packageState(req.Payload.Debs, func(d deb) string {
		if d.Package == "openssh-server" {
			return "1:9.6p1-3ubuntu13.5"
		}
		return ""
	})
	after := packageState(req.Payload.Debs, func(d deb) string { return d.Version })
	req.Expected = &expected{BeforeSHA256: before, AfterSHA256: after, NewPackages: []string{"libnew1"}}
	out, err := ex.execute(req)
	require(t, err)
	if out.Result != "rolledBack" || state != "purged" {
		t.Fatalf("rollback %+v state %s", out, state)
	}

	// Without rollbackDebs an upgraded package stays; rollback must not claim success.
	ex2, fake2 := newTestExecutor(t, true)
	req2 := debRequest(stageRollback)
	req2.Payload.Debs = req2.Payload.Debs[:1]
	fake2.answers["findmnt"] = "rw"
	fake2.answers["dpkg-query -W -f=${db:Status-Abbrev} ${Version} openssh-server"] = "ii  1:9.6p1-3ubuntu13.99"
	req2.Expected = &expected{BeforeSHA256: packageState(req2.Payload.Debs, func(deb) string { return "1:9.6p1-3ubuntu13.5" }),
		AfterSHA256: packageState(req2.Payload.Debs, func(d deb) string { return d.Version })}
	if _, err := ex2.execute(req2); err == nil || !strings.Contains(err.Error(), "replace the node") {
		t.Fatalf("expected a verified rollback failure, got %v", err)
	}
}

func TestDpkgQueryFailureIsNotAbsence(t *testing.T) {
	ex, fake := newTestExecutor(t, true)
	fake.fail["dpkg-query"] = true
	if _, err := ex.execute(debRequest(stagePlan)); err == nil || !strings.Contains(err.Error(), "injected failure") {
		t.Fatalf("a failing dpkg-query must fail the plan, got %v", err)
	}
}

func TestHostContainerRollbackUsesRunningImage(t *testing.T) {
	ex, fake := newTestExecutor(t, true)
	writeHost(t, ex, "/etc/cra/image", "cit-t-caas-oci/images/t-caas/cra-vsr-6wind-ubi:3.12.3.1\n")
	image := "registry.example/t-caas/cra-vsr" + digest
	c := &hostContainer{Name: "cra-vsr", ContainerdNamespace: "hbr", Unit: "cra.service", ImageRefFile: "/etc/cra/image"}
	req := &request{Stage: stagePlan, HotfixID: "hf-6", DeadlineUnix: time.Now().Add(time.Hour).Unix(), HostContainer: c,
		Payload: payload{Type: payloadHostContainer, Image: &imagePayload{HostContainer: "cra-vsr", Image: image}}}
	plan, err := ex.execute(req)
	require(t, err)
	normalized := "docker.io/cit-t-caas-oci/images/t-caas/cra-vsr-6wind-ubi:3.12.3.1"
	running := normalized
	fake.onCall = func(call string) {
		if strings.HasPrefix(call, "systemctl restart cra.service") {
			content := readHost(t, ex, "/etc/cra/image")
			if strings.HasPrefix(content, "registry.example") {
				running = image
			} else {
				running = normalized
			}
		}
		fake.answers["nerdctl --namespace hbr inspect"] = running + " true\n"
	}
	req.Stage = stageApply
	req.Expected = &expected{BeforeSHA256: plan.BeforeSHA256, AfterSHA256: plan.AfterSHA256}
	_, err = ex.execute(req)
	require(t, err)
	req.Stage = stageRollback
	out, err := ex.execute(req)
	require(t, err)
	if out.Result != "rolledBack" || running != normalized {
		t.Fatalf("rollback %+v running %s", out, running)
	}
}

func TestStaticPodWaitTimesOut(t *testing.T) {
	ex, fake := newTestExecutor(t, true)
	base := time.Now()
	calls := 0
	ex.now = func() time.Time { calls++; return base.Add(time.Duration(calls) * time.Second) }
	ex.deadline = base.Add(time.Hour)
	fake.answers["crictl ps"] = `{"containers":[{"id":"c1","imageRef":"sha256:old"}]}`
	if err := ex.waitStaticPod("kube-apiserver", "sha256:new", digest, time.Minute); err == nil {
		t.Fatal("waiting must time out when the old image keeps running")
	}
	fake.answers["crictl ps"] = `{"containers":[{"id":"c1","imageRef":"registry.k8s.io/kube-apiserver` + digest + `"}]}`
	require(t, ex.waitStaticPod("kube-apiserver", "sha256:new", digest, time.Minute))
}

func TestResultFitsTerminationMessage(t *testing.T) {
	out := &result{Result: "planned", Diff: strings.Repeat("<&>\"", 2500), Message: strings.Repeat("x", 3000), BeforeSHA256: strings.Repeat("a", 64)}
	data := fitResult(out)
	if len(data) > maxResultBytes {
		t.Fatalf("result is %d bytes", len(data))
	}
	var parsed result
	require(t, json.Unmarshal(data, &parsed))
	if parsed.BeforeSHA256 != strings.Repeat("a", 64) || !strings.Contains(parsed.Diff, "[truncated]") {
		t.Fatalf("hashes must survive and the diff must be marked truncated: %+v", parsed)
	}
}
