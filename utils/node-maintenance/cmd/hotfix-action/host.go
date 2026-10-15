// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"
)

const hostPath = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// runCommand runs one binary without a shell and returns stdout. On failure
// stdout is still returned (diff exits 1 when files differ).
func runCommand(ctx context.Context, env []string, stdin []byte, name string, args ...string) ([]byte, error) {
	// Callers pass fixed binary names (sed, diff, nsenter) and arguments built
	// from validated, typed request fields; no shell is involved.
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- fixed binaries, validated arguments, no shell
	cmd.Env = env
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err != nil {
		message := strings.TrimSpace(stderr.String())
		if len(message) > 400 {
			message = message[len(message)-400:]
		}
		err = fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, message)
	}
	return stdout.Bytes(), err
}

// hostRun runs a host binary in the host namespaces of PID 1.
func (ex *executor) hostRun(ctx context.Context, env []string, name string, args ...string) ([]byte, error) {
	if !ex.hostExec {
		return nil, errors.New("this payload needs the host-namespace executor")
	}
	argv := append([]string{"-t", "1", "-m", "-u", "-i", "-n", "-p", "--", "env", "-i", hostPath}, env...)
	argv = append(argv, name)
	return ex.run(ctx, nil, nil, "nsenter", append(argv, args...)...)
}

// hostStep runs one bounded host command.
func (ex *executor) hostStep(budget time.Duration, env []string, name string, args ...string) ([]byte, error) {
	ctx, cancel, err := ex.step(budget)
	if err != nil {
		return nil, err
	}
	defer cancel()
	return ex.hostRun(ctx, env, name, args...)
}

// restart restarts allowlisted units one by one and requires them active.
func (ex *executor) restart(units []string) error {
	for _, unit := range units {
		if _, err := ex.hostStep(2*time.Minute, nil, "systemctl", "restart", unit); err != nil {
			return err
		}
		out, err := ex.hostStep(10*time.Second, nil, "systemctl", "is-active", unit)
		if err != nil {
			return fmt.Errorf("%s is not active after restart: %w", unit, err)
		}
		if state := strings.TrimSpace(string(out)); state != "active" {
			return fmt.Errorf("%s is %q after restart", unit, state)
		}
	}
	return nil
}

// ---- node-deb ----

func (ex *executor) debPath(req *request, d deb) string {
	return path.Join(stateDir, req.HotfixID, "debs", d.SHA256+".deb")
}

// stageDebs downloads each deb into the hotfix state directory, or reuses a
// file with the pinned hash, and checks its control fields.
func (ex *executor) stageDebs(req *request, debs []deb) ([]string, error) {
	if err := os.MkdirAll(ex.host(path.Join(stateDir, req.HotfixID, "debs")), 0o700); err != nil {
		return nil, err
	}
	var paths []string
	for _, d := range debs {
		p := ex.debPath(req, d)
		if got, err := fileSHA256(ex.host(p)); err != nil || got != d.SHA256 {
			if err := ex.fetchToFile(d.URL, d.SHA256, ex.host(p), 1<<30); err != nil {
				return nil, err
			}
		}
		fields, err := ex.hostStep(30*time.Second, nil, "dpkg-deb", "-f", p, "Package", "Version")
		if err != nil {
			return nil, err
		}
		want := fmt.Sprintf("Package: %s\nVersion: %s", d.Package, d.Version)
		if strings.TrimSpace(string(fields)) != want {
			return nil, fmt.Errorf("%s control fields %q do not match %s %s", d.URL, strings.TrimSpace(string(fields)), d.Package, d.Version)
		}
		paths = append(paths, p)
	}
	return paths, nil
}

// installed returns the installed version of each package, "" if absent.
func (ex *executor) installed(debs []deb) (map[string]string, error) {
	versions := map[string]string{}
	for _, d := range debs {
		out, err := ex.hostStep(30*time.Second, nil, "dpkg-query", "-W", "-f=${db:Status-Abbrev} ${Version}", d.Package)
		if err != nil {
			// Only an unknown package is absent; any other failure must not
			// make rollback purge a package that was installed before.
			if strings.Contains(err.Error(), "no packages found matching") {
				versions[d.Package] = ""
				continue
			}
			return nil, err
		}
		fields := strings.Fields(string(out))
		// The second status letter is the current state; "i" is installed
		// (also for held packages, "hi"); "rc" leftovers count as absent.
		if len(fields) == 2 && len(fields[0]) >= 2 && fields[0][1] == 'i' {
			versions[d.Package] = fields[1]
		} else {
			versions[d.Package] = ""
		}
	}
	return versions, nil
}

// packageState hashes "package=version" lines in payload order.
func packageState(debs []deb, version func(deb) string) string {
	var b strings.Builder
	for _, d := range debs {
		fmt.Fprintf(&b, "%s=%s\n", d.Package, version(d))
	}
	return sum([]byte(b.String()))
}

// debPreflight refuses read-only /usr and an already broken dpkg database,
// so the plan fails instead of the apply after a change.
func (ex *executor) debPreflight(audit bool) error {
	if err := ex.recoverServiceStarts(); err != nil {
		return err
	}
	out, err := ex.hostStep(10*time.Second, nil, "findmnt", "-n", "-o", "OPTIONS", "--target", "/usr")
	if err != nil {
		return err
	}
	if slices.Contains(strings.Split(strings.TrimSpace(string(out)), ","), "ro") {
		return errors.New("/usr is read-only on this node; deb payloads are not supported here")
	}
	if !audit {
		return nil
	}
	return ex.dpkgAudit("before the change")
}

func (ex *executor) dpkgAudit(when string) error {
	out, err := ex.hostStep(time.Minute, nil, "dpkg", "--audit")
	if err != nil {
		return fmt.Errorf("dpkg --audit %s: %w", when, err)
	}
	if text := strings.TrimSpace(string(out)); text != "" {
		return fmt.Errorf("dpkg --audit reports problems %s: %s", when, truncateText(text, 300))
	}
	return nil
}

func truncateText(text string, limit int) string {
	if len(text) > limit {
		return text[:limit]
	}
	return text
}

func (ex *executor) debs(req *request) (*result, error) {
	debs := req.Payload.Debs
	current, err := ex.installed(debs)
	if err != nil {
		return nil, err
	}
	before := packageState(debs, func(d deb) string { return current[d.Package] })
	target := packageState(debs, func(d deb) string { return d.Version })
	switch req.Stage {
	case stagePlan:
		var fresh []string
		for _, d := range debs {
			if current[d.Package] == "" {
				fresh = append(fresh, d.Package)
			}
		}
		if before == target {
			return &result{Result: "planned", Action: "skip", BeforeSHA256: before, AfterSHA256: target}, nil
		}
		if err := ex.debPreflight(true); err != nil {
			return nil, err
		}
		paths, err := ex.stageDebs(req, debs)
		if err != nil {
			return nil, err
		}
		// dpkg --dry-run resolves dependencies without changing the node.
		if _, err := ex.hostStep(2*time.Minute, nil, "dpkg", append([]string{"--dry-run", "-i"}, paths...)...); err != nil {
			return nil, fmt.Errorf("dependency check failed: %w", err)
		}
		var diff strings.Builder
		for _, d := range debs {
			fmt.Fprintf(&diff, "%s: %q -> %q\n", d.Package, current[d.Package], d.Version)
		}
		return &result{Result: "planned", Action: "apply", BeforeSHA256: before, AfterSHA256: target, Diff: diff.String(), NewPackages: fresh}, nil
	case stageApply:
		if before == req.Expected.AfterSHA256 {
			return &result{Result: "skipped", BeforeSHA256: before, AfterSHA256: before}, nil
		}
		if before != req.Expected.BeforeSHA256 || target != req.Expected.AfterSHA256 {
			return nil, errors.New("installed package versions changed since the plan")
		}
		if err := ex.debPreflight(true); err != nil {
			return nil, err
		}
		paths, err := ex.stageDebs(req, debs)
		if err != nil {
			return nil, err
		}
		if err := ex.dpkgInstall(req, debs, paths, false); err != nil {
			return nil, err
		}
		if err := ex.restart(req.Payload.Restart); err != nil {
			return nil, err
		}
		return &result{Result: "applied", BeforeSHA256: before, AfterSHA256: target}, nil
	case stageRollback:
		return ex.rollbackDebs(req, before)
	}
	return nil, fmt.Errorf("unsupported stage %q", req.Stage)
}

// dpkgInstall installs debs in one transaction. policy-rc.d stops maintainer
// scripts from (re)starting services; --force-hold keeps held packages
// installable, and their holds are re-asserted afterwards.
func (ex *executor) dpkgInstall(req *request, debs []deb, paths []string, downgrade bool) error {
	if err := ex.fits(12 * time.Minute); err != nil {
		return err
	}
	held, err := ex.heldPackages(debs)
	if err != nil {
		return err
	}
	if err := ex.blockServiceStarts(req); err != nil {
		return err
	}
	args := []string{"--force-hold", "--force-confold"}
	if downgrade {
		args = append(args, "--force-downgrade")
	}
	_, installErr := ex.hostStep(10*time.Minute, []string{"DEBIAN_FRONTEND=noninteractive"}, "dpkg", append(append(args, "-i"), paths...)...)
	if err := errors.Join(installErr, ex.recoverServiceStarts(), ex.hold(held)); err != nil {
		return fmt.Errorf("%w; run dpkg --audit and dpkg --configure -a before a rollback", err)
	}
	if err := ex.dpkgAudit("after the install"); err != nil {
		return err
	}
	versions, err := ex.installed(debs)
	if err != nil {
		return err
	}
	for _, d := range debs {
		if versions[d.Package] != d.Version {
			return fmt.Errorf("%s has version %q after the install, want %q", d.Package, versions[d.Package], d.Version)
		}
	}
	return nil
}

func (ex *executor) heldPackages(debs []deb) ([]string, error) {
	var held []string
	for _, d := range debs {
		out, err := ex.hostStep(30*time.Second, nil, "dpkg-query", "-W", "-f=${Status}", d.Package)
		if err != nil && !strings.Contains(err.Error(), "no packages found matching") {
			return nil, err
		}
		if strings.HasPrefix(string(out), "hold ") {
			held = append(held, d.Package)
		}
	}
	return held, nil
}

func (ex *executor) hold(packages []string) error {
	for _, name := range packages {
		if _, err := ex.hostStep(30*time.Second, nil, "apt-mark", "hold", name); err != nil {
			return err
		}
	}
	return nil
}

const (
	policyRC       = "/usr/sbin/policy-rc.d"
	policyRCMarker = "# breakglass hotfix: no service starts during dpkg"
	// policyRCSaved keeps the previous policy-rc.d on the node, so a killed
	// executor's denial can be undone by the next hotfix run.
	policyRCSaved = stateDir + "/policy-rc.d.previous"
	policyRCNone  = stateDir + "/policy-rc.d.absent"
)

// blockServiceStarts installs a policy-rc.d that denies every service action.
// The previous state is saved on the node first.
func (ex *executor) blockServiceStarts(req *request) error {
	if err := ex.recoverServiceStarts(); err != nil {
		return err
	}
	target := ex.host(policyRC)
	if err := os.MkdirAll(ex.host(stateDir), 0o700); err != nil {
		return err
	}
	previous, readErr := os.ReadFile(target)
	switch {
	case readErr == nil:
		if err := writeSynced(ex.host(policyRCSaved), previous, 0o600); err != nil {
			return err
		}
	case os.IsNotExist(readErr):
		if err := writeSynced(ex.host(policyRCNone), nil, 0o600); err != nil {
			return err
		}
	default:
		return readErr
	}
	return writeSynced(target, []byte("#!/bin/sh\n"+policyRCMarker+"\nexit 101\n"), 0o755)
}

// recoverServiceStarts removes a policy-rc.d left by this executor and
// restores the saved previous one. It runs before and after every dpkg step.
func (ex *executor) recoverServiceStarts() error {
	target := ex.host(policyRC)
	current, err := os.ReadFile(target)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil && strings.Contains(string(current), policyRCMarker) {
		if previous, readErr := os.ReadFile(ex.host(policyRCSaved)); readErr == nil {
			if err := writeSynced(target, previous, 0o755); err != nil {
				return err
			}
		} else if err := os.Remove(target); err != nil {
			return err
		}
	}
	_ = os.Remove(ex.host(policyRCSaved))
	_ = os.Remove(ex.host(policyRCNone))
	return nil
}

// rollbackDebs reinstalls rollbackDebs, purges packages the hotfix added and
// verifies that every package is back at its pre-hotfix version.
func (ex *executor) rollbackDebs(req *request, current string) (*result, error) {
	if current == req.Expected.BeforeSHA256 {
		return &result{Result: "skipped", BeforeSHA256: current, AfterSHA256: current}, nil
	}
	if current != req.Expected.AfterSHA256 {
		return nil, errors.New("installed versions changed after the hotfix; not rolling back automatically")
	}
	if err := ex.debPreflight(false); err != nil {
		return nil, err
	}
	if len(req.Payload.RollbackDebs) != 0 {
		paths, err := ex.stageDebs(req, req.Payload.RollbackDebs)
		if err != nil {
			return nil, err
		}
		if err := ex.dpkgInstall(req, req.Payload.RollbackDebs, paths, true); err != nil {
			return nil, err
		}
	}
	for _, name := range req.Expected.NewPackages {
		if err := ex.fits(5 * time.Minute); err != nil {
			return nil, err
		}
		if err := ex.blockServiceStarts(req); err != nil {
			return nil, err
		}
		_, purgeErr := ex.hostStep(5*time.Minute, []string{"DEBIAN_FRONTEND=noninteractive"}, "dpkg", "--purge", name)
		if err := errors.Join(purgeErr, ex.recoverServiceStarts()); err != nil {
			return nil, err
		}
	}
	versions, err := ex.installed(req.Payload.Debs)
	if err != nil {
		return nil, err
	}
	if after := packageState(req.Payload.Debs, func(d deb) string { return versions[d.Package] }); after != req.Expected.BeforeSHA256 {
		return nil, errors.New("packages still differ from the pre-hotfix state after the rollback; replace the node")
	}
	if err := ex.restart(req.Payload.Restart); err != nil {
		return nil, err
	}
	return &result{Result: "rolledBack", BeforeSHA256: current, AfterSHA256: req.Expected.BeforeSHA256}, nil
}

// ---- static-pod-image ----

var imageLine = regexp.MustCompile(`(?m)^(\s*(?:- )?)image:\s*\S+\s*$`)

func manifestPath(pod string) string { return "/etc/kubernetes/manifests/" + pod + ".yaml" }

// patchImage replaces the single image line of a kubeadm static Pod manifest.
func patchImage(manifest []byte, image string) ([]byte, error) {
	matches := imageLine.FindAllSubmatchIndex(manifest, -1)
	if len(matches) != 1 {
		return nil, fmt.Errorf("manifest has %d image lines; exactly one is supported", len(matches))
	}
	m := matches[0]
	var out bytes.Buffer
	out.Write(manifest[:m[0]])
	out.Write(manifest[m[2]:m[3]])
	out.WriteString("image: " + image)
	out.Write(manifest[m[1]:])
	return out.Bytes(), nil
}

type crictlContainers struct {
	Containers []struct {
		ID       string `json:"id"`
		ImageRef string `json:"imageRef"`
	} `json:"containers"`
}

// imageID pulls nothing; it returns the local image ID of a pulled image.
func (ex *executor) imageID(image string) (string, error) {
	out, err := ex.hostStep(30*time.Second, nil, "crictl", "inspecti", "-o", "json", image)
	if err != nil {
		return "", err
	}
	var inspected struct {
		Status struct {
			ID          string   `json:"id"`
			RepoDigests []string `json:"repoDigests"`
		} `json:"status"`
	}
	if err := json.Unmarshal(out, &inspected); err != nil || inspected.Status.ID == "" {
		return "", fmt.Errorf("inspect %s: unexpected output", image)
	}
	digest := image[strings.LastIndex(image, "@"):]
	if !slices.ContainsFunc(inspected.Status.RepoDigests, func(d string) bool { return strings.HasSuffix(d, digest) }) {
		return "", fmt.Errorf("pulled image does not carry digest %s", digest)
	}
	return inspected.Status.ID, nil
}

// waitStaticPod waits until exactly the static Pod's container runs the
// image. containerd reports imageRef as the image ID or as repo@digest.
func (ex *executor) waitStaticPod(pod, id, digest string, budget time.Duration) error {
	if err := ex.fits(budget); err != nil {
		return err
	}
	end := ex.now().Add(budget)
	for {
		out, err := ex.hostStep(15*time.Second, nil, "crictl", "ps", "--name", "^"+pod+"$", "--label", staticPodLabel, "--state", "running", "-o", "json")
		var running crictlContainers
		if err == nil && json.Unmarshal(out, &running) == nil && len(running.Containers) == 1 &&
			(running.Containers[0].ImageRef == id || strings.HasSuffix(running.Containers[0].ImageRef, digest)) {
			return nil
		}
		if ex.now().After(end) {
			return fmt.Errorf("%s did not run image %s within %s", pod, id, budget)
		}
		time.Sleep(ex.poll)
	}
}

// staticPodLabel limits crictl to kube-system static Pod containers.
const staticPodLabel = "io.kubernetes.pod.namespace=kube-system"

type etcdStatus struct {
	Endpoint string `json:"Endpoint"`
	Status   struct {
		Header struct {
			MemberID uint64 `json:"member_id"`
		} `json:"header"`
		Leader uint64 `json:"leader"`
	} `json:"Status"`
}

// etcdHealthy requires every member to answer and to agree on one leader.
// Changing one member at a time then keeps quorum.
func (ex *executor) etcdHealthy() error {
	out, err := ex.hostStep(15*time.Second, nil, "crictl", "ps", "--name", "^etcd$", "--label", staticPodLabel, "--state", "running", "-q")
	if err != nil {
		return fmt.Errorf("list the local etcd container: %w", err)
	}
	ids := strings.Fields(string(out))
	if len(ids) != 1 {
		return fmt.Errorf("found %d running local etcd containers, want 1", len(ids))
	}
	etcdctl := []string{"exec", ids[0], "etcdctl", "--endpoints=https://127.0.0.1:2379",
		"--cacert=/etc/kubernetes/pki/etcd/ca.crt", "--cert=/etc/kubernetes/pki/etcd/healthcheck-client.crt",
		"--key=/etc/kubernetes/pki/etcd/healthcheck-client.key", "-w", "json"}
	members, err := ex.hostStep(30*time.Second, nil, "crictl", append(etcdctl, "member", "list")...)
	if err != nil {
		return err
	}
	var list struct {
		Members []struct {
			ID uint64 `json:"ID"`
		} `json:"members"`
	}
	if err := json.Unmarshal(members, &list); err != nil || len(list.Members) == 0 {
		return errors.New("etcd member list is unreadable")
	}
	out, err = ex.hostStep(30*time.Second, nil, "crictl", append(etcdctl, "endpoint", "status", "--cluster")...)
	if err != nil {
		return fmt.Errorf("etcd endpoint status: %w", err)
	}
	var statuses []etcdStatus
	if err := json.Unmarshal(out, &statuses); err != nil || len(statuses) == 0 {
		return errors.New("etcd endpoint status is unreadable")
	}
	answered := map[uint64]bool{}
	for _, s := range statuses {
		if s.Status.Leader == 0 || s.Status.Leader != statuses[0].Status.Leader {
			return errors.New("etcd members do not agree on one leader")
		}
		answered[s.Status.Header.MemberID] = true
	}
	for _, member := range list.Members {
		if !answered[member.ID] {
			return fmt.Errorf("etcd member %x does not answer; %d of %d answer", member.ID, len(answered), len(list.Members))
		}
	}
	return nil
}

// waitEtcdHealthy polls etcdHealthy within the budget.
func (ex *executor) waitEtcdHealthy(budget time.Duration) error {
	end := ex.now().Add(budget)
	for {
		err := ex.etcdHealthy()
		if err == nil {
			return nil
		}
		if ex.now().After(end) {
			return err
		}
		time.Sleep(ex.poll)
	}
}

func (ex *executor) staticPod(req *request) (*result, error) {
	pod := req.Payload.Image.StaticPod
	p := manifestPath(pod)
	old, info, err := ex.read(p)
	if err != nil {
		return nil, err
	}
	before := sum(old)
	updated, err := patchImage(old, req.Payload.Image.Image)
	if err != nil {
		return nil, err
	}
	after := sum(updated)
	switch req.Stage {
	case stagePlan:
		action := "apply"
		if before == after {
			action = "skip"
		}
		return &result{Result: "planned", Action: action, BeforeSHA256: before, AfterSHA256: after, Diff: ex.reviewDiff(p, old, updated)}, nil
	case stageApply:
		if before == req.Expected.AfterSHA256 {
			return &result{Result: "skipped", BeforeSHA256: before, AfterSHA256: before}, nil
		}
		if before != req.Expected.BeforeSHA256 || after != req.Expected.AfterSHA256 {
			return nil, fmt.Errorf("%s changed since the plan", p)
		}
		if pod == "etcd" {
			if err := ex.etcdHealthy(); err != nil {
				return nil, fmt.Errorf("refusing to restart an etcd member without full quorum: %w", err)
			}
		}
		// Pre-pull, so the Pod restarts without waiting for the registry.
		if _, err := ex.hostStep(5*time.Minute, nil, "crictl", "pull", req.Payload.Image.Image); err != nil {
			return nil, err
		}
		id, err := ex.imageID(req.Payload.Image.Image)
		if err != nil {
			return nil, err
		}
		if err := ex.fits(6 * time.Minute); err != nil {
			return nil, err
		}
		if err := ex.replaceFile(req, p, old, updated, info); err != nil {
			return nil, err
		}
		if err := ex.waitStaticPod(pod, id, req.Payload.Image.Image[strings.LastIndex(req.Payload.Image.Image, "@"):], 5*time.Minute); err != nil {
			return nil, err
		}
		if pod == "etcd" {
			if err := ex.waitEtcdHealthy(time.Minute); err != nil {
				return nil, err
			}
		}
		return &result{Result: "applied", BeforeSHA256: before, AfterSHA256: after}, nil
	case stageRollback:
		out, err := ex.restoreFile(req, p, before, info, nil)
		if err != nil || out.Result == "skipped" {
			return out, err
		}
		if pod == "etcd" {
			if err := ex.waitEtcdHealthy(5 * time.Minute); err != nil {
				return nil, err
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("unsupported stage %q", req.Stage)
}

// ---- host-container-image ----

func (ex *executor) hostContainer(req *request) (*result, error) {
	c := req.HostContainer
	old, info, err := ex.read(c.ImageRefFile)
	if err != nil {
		return nil, err
	}
	before := sum(old)
	updated := []byte(req.Payload.Image.Image + "\n")
	after := sum(updated)
	switch req.Stage {
	case stagePlan:
		if _, err := ex.hostStep(15*time.Second, nil, "systemctl", "cat", c.Unit); err != nil {
			return nil, fmt.Errorf("unit %s is not installed: %w", c.Unit, err)
		}
		action := "apply"
		if before == after {
			action = "skip"
		}
		return &result{Result: "planned", Action: action, BeforeSHA256: before, AfterSHA256: after, Diff: ex.reviewDiff(c.ImageRefFile, old, updated)}, nil
	case stageApply:
		if before == req.Expected.AfterSHA256 {
			return &result{Result: "skipped", BeforeSHA256: before, AfterSHA256: before}, nil
		}
		if before != req.Expected.BeforeSHA256 || after != req.Expected.AfterSHA256 {
			return nil, fmt.Errorf("%s changed since the plan", c.ImageRefFile)
		}
		if _, err := ex.hostStep(5*time.Minute, nil, "ctr", "-n", c.ContainerdNamespace, "images", "pull",
			"--hosts-dir", "/etc/containerd/certs.d", req.Payload.Image.Image); err != nil {
			return nil, err
		}
		if err := ex.fits(4 * time.Minute); err != nil {
			return nil, err
		}
		// nerdctl reports the image as it normalised it on start; keep the
		// running reference so rollback can verify the previous image. A
		// crashed container has none; a hotfix may be its repair.
		running, err := ex.runningImage(c)
		if err != nil {
			running = ""
		}
		if err := os.MkdirAll(ex.host(path.Join(stateDir, req.HotfixID)), 0o700); err != nil {
			return nil, err
		}
		if err := writeSynced(ex.host(ex.runningImagePath(req, c)), []byte(running), 0o600); err != nil {
			return nil, err
		}
		if err := ex.replaceFile(req, c.ImageRefFile, old, updated, info); err != nil {
			return nil, err
		}
		if err := ex.restartHostContainer(c, req.Payload.Image.Image); err != nil {
			return nil, err
		}
		return &result{Result: "applied", BeforeSHA256: before, AfterSHA256: after}, nil
	case stageRollback:
		out, err := ex.restoreFile(req, c.ImageRefFile, before, info, nil)
		if err != nil || out.Result == "skipped" {
			return out, err
		}
		previous, err := os.ReadFile(ex.host(ex.runningImagePath(req, c)))
		if err != nil {
			return nil, fmt.Errorf("read the image %s ran before the hotfix: %w", c.Name, err)
		}
		// An empty reference means the container was not running before the
		// hotfix; then rollback only requires it to run again.
		if err := ex.restartHostContainer(c, strings.TrimSpace(string(previous))); err != nil {
			return nil, err
		}
		return out, nil
	}
	return nil, fmt.Errorf("unsupported stage %q", req.Stage)
}

func (ex *executor) runningImagePath(req *request, c *hostContainer) string {
	return path.Join(stateDir, req.HotfixID, c.Name+".running-image")
}

// runningImage returns the image reference of the running host container.
func (ex *executor) runningImage(c *hostContainer) (string, error) {
	out, err := ex.hostStep(30*time.Second, nil, "nerdctl", "--namespace", c.ContainerdNamespace, "inspect",
		"--format", "{{.Image}} {{.State.Running}}", c.Name)
	if err != nil {
		return "", err
	}
	image, running, _ := strings.Cut(strings.TrimSpace(string(out)), " ")
	if running != "true" || image == "" {
		return "", fmt.Errorf("%s is not running (%q)", c.Name, strings.TrimSpace(string(out)))
	}
	return image, nil
}

// restartHostContainer restarts the unit and requires the container to run
// the expected image. Restarting cra-vsr interrupts the node's network.
func (ex *executor) restartHostContainer(c *hostContainer, image string) error {
	if _, err := ex.hostStep(3*time.Minute, nil, "systemctl", "restart", c.Unit); err != nil {
		return err
	}
	got, err := ex.runningImage(c)
	if err != nil {
		return err
	}
	if image != "" && got != image {
		return fmt.Errorf("%s runs %q after the restart, want %q", c.Name, got, image)
	}
	return nil
}
