// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { after, test } from 'node:test';
import { pathToFileURL } from 'node:url';

assert.ok(process.env.RENOVATE_PACKAGE_DIR, 'Set RENOVATE_PACKAGE_DIR to the pinned Renovate installation');
const load = relative => import(pathToFileURL(path.join(process.env.RENOVATE_PACKAGE_DIR, 'dist', relative)));
const { init } = await load('logger/index.js');
await init();
const { GlobalConfig } = await load('config/global.js');
const { extractPackageFile } = await load('modules/manager/custom/regex/index.js');
const { doAutoReplace } = await load('workers/repository/update/branch/auto-replace.js');
const { applyPackageRules } = await load('util/package-rules/index.js');
const config = JSON.parse(await fs.readFile('.github/renovate.json', 'utf8'));
const [toolManager, packageManager] = config.customManagers;
const sandbox = await fs.mkdtemp(path.join(os.tmpdir(), 'dependency-updates-'));
GlobalConfig.set({ localDir: sandbox, cacheDir: sandbox, platform: 'local' });
after(() => fs.rm(sandbox, { recursive: true, force: true }));

const extract = (contents, fileName, manager = toolManager) => extractPackageFile(contents, fileName, manager).deps;

test('extracts complete Go module versions after versioned package paths', () => {
  const input = '# renovate: datasource=go depName=github.com/google/go-licenses/v2\n' +
    'run: go install github.com/google/go-licenses/v2@v2.0.1\n';
  const deps = extract(input, 'security.yml');
  assert.equal(deps.length, 1);
  assert.equal(deps[0].depName, 'github.com/google/go-licenses/v2');
  assert.equal(deps[0].currentValue, 'v2.0.1');
});

test('extracts tagged tool versions, image digests, and release prereleases without truncation', () => {
  const input = '# renovate: datasource=github-releases depName=kubernetes-sigs/kind\n' +
    'KIND_VERSION=v0.32.0\n' +
    '# renovate: datasource=docker depName=kindest/node versioning=docker\n' +
    'KIND_NODE_IMAGE=kindest/node:v1.36.1@sha256:' + 'a'.repeat(64) + '\n' +
    '# renovate: datasource=github-releases depName=renovatebot/renovate\n' +
    'RENOVATE_VERSION=44.176.3';
  const deps = extract(input, 'pins.env');
  assert.deepEqual(deps.map(dep => [dep.depName, dep.currentValue]), [
    ['kubernetes-sigs/kind', 'v0.32.0'],
    ['kindest/node', 'v1.36.1'],
    ['renovatebot/renovate', '44.176.3'],
  ]);
  assert.equal(deps[1].currentDigest, `sha256:${'a'.repeat(64)}`);
});

test('preserves full Debian package revisions including epochs and suffixes', () => {
  const input = '# renovate: datasource=deb depName=clang versioning=deb\n' +
    'ARG CLANG_VERSION=1:19.0-63\n' +
    '# renovate: datasource=deb depName=bison versioning=deb\n' +
    'BISON_VERSION=2:3.8.2+dfsg-1+b2';
  const deps = extract(input, 'versions.env', packageManager);
  assert.deepEqual(deps.map(dep => [dep.depName, dep.currentValue]), [
    ['clang', '1:19.0-63'],
    ['bison', '2:3.8.2+dfsg-1+b2'],
  ]);
});

test('extracts exact APK and Debian revisions from fixed package fixtures', () => {
  const lock = '# renovate: datasource=repology depName=alpine_3_24/ethtool versioning=loose\nethtool=7.0-r0\n';
  const dockerfile = '# renovate: datasource=deb depName=flex versioning=deb\nARG FLEX_VERSION=2.6.4-8.2+b4\n' +
    '# renovate: datasource=deb depName=bison versioning=deb\nARG BISON_VERSION=2:3.8.2+dfsg-1+b2\n';
  const alpine = extract(lock, 'fixture.lock', packageManager);
  const debian = extract(dockerfile, 'Dockerfile', packageManager);
  assert.equal(alpine.find(dep => dep.depName.endsWith('/ethtool'))?.currentValue, '7.0-r0');
  assert.equal(debian.find(dep => dep.depName === 'flex')?.currentValue, '2.6.4-8.2+b4');
  assert.equal(debian.find(dep => dep.depName === 'bison')?.currentValue, '2:3.8.2+dfsg-1+b2');
});

test('binary Debian pins resolve against the explicit distribution and preserve full revisions during updates', async () => {
  const original = '# renovate: datasource=deb depName=clang versioning=deb\nCLANG_VERSION=1:19.0-63\n';
  const dep = extract(original, 'debian.env', packageManager)[0];
  const resolved = await applyPackageRules({
    ...dep, packageRules: config.packageRules, manager: 'custom.regex', packageName: dep.depName,
  }, 'Debian binary package lookup');
  assert.equal(resolved.versioning, 'deb');
  assert.deepEqual(resolved.registryUrls, ['https://deb.debian.org/debian?suite=trixie&components=main&binaryArch=amd64']);
  assert.equal(resolved.dependencyDashboardApproval, true);
  const updated = await doAutoReplace({
    ...packageManager, ...dep, manager: 'regex', depIndex: 0, packageFile: 'debian.env',
    newValue: '1:20.0-1+b2',
  }, original, false);
  assert.equal(updated, original.replace('1:19.0-63', '1:20.0-1+b2'));
});

test('the real updater replaces duplicate immutable image references as a coordinated change', async () => {
  const oldDigest = `sha256:${'a'.repeat(64)}`;
  const newDigest = `sha256:${'b'.repeat(64)}`;
  const files = new Map([
    ['first.yml', `# renovate: datasource=docker depName=kindest/node versioning=docker\nIMAGE=kindest/node:v1.36.1@${oldDigest}\n`],
    ['second.sh', `# renovate: datasource=docker depName=kindest/node versioning=docker\nIMAGE=kindest/node:v1.36.1@${oldDigest}\n`],
  ]);
  for (const [fileName, original] of files) {
    const dep = extract(original, fileName)[0];
    assert.equal(dep.currentValue, 'v1.36.1');
    assert.equal(dep.currentDigest, oldDigest);
    const updated = await doAutoReplace({
      ...toolManager, ...dep, manager: 'regex', depIndex: 0, packageFile: fileName,
      newValue: 'v1.36.2', newDigest,
    }, original, false);
    assert.equal(updated, original.replace(`v1.36.1@${oldDigest}`, `v1.36.2@${newDigest}`));
    assert.equal(await fs.readFile(path.join(sandbox, fileName), 'utf8'), updated);
  }
});

test('package rules leave ordinary Go modules with Dependabot and re-enable only Go version and OPA', async () => {
  for (const [depType, packageName, datasource, enabled] of [
    ['', '@tsconfig/node22', 'npm', false],
    ['require', 'k8s.io/client-go', 'go', false],
    ['golang', 'go', 'golang-version', true],
    ['indirect', 'github.com/open-policy-agent/frameworks/constraint', 'go', true],
  ]) {
    const resolved = await applyPackageRules({
      packageRules: config.packageRules, manager: packageName === '@tsconfig/node22' ? 'custom.regex' : 'gomod', depType,
      packageName, depName: packageName, datasource,
    }, 'dependency ownership test');
    assert.equal(resolved.enabled, enabled, `${depType} ${packageName}`);
    if (depType === 'golang') {
      assert.equal(resolved.rangeStrategy, 'bump');
      assert.equal(resolved.allowedVersions, '<1.28.0');
    }
  }
});

test('the real updater replaces a fixed validator version fixture', async () => {
  const workflow = '# renovate: datasource=github-releases depName=renovatebot/renovate\n' +
    'run: npm install --prefix "$RUNNER_TEMP/renovate" --no-audit --no-fund renovate@44.176.3\n';
  const dep = extract(workflow, 'validator.yml')[0];
  assert.equal(dep.currentValue, '44.176.3');
  const updated = await doAutoReplace({
    ...toolManager, ...dep, manager: 'regex', depIndex: 0, packageFile: 'validator.yml',
    newValue: '44.176.4',
  }, workflow, false);
  assert.equal(updated, workflow.replace('renovate@44.176.3', 'renovate@44.176.4'));
  assert.equal(await fs.readFile(path.join(sandbox, 'validator.yml'), 'utf8'), updated);
});

test('requires dashboard approval for package revisions and checksum-coupled source pins', async () => {
  for (const [datasource, packageName] of [
    ['repology', 'alpine_3_24/bash'],
    ['deb', 'clang'],
    ['github-releases', 'cilium/pwru'],
    ['github-releases', 'kastenhq/kubestr'],
    ['github-releases', 'kubernetes-sigs/kind'],
  ]) {
    const resolved = await applyPackageRules({
      packageRules: config.packageRules, manager: 'custom.regex', datasource,
      packageName, depName: packageName,
    }, 'dashboard approval test');
    assert.equal(resolved.dependencyDashboardApproval, true, `${datasource} ${packageName}`);
  }
});

test('the native Go datasource resolves the OPA submodule from the Go proxy', { timeout: 90000 }, async () => {
  const module = 'github.com/open-policy-agent/frameworks/constraint';
  const response = await fetch(`https://proxy.golang.org/${module}/@latest`, { signal: AbortSignal.timeout(30000) });
  assert.equal(response.status, 200);
  const latest = await response.json();
  const { getPkgReleases } = await load('modules/datasource/index.js');
  const result = await getPkgReleases({ datasource: 'go', packageName: module, versioning: 'semver' });
  assert.ok(result?.releases.some(release => release.version === latest.Version), 'Renovate must use the Go proxy module version');
});
