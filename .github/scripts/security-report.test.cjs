// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

const assert = require('node:assert/strict');
const test = require('node:test');
const report = require('./security-report.cjs');

function fixture() {
  const posted = [];
  const pr = {
    number: 1, state: 'open', head: { sha: 'abc', repo: { id: 2 } },
    base: { repo: { full_name: 'owner/repo' } },
  };
  const data = {
    pulls: [pr], comments: [],
    runs: [{ id: 3, name: 'Security Scan' }, { id: 1, name: 'Security Scan' }],
    jobs: [{ name: 'govulncheck', conclusion: 'success', html_url: 'https://github.com/logs', check_run_url: 'https://api.github.com/checks/4' }],
    annotations: [{ title: 'Security scan advisory', message: '<ScRiPt>@someone|[finding](evil)</SCRIPT>', annotation_level: 'warning' }],
  };
  const endpoint = key => Object.assign(() => {}, { key });
  const github = {
    paginate: async (method, args) => {
      if (method.key === 'jobs') assert.equal(args.run_id, 3);
      if (method.key === 'annotations') assert.equal(args.check_run_id, 4);
      return data[method.key];
    },
    rest: {
      repos: { listPullRequestsAssociatedWithCommit: endpoint('pulls') },
      pulls: { get: async () => ({ data: pr }) },
      actions: { listWorkflowRunsForRepo: endpoint('runs'), listJobsForWorkflowRun: endpoint('jobs') },
      checks: { listAnnotations: endpoint('annotations') },
      issues: {
        listComments: endpoint('comments'),
        createComment: async args => posted.push({ method: 'create', ...args }),
        updateComment: async args => posted.push({ method: 'update', ...args }),
      },
    },
  };
  const context = {
    repo: { owner: 'owner', repo: 'repo' },
    payload: { workflow_run: { event: 'pull_request', name: 'Security Scan', head_sha: 'abc', head_repository: { id: 2 } } },
  };
  return { github, context, core: { info() {} }, data, pr, posted };
}

test('creates an escaped advisory report using the newest run', async () => {
  const f = fixture();
  await report(f);
  assert.equal(f.posted.length, 1);
  assert.equal(f.posted[0].method, 'create');
  assert.match(f.posted[0].body, /success; findings or scanner error \(advisory\)/);
  assert.match(f.posted[0].body, /&lt;ScRiPt&gt;&#64;someone&#124;&#91;finding&#93;&#40;evil&#41;&lt;\/SCRIPT&gt;/);
  assert.doesNotMatch(f.posted[0].body, /<\/?script>|@someone|\[finding\]\(evil\)/i);
  assert.match(f.posted[0].body, /licensing and REUSE checks remain blocking/);
});

test('updates only its own bot comment, preserving human comments', async () => {
  const f = fixture();
  f.data.comments = [
    { id: 8, user: { login: 'human' }, body: '<!-- security-scan-report -->' },
    { id: 9, user: { login: 'github-actions[bot]' }, body: '<!-- security-scan-report --> old' },
  ];
  await report(f);
  assert.equal(f.posted[0].method, 'update');
  assert.equal(f.posted[0].comment_id, 9);
});

test('accepts the separately completed dependency review workflow', async () => {
  const f = fixture();
  f.context.payload.workflow_run.name = 'Dependency Review';
  await report(f);
  assert.equal(f.posted.length, 1);
});

test('ignores stale, closed, foreign and mismatched-head reports', async () => {
  for (const change of [
    f => { f.pr.head.sha = 'new'; },
    f => { f.pr.state = 'closed'; },
    f => { f.pr.base.repo.full_name = 'other/repo'; },
    f => { f.pr.head.repo.id = 99; },
    f => { f.pr.head.repo = null; },
    f => { f.context.payload.workflow_run.head_repository = null; },
    f => { f.context.payload.workflow_run.event = 'push'; },
    f => { f.context.payload.workflow_run.name = 'Other'; },
  ]) {
    const f = fixture();
    change(f);
    await report(f);
    assert.equal(f.posted.length, 0);
  }
});

test('does not claim a running scanner succeeded', async () => {
  const f = fixture();
  f.data.jobs[0].conclusion = null;
  f.data.jobs[0].status = 'in_progress';
  f.data.annotations = [];
  await report(f);
  assert.match(f.posted[0].body, /in_progress/);
});

test('retains blocking license failures alongside scan warnings', async () => {
  const f = fixture();
  f.data.jobs[0].conclusion = 'failure';
  f.data.jobs.push({ name: 'Dependency License Audit', conclusion: 'failure', html_url: 'https://github.com/license-logs' });
  await report(f);
  assert.match(f.posted[0].body, /failure; findings or scanner error \(advisory\)/);
  assert.match(f.posted[0].body, /\| Dependency License Audit \| failure \|/);
});

test('does not post when the PR advances during report generation', async () => {
  const f = fixture();
  let calls = 0;
  f.github.rest.pulls.get = async () => ({ data: ++calls === 1 ? f.pr : { ...f.pr, head: { sha: 'new' } } });
  await report(f);
  assert.equal(f.posted.length, 0);
});
