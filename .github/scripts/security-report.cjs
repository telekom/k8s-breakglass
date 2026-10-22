// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

const marker = '<!-- security-scan-report -->';
const workflows = new Set(['Security Scan', 'Dependency Review']);
const escape = value => Array.from(String(value), character => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '@': '&#64;', '|': '&#124;',
  '`': '&#96;', '\\': '&#92;', '[': '&#91;', ']': '&#93;',
  '(': '&#40;', ')': '&#41;', '*': '&#42;', '_': '&#95;', '!': '&#33;',
  '\r': ' ', '\n': ' ', '\t': ' ',
}[character] ?? character)).join('');

module.exports = async ({ github, context, core }) => {
  const source = context.payload.workflow_run;
  if (source.event !== 'pull_request' || !workflows.has(source.name)) return;
  const repo = context.repo;
  const pulls = await github.paginate(github.rest.repos.listPullRequestsAssociatedWithCommit, {
    ...repo, commit_sha: source.head_sha, per_page: 100,
  });

  for (const candidate of pulls) {
    const { data: pr } = await github.rest.pulls.get({ ...repo, pull_number: candidate.number });
    if (pr.state !== 'open' || pr.head.sha !== source.head_sha ||
        !pr.head.repo || !source.head_repository ||
        pr.base.repo.full_name !== `${repo.owner}/${repo.repo}` ||
        pr.head.repo.id !== source.head_repository.id) continue;

    const runs = await github.paginate(github.rest.actions.listWorkflowRunsForRepo, {
      ...repo, event: 'pull_request', head_sha: pr.head.sha, per_page: 100,
    });
    const latest = new Map();
    for (const run of runs) {
      if (workflows.has(run.name) && (!latest.has(run.name) || latest.get(run.name).id < run.id)) {
        latest.set(run.name, run);
      }
    }

    const rows = [];
    const notices = [];
    for (const run of latest.values()) {
      const jobs = await github.paginate(github.rest.actions.listJobsForWorkflowRun, {
        ...repo, run_id: run.id, filter: 'latest', per_page: 100,
      });
      for (const job of jobs) {
        const annotations = job.check_run_url
          ? await github.paginate(github.rest.checks.listAnnotations, {
            ...repo, check_run_id: Number(new URL(job.check_run_url).pathname.split('/').pop()), per_page: 100,
          }) : [];
        const advisory = annotations.some(annotation => annotation.title === 'Security scan advisory');
        const result = `${job.conclusion || job.status}${advisory ? '; findings or scanner error (advisory)' : ''}`;
        rows.push(`| ${escape(job.name)} | ${result} | [Logs](${job.html_url}) |`);
        for (const annotation of annotations) {
          if (annotation.annotation_level !== 'notice' && notices.length < 8) {
            notices.push(`<pre>${escape(`${job.name}: ${annotation.message}`).slice(0, 1500)}</pre>`);
          }
        }
      }
    }

    const body = [
      marker, '## Security scan report', `Commit: \`${pr.head.sha}\``,
      'Security findings are advisory, not merge blockers. Build, test, lint, licensing and REUSE checks remain blocking.',
      'A successful job is not proof of a clean scan; findings and scanner errors are called out below.',
      '| Check | Result | Details |', '| --- | --- | --- |',
      ...(rows.length ? rows : ['| No scan jobs were reported | unavailable | See workflow logs |']),
      ...notices, 'See the linked logs for complete findings and scanner setup failures.',
    ].join('\n\n').replace(/\|\n\n\|/g, '|\n|');
    const comments = await github.paginate(github.rest.issues.listComments, {
      ...repo, issue_number: pr.number, per_page: 100,
    });
    const previous = comments.find(comment =>
      comment.user.login === 'github-actions[bot]' && comment.body?.startsWith(marker));
    const { data: current } = await github.rest.pulls.get({ ...repo, pull_number: pr.number });
    if (current.state !== 'open' || current.head.sha !== source.head_sha) {
      core.info('Skipping a stale security report.');
      continue;
    }
    if (previous) {
      await github.rest.issues.updateComment({ ...repo, comment_id: previous.id, body });
    } else {
      await github.rest.issues.createComment({ ...repo, issue_number: pr.number, body });
    }
  }
};
