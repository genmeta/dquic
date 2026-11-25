const marker = '<!-- dquic-interop -->';

async function findPullRequest(github, context) {
  const run = context.payload.workflow_run;
  if (run.event !== 'pull_request') return;
  // workflow_run.pull_requests can be empty for fork PRs.
  const pulls = await github.paginate(github.rest.repos.listPullRequestsAssociatedWithCommit, {
    ...context.repo, commit_sha: run.head_sha, per_page: 100,
  });
  return pulls.find((pr) => pr.state === 'open' && pr.head.sha === run.head_sha &&
    pr.base.ref === 'main' &&
    pr.base.repo.full_name === `${context.repo.owner}/${context.repo.repo}` &&
    pr.title.toLowerCase().includes('[interop]'));
}

async function publishReport(github, context, report) {
  const pr = await findPullRequest(github, context);
  if (!pr) return;
  const run = context.payload.workflow_run;
  const comments = await github.paginate(github.rest.issues.listComments, {
    ...context.repo, issue_number: pr.number, per_page: 100,
  });
  const comment = comments.find((entry) => entry.user.login === 'github-actions[bot]' &&
    entry.body?.startsWith(marker));
  const previous = comment?.body.match(/<!-- run:(\d+) attempt:(\d+) -->/);
  if (previous && (Number(previous[1]) > run.id ||
      (Number(previous[1]) === run.id && Number(previous[2]) > run.run_attempt))) return;
  const body = `${marker}\n<!-- run:${run.id} attempt:${run.run_attempt} -->\n${report}`;
  if (comment) {
    await github.rest.issues.updateComment({...context.repo, comment_id: comment.id, body});
  } else {
    await github.rest.issues.createComment({...context.repo, issue_number: pr.number, body});
  }
}

async function prepareReport(github, context) {
  const pr = await findPullRequest(github, context);
  if (!pr) return;
  const jobs = await github.paginate(github.rest.actions.listJobsForWorkflowRun, {
    ...context.repo, run_id: context.payload.workflow_run.id, per_page: 100,
  });
  // An ignored body edit creates a skipped run, not a new set of test results.
  if (jobs.every((job) => job.conclusion === 'skipped')) return;
  return {pr, jobs};
}

module.exports = {findPullRequest, prepareReport, publishReport};
