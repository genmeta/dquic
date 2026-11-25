const assert = require('node:assert/strict');
const {test} = require('node:test');
const {findPullRequest, prepareReport, publishReport} = require('./comment.cjs');

function fixture() {
  const run = {id: 12, run_attempt: 1, head_sha: 'abc', event: 'pull_request'};
  const pr = {number: 840, state: 'open', title: '[interop] test',
    head: {sha: 'abc'}, base: {ref: 'main', repo: {full_name: 'genmeta/dquic'}}};
  const calls = [];
  const comments = [];
  const jobs = [];
  const github = {
    rest: {
      repos: {listPullRequestsAssociatedWithCommit: 'pulls'},
      actions: {listJobsForWorkflowRun: 'jobs'},
      issues: {
        listComments: 'comments',
        createComment: async (args) => calls.push(['create', args]),
        updateComment: async (args) => calls.push(['update', args]),
      },
    },
    paginate: async (endpoint) => endpoint === 'pulls' ? [pr] : endpoint === 'jobs' ? jobs : comments,
  };
  const context = {repo: {owner: 'genmeta', repo: 'dquic'}, payload: {workflow_run: run}};
  return {run, pr, calls, comments, jobs, github, context};
}

test('finds fork PRs through commit association even without run.pull_requests', async () => {
  const f = fixture();
  f.pr.head.repo = {full_name: 'contributor/dquic'};
  assert.equal((await findPullRequest(f.github, f.context)).number, 840);
});

test('skips obsolete commits, unmarked titles, closed PRs and other base repos', async () => {
  for (const change of [
    (f) => f.pr.head.sha = 'new',
    (f) => f.pr.title = 'test',
    (f) => f.pr.state = 'closed',
    (f) => f.pr.base.repo.full_name = 'someone/dquic',
    (f) => f.run.event = 'push',
  ]) {
    const f = fixture();
    change(f);
    await publishReport(f.github, f.context, 'results');
    assert.equal(f.calls.length, 0);
  }
});

test('creates one marked comment and updates the existing bot comment', async () => {
  const f = fixture();
  await publishReport(f.github, f.context, 'first');
  assert.equal(f.calls[0][0], 'create');
  const body = f.calls[0][1].body;
  assert.ok(body.includes('run:12 attempt:1'));
  f.comments.push({id: 4, body, user: {login: 'a-user'}});
  f.comments.push({id: 5, body, user: {login: 'github-actions[bot]'}});
  await publishReport(f.github, f.context, 'updated');
  assert.equal(f.calls[1][0], 'update');
  assert.equal(f.calls[1][1].comment_id, 5);
  assert.ok(f.calls[1][1].body.endsWith('updated'));
});

test('older runs and older attempts cannot overwrite newer comments', async () => {
  for (const stamp of ['run:13 attempt:1', 'run:12 attempt:2']) {
    const f = fixture();
    f.comments.push({id: 5, body: `<!-- dquic-interop -->\n<!-- ${stamp} -->\nnewer`,
      user: {login: 'github-actions[bot]'}});
    await publishReport(f.github, f.context, 'older');
    assert.equal(f.calls.length, 0);
  }
});

test('body-edit runs with skipped jobs do not replace actual test results', async () => {
  const f = fixture();
  f.jobs.push({name: 'image', conclusion: 'skipped'}, {name: 'regression', conclusion: 'skipped'});
  assert.equal(await prepareReport(f.github, f.context), undefined);
  f.jobs.length = 0;
  assert.equal(await prepareReport(f.github, f.context), undefined);
});

test('build failures still produce a report even without interop results', async () => {
  const f = fixture();
  f.jobs.push({name: 'image', conclusion: 'failure'}, {name: 'interop', conclusion: 'skipped'});
  const report = await prepareReport(f.github, f.context);
  assert.equal(report.pr.number, 840);
  assert.equal(report.jobs[0].conclusion, 'failure');
});
