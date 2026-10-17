"""Authenticate complete Actions campaigns before interpreting their artifacts.

Job success is an admission prerequisite. The Go evidence verifier independently
checks original plans, streams, source cases and native output identities.
"""
import re
import subprocess

from reference_sources import sources
from release_assets import require

PROOF_STEPS = frozenset(('Retain required case execution evidence',
                         'Retain required capture execution evidence'))
FULL_NATIVE_GATE = 'Require all filesystem compatibility checks'
REFRESH_TITLE = 'Independent Apple reference refresh'


def refresh_for_completion(client, run_id):
    """Either complete rail can finish last; both must reference the same SHA."""
    require(re.fullmatch('[1-9][0-9]*', str(run_id)), 'explicit completed workflow run required')
    root = f'/repos/{client.repository}'
    completed = client.request(root + f'/actions/runs/{run_id}')
    require(completed['repository']['full_name'] == client.repository and
            completed['head_repository']['full_name'] == client.repository and
            completed['head_branch'] == 'main' and completed['status'] == 'completed' and
            completed['conclusion'] == 'success', 'untrusted/incomplete publication trigger')
    if completed['path'] == '.github/workflows/native.yml':
        return completed['id'] if completed['display_title'] == REFRESH_TITLE else None
    require(completed['path'] == '.github/workflows/ci.yml', 'unknown publication completion trigger')
    native = client.pages(root + '/actions/workflows/native.yml/runs', field='workflow_runs',
                           parameters={'head_sha': completed['head_sha'], 'branch': 'main', 'status': 'completed'})
    eligible = [r for r in native if r['head_sha'] == completed['head_sha'] and
                r['head_branch'] == 'main' and r['conclusion'] == 'success' and
                r['display_title'] == REFRESH_TITLE and r['event'] in ('workflow_dispatch', 'schedule')]
    return max((r['id'] for r in eligible), default=None)


def capture_artifacts():
    return sorted({spec['artifact'].format(major=major)
                   for spec in sources().values() for major in (15, 26, 27)})


def authenticated_checkout(client, run, revision):
    """Bind the receipt's real checkout to its original run; grant no verdict.

    Actions reports a PR head SHA while checkout normally tests its synthetic
    merge. After merging, run.pull_requests can become empty. Associated closed
    PRs retain the original base/head pair; never rewrite a receipt to the head.
    """
    require(run['repository']['full_name'] == client.repository and
            run['head_repository']['full_name'] == client.repository and
            re.fullmatch('[a-f0-9]{40}', revision or '') and
            re.fullmatch('[a-f0-9]{40}', run['head_sha'] or ''), 'untrusted checkout origin')
    require(run['event'] in ('push', 'workflow_dispatch', 'schedule', 'pull_request'),
            'unknown checkout event requires fresh qualification')
    root = f'/repos/{client.repository}'
    commit = client.request(root + '/git/commits/' + revision)
    require(commit['sha'] == revision and re.fullmatch('[a-f0-9]{40}', commit['tree']['sha']),
            'tested commit/tree identity differs')
    binding, pull = 'run-head', None
    if revision != run['head_sha']:
        parents = [p['sha'] for p in commit['parents']]
        require(run['event'] == 'pull_request' and len(parents) == 2 and parents[1] == run['head_sha'],
                'tested checkout is not this run head or its pull-request merge')
        associated = run.get('pull_requests') or client.pages(root + '/commits/' + run['head_sha'] + '/pulls')
        matches = [p for p in associated if p['head']['sha'] == parents[1] and p['base']['sha'] == parents[0]]
        require(len(matches) == 1, 'original pull-request base/head association missing or ambiguous')
        pull = matches[0]
        # The synthetic commit is made by GitHub, not an arbitrary same-parent
        # commit supplied by a caller. Keep its original API proof permanently.
        require(commit['verification']['verified'] is True and
                commit['committer']['email'] == 'noreply@github.com',
                'pull-request merge lacks GitHub checkout verification')
        binding = 'pull-request-merge'
    return {'schema': 1, 'run_head_sha': run['head_sha'], 'tested_revision': revision,
            'tree_sha': commit['tree']['sha'], 'binding': binding, 'commit': commit,
            'pull_request': pull}


def inspect_campaign(client, run_id):
    require(re.fullmatch('[1-9][0-9]*', str(run_id)), 'explicit native campaign run required')
    root = f'/repos/{client.repository}'
    run = client.request(root + f'/actions/runs/{run_id}')
    require(run['id'] == int(run_id) and run['repository']['full_name'] == client.repository and
            run['head_repository']['full_name'] == client.repository and run['head_branch'] == 'main' and
            run['path'] == '.github/workflows/native.yml' and run['event'] in ('workflow_dispatch', 'schedule'),
            'reference publication requires a trusted default-branch native campaign')
    require(run['status'] == 'completed' and run['conclusion'] == 'success',
            'native reference campaign is incomplete or failed')
    revision, attempt = run['head_sha'], run['run_attempt']
    require(re.fullmatch('[a-f0-9]{40}', revision) and type(attempt) is int and attempt > 0,
            'native campaign revision/attempt missing')
    jobs = client.pages(root + f'/actions/runs/{run_id}/attempts/{attempt}/jobs', field='jobs')
    gates = [j for j in jobs if j['name'] == FULL_NATIVE_GATE]
    require(len(gates) == 1 and gates[0]['status'] == 'completed' and gates[0]['conclusion'] == 'success',
            'the complete native compatibility gate did not pass')
    proof_jobs = [j for j in jobs if any(step['name'] in PROOF_STEPS for step in j.get('steps', []))]
    require(proof_jobs and all(j['status'] == 'completed' and j['conclusion'] == 'success' and
            sum(s['name'] in PROOF_STEPS and s['conclusion'] == 'success' for s in j['steps']) == 1
            for j in proof_jobs), 'required native execution artifacts were not retained')
    artifacts = client.pages(root + f'/actions/runs/{run_id}/artifacts', field='artifacts')
    by_name = {}
    for artifact in artifacts:
        require(artifact['name'] not in by_name, 'ambiguous Actions artifact name')
        by_name[artifact['name']] = artifact
    names = capture_artifacts()
    proof = sorted(name for name in by_name if name.startswith('qualification-'))
    require(len(proof) == len(proof_jobs), 'native execution artifact inventory differs from completed jobs')
    for name in [*names, *proof]:
        artifact = by_name.get(name)
        require(artifact and not artifact['expired'] and artifact['size_in_bytes'] > 0 and
                artifact['workflow_run']['id'] == int(run_id) and
                artifact['workflow_run']['head_sha'] == revision,
                'required original capture/execution artifact missing, expired or mismatched: ' + name)
    candidates = client.pages(root + '/actions/workflows/ci.yml/runs', field='workflow_runs',
                              parameters={'head_sha': revision, 'branch': 'main', 'status': 'completed'})
    successful = [r for r in candidates if r['head_sha'] == revision and r['head_branch'] == 'main' and
                  r['status'] == 'completed' and r['conclusion'] == 'success' and
                  r['repository']['full_name'] == client.repository and
                  r['head_repository']['full_name'] == client.repository and
                  r['event'] in ('push', 'workflow_dispatch') and r['path'] == '.github/workflows/ci.yml']
    if not successful:
        return {'state': 'waiting-for-ci', 'native': run, 'jobs': jobs, 'artifacts': artifacts}
    ci = max(successful, key=lambda r: r['id'])
    source = authenticated_checkout(client, run, revision)
    return {'state': 'ready', 'origin': {'repository': client.repository, 'revision': revision,
            'run': str(run_id), 'attempt': str(attempt), 'completed_at': run['updated_at']},
            'native': run, 'ci': ci, 'jobs': jobs, 'artifacts': artifacts, 'source': source,
            'captures': names, 'proof': proof}


def download_campaign(repository, run_id, captures, proof, directory, run=subprocess.run):
    """Names and run are selected by the authenticated complete API inventory."""
    require(re.fullmatch('[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository) and
            re.fullmatch('[1-9][0-9]*', str(run_id)), 'explicit artifact origin required')
    for names, target in ((captures, directory / 'captures'), (proof, directory / 'evidence')):
        require(names and len(names) == len(set(names)), 'empty/duplicate original artifact set')
        command = ['gh', 'run', 'download', str(run_id), '--repo', repository, '--dir', str(target)]
        for name in names:
            require(re.fullmatch('[A-Za-z0-9_-]+', name), 'unsafe/unreviewed Actions artifact name')
            command += ['--name', name]
        run(command, check=True)
