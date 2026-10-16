"""Reuse complete CI evidence for identical merged content, or execute CI fully.

This controller changes no assertion scope and invokes no Apple tools. Its API
checks authenticate the original workflow and uploads; Go independently verifies
the original plans, events, input bindings and actual build identities.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess

from reference_campaign import authenticated_checkout
from release_assets import GitHub, require


PROOF_STEP = 'Retain required case execution evidence'
JOB_NAMES = {'portable': 'Portable tests (', 'offline_retained': 'Retained offline editing (',
             'portable_acceptance': 'Retained acceptance (', 'race_acceptance': 'Acceptance race checks ('}


def choose(client, revision, now):
    require(re.fullmatch('[a-f0-9]{40}', revision), 'explicit current merge revision required')
    root = f'/repos/{client.repository}'
    pulls = client.pages(root + '/commits/' + revision + '/pulls')
    merged = [p for p in pulls if p.get('merged_at') and p['merge_commit_sha'] == revision and
              p['head']['repo']['full_name'] == client.repository and p['base']['ref'] == 'main']
    if len(merged) != 1:
        return None
    head = merged[0]['head']['sha']
    runs = client.pages(root + '/actions/workflows/ci.yml/runs', field='workflow_runs',
                        parameters={'head_sha': head, 'event': 'pull_request', 'status': 'completed'})
    eligible = [r for r in runs if r['head_sha'] == head and r['event'] == 'pull_request' and
                r['path'] == '.github/workflows/ci.yml' and r['status'] == 'completed' and
                r['conclusion'] == 'success' and r['repository']['full_name'] == client.repository and
                r['head_repository']['full_name'] == client.repository and
                0 <= (now - datetime.fromisoformat(r['updated_at'].replace('Z', '+00:00'))).total_seconds() <= 86400]
    return max(eligible, key=lambda r: r['id']) if eligible else None


def host(labels):
    choices = set()
    for label in labels:
        if label.startswith('ubuntu-'): choices.add('linux')
        elif label.startswith(('macos-', 'xcode-')): choices.add('darwin')
        elif label.startswith('windows-'): choices.add('windows')
    require(len(choices) == 1, 'original CI host labels are missing or ambiguous')
    return choices.pop()


def inspect(client, run):
    root = f'/repos/{client.repository}'
    attempt = run['run_attempt']
    require(type(attempt) is int and attempt > 0, 'original CI attempt missing')
    jobs = client.pages(root + f'/actions/runs/{run["id"]}/attempts/{attempt}/jobs', field='jobs')
    require(jobs and all(j['status'] == 'completed' and j['conclusion'] in ('success', 'skipped') for j in jobs),
            'original CI job inventory is incomplete or unsuccessful')
    for name in ('quality', 'Source and native verifier checks', 'Library race checks',
                 'Cross-build Linux, macOS and Windows on amd64 and arm64'):
        require(sum(j['name'] == name and j['conclusion'] == 'success' for j in jobs) == 1,
                'original complete CI gate or non-receipt check missing: ' + name)
    proof_jobs = [j for j in jobs if any(s['name'] == PROOF_STEP for s in j.get('steps', []))]
    require(proof_jobs and all(j['conclusion'] == 'success' and
            sum(s['name'] == PROOF_STEP and s['conclusion'] == 'success' for s in j['steps']) == 1
            for j in proof_jobs), 'original CI case evidence was not retained')
    artifacts = client.pages(root + f'/actions/runs/{run["id"]}/artifacts', field='artifacts')
    proof = [a for a in artifacts if a['name'].startswith('qualification-ci-')]
    require(len(proof) == len(proof_jobs) and len({a['name'] for a in proof}) == len(proof),
            'original CI proof artifact inventory differs from successful upload jobs')
    for artifact in proof:
        require(not artifact['expired'] and artifact['size_in_bytes'] > 0 and
                artifact['workflow_run']['id'] == run['id'] and
                artifact['workflow_run']['head_sha'] == run['head_sha'] and
                re.fullmatch('qualification-ci-[a-z_]+-[0-9]+', artifact['name']),
                'original CI proof artifact expired or belongs to another run')
    return jobs, sorted(proof, key=lambda a: a['name'])


def qualify(client, run, tree, workspace, execute=subprocess.run):
    jobs, artifacts = inspect(client, run)
    workspace = Path(workspace).absolute()
    require(not workspace.exists(), 'absent managed CI inheritance scratch required')
    workspace.mkdir(parents=True)
    evidence = workspace / 'evidence'
    download = evidence / artifacts[0]['name'] if len(artifacts) == 1 else evidence
    command = ['gh', 'run', 'download', str(run['id']), '--repo', client.repository, '--dir', str(download)]
    for artifact in artifacts:
        command += ['--name', artifact['name']]
    execute(command, check=True)
    revisions = set()
    declared = []
    for artifact in artifacts:
        match = re.fullmatch('qualification-ci-([a-z_]+)-([0-9]+)', artifact['name'])
        require(match[1] in JOB_NAMES, 'unknown CI execution family requires a fresh campaign')
        directory = evidence / artifact['name']
        records = list(directory.rglob('receipt.json'))
        require(records, 'original required CI receipt missing')
        systems = set()
        for path in records:
            require(not path.is_symlink() and path.stat().st_size <= 32 << 20, 'invalid CI receipt member')
            record = json.loads(path.read_text())
            revisions.add(record['origin']['revision'])
            systems.add(record['plan']['environment']['os'])
        require(len(systems) == 1, 'CI artifact has ambiguous original execution hosts')
        # Native labels independently establish the expected host set; every
        # returned record is still checked against its exact Go plan below.
        actual = systems.pop()
        require(actual in {host(j['labels']) for j in jobs if j['name'].startswith(JOB_NAMES[match[1]]) and
                any(s['name'] == PROOF_STEP for s in j.get('steps', []))},
                'original receipt host has no successful CI executor')
        declared.append({'name': artifact['name'], 'job': match[1], 'host': actual})
    require(len(revisions) == 1, 'CI campaign used inconsistent tested checkouts')
    tested = revisions.pop()
    source = authenticated_checkout(client, run, tested)
    require(source['tree_sha'] == tree, 'prior CI tested different merged contents')
    origin = {'repository': client.repository, 'revision': tested, 'run': str(run['id']),
              'attempt': str(run['run_attempt']), 'completed_at': run['updated_at']}
    document = {'schema': 1, 'origin': origin, 'tree_sha': tree, 'artifacts': declared}
    origin_path = workspace / 'origin.json'
    origin_path.write_text(json.dumps(document, indent=2) + '\n')
    result = execute(['go', 'run', './acceptance/qualification', '-check-ci-evidence', str(evidence),
                      '-ci-origin', str(origin_path)], capture_output=True, text=True)
    (workspace / 'evidence.stdout.log').write_text(result.stdout)
    (workspace / 'evidence.stderr.log').write_text(result.stderr)
    result.check_returncode()
    proof = json.loads(result.stdout)
    require(proof['schema'] == 1 and proof['origin'] == origin and proof['tree_sha'] == tree and
            proof['qualified_cases'] > 0 and proof['original_receipts'], 'original CI proof is incomplete')
    report = {'schema': 1, 'reuse': True, 'reason': 'identical merged contents with complete original CI proof',
              'source': source, 'run': run, 'jobs': jobs, 'artifacts': artifacts, 'proof': proof}
    (workspace / 'inheritance.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, required=True)
    args = parser.parse_args()
    report = {'schema': 1, 'reuse': False, 'reason': 'this event requires fresh complete CI'}
    if os.environ['GITHUB_EVENT_NAME'] == 'push' and os.environ['GITHUB_REF'] == 'refs/heads/main':
        try:
            client = GitHub(os.environ['GITHUB_REPOSITORY'], os.environ['GITHUB_TOKEN'])
            revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
            require(revision == os.environ['GITHUB_SHA'], 'CI controller checkout differs from its event')
            subprocess.run(['git', 'diff', '--quiet', 'HEAD'], check=True)
            require(not subprocess.check_output(['git', 'ls-files', '--others', '--exclude-standard'], text=True).strip(),
                    'untracked source dependencies require fresh CI')
            tree = subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], text=True).strip()
            run = choose(client, revision, datetime.now(timezone.utc))
            if run:
                report = qualify(client, run, tree, args.workspace)
            else:
                report['reason'] = 'no compatible complete CI exists for this merged PR'
        except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
            report = {'schema': 1, 'reuse': False, 'reason': 'prior evidence was not admitted: ' + str(error)}
    args.workspace.mkdir(parents=True, exist_ok=True)
    (args.workspace / 'decision.json').write_text(json.dumps(report, indent=2) + '\n')
    with Path(os.environ['GITHUB_OUTPUT']).open('a', encoding='utf-8') as stream:
        stream.write('reuse=' + str(report['reuse']).lower() + '\n')
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with Path(os.environ['GITHUB_STEP_SUMMARY']).open('a', encoding='utf-8') as stream:
            stream.write('CI execution: ' + report['reason'] + '\n')
            if report['reuse']:
                stream.write(f"Original run: https://github.com/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{report['run']['id']}\n")
    print(json.dumps({'reuse': report['reuse'], 'reason': report['reason']}, indent=2))


if __name__ == '__main__':
    main()
