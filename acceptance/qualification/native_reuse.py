"""Admit complete original Apple -> Go -> Apple evidence for compatible content.

Code changes and manual campaigns execute. Missing, incompatible or interrupted
evidence selects the full campaign. This controller runs only ordinary-file Go
verification on Linux; it never executes Apple filesystem tools.
"""
import json
from pathlib import Path
import re
import subprocess

from ci_reuse import host, main as decide
from reference_campaign import authenticated_checkout, FULL_NATIVE_GATE, PROOF_STEPS
from release_assets import require
from execution_reuse import source_document, verify_summary


def restored_source_job(job):
    names = ['Restore verified original Apple reference inputs']
    names += [f'Retain reviewed original input bytes (macOS {major})' for major in (15, 26, 27)]
    return job['conclusion'] == 'success' and all(
        sum(s['name'] == name and s['conclusion'] == 'success' for s in job.get('steps', [])) == 1
        for name in names)


def inspect(client, run):
    root = f'/repos/{client.repository}/actions/runs/{run["id"]}'
    attempt = run['run_attempt']
    require(type(attempt) is int and attempt > 0, 'original native attempt missing')
    jobs = client.pages(root + f'/attempts/{attempt}/jobs', field='jobs')
    require(jobs and all(j['status'] == 'completed' and j['conclusion'] in ('success', 'skipped') for j in jobs),
            'original native campaign is incomplete or unsuccessful')
    required = [FULL_NATIVE_GATE]
    for platform in ('Linux', 'Windows', 'macOS'):
        required.append(f'Compare Go with macOS reference data ({platform})')
        for major in (15, 26, 27):
            required.append(f'Build images from macOS {major} references ({platform})')
    for major in (15, 26, 27):
        required.extend((f'Retain matched HFS catalog-growth references (macOS {major})',
                         f'Verify Linux, Windows and macOS outputs with Apple tools (macOS {major})'))
    for name in required:
        require(sum(j['name'] == name and j['conclusion'] == 'success' for j in jobs) == 1,
                'original complete native execution missing: ' + name)
    fresh = all(sum(j['name'] == f'Record Apple filesystem reference data (macOS {major})' and
                    j['conclusion'] == 'success' for j in jobs) == 1 for major in (15, 26, 27))
    restored = [j for j in jobs if j['name'] ==
                'Restore reviewed Apple filesystem reference data (macOS 15, 26 and 27)' and
                j['conclusion'] == 'success']
    require(fresh != (len(restored) == 1), 'original independent source capture or restoration missing/ambiguous')
    require(not restored or restored_source_job(restored[0]), 'original source restoration/uploads incomplete')
    proof_jobs = [j for j in jobs if any(s['name'] in PROOF_STEPS for s in j.get('steps', []))]
    require(proof_jobs and all(j['conclusion'] == 'success' and
            sum(s['name'] in PROOF_STEPS and s['conclusion'] == 'success' for s in j['steps']) == 1
            for j in proof_jobs), 'original native execution evidence was not retained')
    artifacts = client.pages(root + '/artifacts', field='artifacts')
    proof = [a for a in artifacts if a['name'].startswith('qualification-')]
    require(len(proof) == len(proof_jobs) and len({a['name'] for a in proof}) == len(proof),
            'original native proof inventory differs from successful upload jobs')
    for artifact in proof:
        require(not artifact['expired'] and artifact['size_in_bytes'] > 0 and
                artifact['workflow_run']['id'] == run['id'] and
                artifact['workflow_run']['head_sha'] == run['head_sha'] and
                re.fullmatch('qualification-[a-z_-]+-[0-9]+', artifact['name']),
                'original native artifact expired or belongs to another run')
    return jobs, sorted(proof, key=lambda a: a['name'])


def qualify(client, run, tree, workspace, execute=subprocess.run):
    jobs, artifacts = inspect(client, run)
    workspace = Path(workspace).absolute()
    require(not workspace.exists(), 'absent managed native inheritance scratch required')
    workspace.mkdir(parents=True)
    evidence = workspace / 'evidence'
    download = evidence / artifacts[0]['name'] if len(artifacts) == 1 else evidence
    command = ['gh', 'run', 'download', str(run['id']), '--repo', client.repository, '--dir', str(download)]
    for artifact in artifacts:
        command += ['--name', artifact['name']]
    execute(command, check=True)
    revisions, declared = set(), []
    for artifact in artifacts:
        job = re.search('-([a-z_]+)-[0-9]+$', artifact['name'])[1]
        directory = evidence / artifact['name']
        paths = sorted(p for p in directory.rglob('*') if p.name == 'receipt.json' or p.name.endswith('.receipt.json'))
        if not paths:
            # Restoring input bytes executes no assertions. Admit these records
            # only beside authenticated successful restoration/upload steps.
            reports = sorted(directory.glob('capture-approved-*/admission.json'))
            require(len(reports) == 3, 'required original native receipts or input admissions missing')
            restore_jobs = [j for j in jobs if restored_source_job(j) and
                            host(j['labels']) == 'linux']
            require(restore_jobs, 'original source restoration has no successful executor')
            for major, path in zip((15, 26, 27), reports):
                report = json.loads(path.read_text())
                require(report['kind'] == 'approved-native-input-admission' and
                        report['assertions_executed'] is False and report['source_major'] == major,
                        'input admission cannot substitute for executed assertions')
            declared.append({'name': artifact['name'], 'job': job, 'host': 'linux', 'kind': 'approved-inputs'})
            continue
        systems, majors = set(), set()
        for path in paths:
            require(not path.is_symlink() and path.stat().st_size <= 32 << 20, 'invalid native receipt member')
            record = json.loads(path.read_text())
            revisions.add(record['origin']['revision'])
            if record['origin']['job'] == job:
                plan = record['plan']
                systems.add(plan['environment']['os'])
                if plan['stage'] != 'replay':
                    majors.add(int(plan['environment']['version'].split('.')[0]))
        require(len(systems) == 1 and len(majors) <= 1, 'original native artifact lacks an unambiguous executor')
        actual = systems.pop()
        require(actual in {host(j['labels']) for j in jobs if
                any(s['name'] in PROOF_STEPS for s in j.get('steps', []))},
                'original native receipt host has no successful executor')
        major = majors.pop() if majors else 0
        if major:
            require(actual == 'darwin' and major in (15, 26, 27) and
                    any(('macos-' + str(major) in j['labels'] or 'xcode-' + str(major) in j['labels'])
                        for j in jobs if j['conclusion'] == 'success'), 'original Apple version has no runner')
        declared.append({'name': artifact['name'], 'job': job, 'host': actual, 'native_major': major})
    require(len(revisions) == 1, 'native campaign used inconsistent tested checkouts')
    tested = revisions.pop()
    source = authenticated_checkout(client, run, tested)
    origin = {'repository': client.repository, 'revision': tested, 'run': str(run['id']),
              'attempt': str(run['run_attempt']), 'completed_at': run['updated_at']}
    origin_path = workspace / 'origin.json'
    document = source_document(source, origin, tree, declared, 'native', execute)
    origin_path.write_text(json.dumps(document, indent=2) + '\n')
    result = execute(['go', 'run', './acceptance/qualification', '-check-execution-evidence', str(evidence),
                      '-execution-origin', str(origin_path)], capture_output=True, text=True)
    (workspace / 'evidence.stdout.log').write_text(result.stdout)
    (workspace / 'evidence.stderr.log').write_text(result.stderr)
    result.check_returncode()
    proof = json.loads(result.stdout)
    verify_summary(proof, document, tree)
    report = {'schema': 1, 'reuse': True, 'reason': 'compatible contents with complete original Apple/Go proof',
              'source': source, 'run': run, 'jobs': jobs, 'artifacts': artifacts, 'proof': proof,
              'current_tree_sha': tree}
    (workspace / 'inheritance.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    decide(workflow='native', qualifier=qualify, inspector=inspect)
