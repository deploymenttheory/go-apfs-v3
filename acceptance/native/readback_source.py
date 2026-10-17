"""Admit archived reference/output artifacts for a verifier-only rerun.

The original run must have completed all captures and portable comparisons.
Only verifier, documentation and workflow changes may differ from its commit;
production code, Go tests, fixtures, dependencies and build inputs must match.
Offline editing additionally requires unchanged native construction code and can
select one capability while checking every source version and portable host.
"""
import json
from collections import Counter
import os
from pathlib import PurePosixPath
import re
import subprocess
import urllib.request


def verifier_only(path):
    return (path.startswith(('acceptance/native/', 'docs/')) or
            path in ('README.md', 'acceptance/README.md',
                     '.github/workflows/native.yml', '.github/workflows/ci.yml'))


OFFLINE_FAMILIES = ('apfs', 'hfs', 'hfs-fragmented', 'permissions', 'statistics',
                    'copy-permissions', 'statistics-transitions')


def offline_verifier_only(path):
    native = PurePosixPath(path)
    return (path.startswith('docs/') or
            path in ('README.md', 'acceptance/README.md',
                     '.github/workflows/native.yml', '.github/workflows/ci.yml',
                     '.github/workflows/offline-editing.yml') or
            (native.parent == PurePosixPath('acceptance/native') and
            (native.name.startswith('test_') or native.name in (
                'verify_apfs_offline_editing.py', 'verify_hfs_metadata_growth.py',
                'verify_permission_inheritance.py', 'verify_directory_statistics.py',
                'readback_source.py'))))


def offline_required_jobs(family):
    if family and family not in OFFLINE_FAMILIES:
        raise ValueError('unknown offline editing readback family')
    families = (family,) if family else OFFLINE_FAMILIES
    return ({f'Record Apple {name} editing controls (macOS {major})'
             for name in families for major in (15, 26, 27)} |
            {f'Edit offline editing {name} controls ({host}, macOS {major} sources)'
             for name in families for major in (15, 26, 27)
             for host in ('Linux', 'Windows', 'macOS')})


def restored_input_requirements(job):
    """Recognise all three original input versions retained by one resolver.

    These are input prerequisites, not native capture or execution verdicts.
    Original archives keep their names and bytes. Every portable comparison and
    subsequent Apple verification remains required by the caller.
    """
    if job.get('conclusion') != 'success':
        return set()
    name = job['name'].rsplit(' / ', 1)[-1]
    required = set()
    if name == 'Restore reviewed Apple filesystem reference data (macOS 15, 26 and 27)':
        required = {f'Record Apple filesystem reference data (macOS {major})' for major in (15, 26, 27)}
    for family in OFFLINE_FAMILIES:
        if name == f'Restore reviewed Apple {family} editing controls (macOS 15, 26 and 27)':
            required = {f'Record Apple {family} editing controls (macOS {major})' for major in (15, 26, 27)}
    steps = Counter(step['name'] for step in job.get('steps', []) if step['conclusion'] == 'success')
    expected = ['Restore verified original Apple reference inputs'] + [
        f'Retain reviewed original input bytes (macOS {major})' for major in (15, 26, 27)]
    return required if all(steps[name] == 1 for name in expected) else set()


def main():
    run_id = os.environ['READBACK_RUN']
    if not run_id.isdecimal() or int(run_id) <= 0:
        raise ValueError('readback run must be a positive Actions run ID')
    scope = os.environ.get('READBACK_SCOPE', '')
    if scope not in ('', 'offline-editing'):
        raise ValueError('unknown readback scope')
    offline = scope == 'offline-editing'
    family = os.environ.get('READBACK_FAMILY', '')
    if offline:
        required = offline_required_jobs(family)
    api = f"{os.environ['GITHUB_API_URL']}/repos/{os.environ['GITHUB_REPOSITORY']}"
    def get(path):
        request = urllib.request.Request(api + path, headers={
            'Authorization': 'Bearer ' + os.environ['GH_TOKEN'],
            'Accept': 'application/vnd.github+json'})
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    run = get(f'/actions/runs/{run_id}')
    if run['status'] != 'completed' or run['path'] != '.github/workflows/native.yml':
        raise ValueError('source must be a completed filesystem compatibility run')
    sha = run['head_sha']
    if not re.fullmatch('[0-9a-f]{40}', sha):
        raise ValueError('invalid source commit')
    if not offline:
        required = {f'Record Apple filesystem reference data (macOS {major})' for major in (15, 26, 27)}
        required |= {f'Compare Go with macOS reference data ({host})' for host in ('Linux', 'Windows', 'macOS')}
        required |= {f'Build images from macOS {major} references ({host})'
                     for major in (15, 26, 27) for host in ('Linux', 'Windows', 'macOS')}
    passed = set()
    restored_inputs = set()
    page = 1
    while True:
        jobs = get(f'/actions/runs/{run_id}/jobs?filter=latest&per_page=100&page={page}')['jobs']
        passed.update(job['name'].rsplit(' / ', 1)[-1] for job in jobs
                      if job['conclusion'] == 'success')
        for job in jobs:
            restored_inputs.update(restored_input_requirements(job))
        if len(jobs) < 100:
            break
        page += 1
    if not required <= passed | restored_inputs:
        raise ValueError(f'source run is missing successful inputs/replays: {sorted(required - passed - restored_inputs)}')
    subprocess.run(['git', 'fetch', '--no-tags', '--depth=1', 'origin', sha], check=True)
    changes = subprocess.check_output(['git', 'diff', '--no-renames', '--name-only', '-z', sha, 'HEAD']).decode().split('\0')
    allowed = offline_verifier_only if offline else verifier_only
    refused = [p for p in changes if p and not allowed(PurePosixPath(p).as_posix())]
    if refused:
        raise ValueError(f'Go code or its inputs changed; run fresh capture/replay: {refused}')
    print(f'Using proven artifacts from run {run_id}, commit {sha}; Go code and inputs are unchanged.', flush=True)


if __name__ == '__main__':
    main()
