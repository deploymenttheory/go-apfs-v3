"""Admit archived reference/output artifacts for a verifier-only rerun.

The original run must have completed all captures and portable comparisons.
Only verifier, documentation and workflow changes may differ from its commit;
production code, Go tests, fixtures, dependencies and build inputs must match.
"""
import json
import os
from pathlib import PurePosixPath
import re
import subprocess
import urllib.request


def verifier_only(path):
    return (path.startswith(('acceptance/native/', 'docs/')) or
            path in ('README.md', 'acceptance/README.md',
                     '.github/workflows/native.yml', '.github/workflows/ci.yml'))


def main():
    run_id = os.environ['READBACK_RUN']
    if not run_id.isdecimal() or int(run_id) <= 0:
        raise ValueError('readback run must be a positive Actions run ID')
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
    jobs = get(f'/actions/runs/{run_id}/jobs?filter=latest&per_page=100')
    required = {f'Record Apple filesystem reference data (macOS {major})' for major in (15, 26, 27)}
    required |= {f'Compare Go with macOS reference data ({host})' for host in ('Linux', 'Windows', 'macOS')}
    passed = {job['name'] for job in jobs['jobs'] if job['conclusion'] == 'success'}
    if not required <= passed:
        raise ValueError(f'source run is missing successful captures/replays: {sorted(required - passed)}')
    subprocess.run(['git', 'fetch', '--no-tags', '--depth=1', 'origin', sha], check=True)
    changes = subprocess.check_output(['git', 'diff', '--no-renames', '--name-only', '-z', sha, 'HEAD']).decode().split('\0')
    refused = [p for p in changes if p and not verifier_only(PurePosixPath(p).as_posix())]
    if refused:
        raise ValueError(f'Go code or its inputs changed; run fresh capture/replay: {refused}')
    print(f'Using proven artifacts from run {run_id}, commit {sha}; Go code and inputs are unchanged.', flush=True)


if __name__ == '__main__':
    main()
