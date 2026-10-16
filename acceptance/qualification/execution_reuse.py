"""Source classification and direct original-proof lookup for event admission.

An inherited decision is only a hint to an original run. Its jobs, artifacts,
source and receipts must pass the same independent admission again; decisions
are never chained into substitute filesystem verdicts.
"""
from datetime import datetime
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from release_assets import read_document, require, unique_object


DOCUMENTATION = 'documentation-or-release-only'


def eligible_run(client, run, now, workflow):
    return (run['path'] == f'.github/workflows/{workflow}.yml' and run['status'] == 'completed' and
            run['conclusion'] == 'success' and run['repository']['full_name'] == client.repository and
            run['head_repository']['full_name'] == client.repository and
            run['event'] in ('pull_request', 'push', 'workflow_dispatch') and
            (run['event'] == 'pull_request' or run['head_branch'] == 'main') and
            0 <= (now - datetime.fromisoformat(run['updated_at'].replace('Z', '+00:00'))).total_seconds() <= 86400)


def fetch_revision(revision, execute=subprocess.run):
    require(re.fullmatch('[a-f0-9]{40}', revision), 'exact original source revision required')
    execute(['git', 'fetch', '--no-tags', '--depth=1', 'origin', revision], check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def pull_request_base():
    path = Path(os.environ['GITHUB_EVENT_PATH'])
    require(path.is_file() and path.stat().st_size <= 8 << 20, 'complete original PR event required')
    event = json.loads(path.read_text(), object_pairs_hook=unique_object)
    pull = event['pull_request']
    repository = os.environ['GITHUB_REPOSITORY']
    require(pull['head']['repo']['full_name'] == repository and
            pull['base']['repo']['full_name'] == repository and pull['base']['ref'] == 'main' and
            re.fullmatch('[a-f0-9]{40}', pull['base']['sha']),
            'unrecognised/fork PR requires complete fresh execution')
    return pull['base']['sha']


def classify(base, execute=subprocess.run):
    fetch_revision(base, execute)
    result = execute(['go', 'run', './acceptance/qualification', '-classify-changes-from', base],
                     check=True, capture_output=True, text=True)
    changes = json.loads(result.stdout)
    require(changes['schema'] == 1 and changes['original_revision'] == base and
            changes['classification'] in ('identical', DOCUMENTATION, 'full'),
            'source classification was not independently established')
    return changes


def original_run(client, candidate, workflow, now, inspector, execute=subprocess.run):
    """Resolve at most one hint, then demand a complete original execution."""
    require(eligible_run(client, candidate, now, workflow), 'original campaign expired or is untrusted')
    try:
        inspector(client, candidate)
        return candidate
    except ValueError:
        pass
    root = f'/repos/{client.repository}/actions/runs/{candidate["id"]}'
    artifacts = client.pages(root + '/artifacts', field='artifacts')
    prefix = 'ci' if workflow == 'ci' else 'native'
    expected = f'{prefix}-inheritance-{candidate["id"]}-{candidate["run_attempt"]}'
    matches = [a for a in artifacts if a['name'] == expected]
    require(len(matches) == 1, 'complete original campaign or unique original-proof hint missing')
    artifact = matches[0]
    require(not artifact['expired'] and artifact['size_in_bytes'] > 0 and
            artifact['workflow_run']['id'] == candidate['id'] and
            artifact['workflow_run']['head_sha'] == candidate['head_sha'], 'original-proof hint expired or changed')
    with tempfile.TemporaryDirectory(prefix='qualification-origin-') as temporary:
        execute(['gh', 'run', 'download', str(candidate['id']), '--repo', client.repository,
                 '--name', expected, '--dir', temporary], check=True)
        hint = read_document(Path(temporary) / 'inheritance.json', 32 << 20)
    identity = hint['run']['id']
    require(type(identity) is int and identity > 0 and identity != candidate['id'],
            'original-proof hint is recursive or has no original run')
    original = client.request(f'/repos/{client.repository}/actions/runs/{identity}')
    require(original['id'] == identity and eligible_run(client, original, now, workflow),
            'hinted original run is expired, incomplete or untrusted')
    inspector(client, original)
    return original


def source_document(source, origin, tree, artifacts, workflow, execute=subprocess.run):
    document = {'schema': 1, 'workflow': workflow, 'origin': origin,
                'tree_sha': source['tree_sha'], 'artifacts': artifacts}
    if source['tree_sha'] != tree:
        fetch_revision(source['tested_revision'], execute)
        document['source_projection'] = DOCUMENTATION
    return document


def verify_summary(proof, document, current_tree):
    require(proof['schema'] == 1 and proof['origin'] == document['origin'] and
            proof['tree_sha'] == document['tree_sha'] and proof['qualified_cases'] > 0 and
            proof['original_receipts'], 'original complete execution proof missing')
    if document.get('source_projection'):
        projection = proof['source_projection']
        require(projection['original_revision'] == document['origin']['revision'] and
                projection['original_tree_sha'] == document['tree_sha'] and
                projection['current_tree_sha'] == current_tree and
                projection['classification'] in ('identical', DOCUMENTATION) and
                not projection['execution_reasons'], 'execution dependencies differ from the original proof')
    else:
        require(document['tree_sha'] == current_tree, 'original execution tested different contents')
