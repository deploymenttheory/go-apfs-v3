#!/usr/bin/env python3
"""Persist refresh coordination and its single stale incident in GitHub issues.

The controller runs on Linux. It neither executes Apple tools nor qualifies a
candidate. Workflow concurrency serializes updates to its durable control issue;
the first-observed clock cannot be reset by hourly retries or deferrals.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path

from refresh import State, decide, incident_action, incident_body, require
from release_assets import GitHub, unique_object

STATE_MARKER = '<!-- native-corpus-refresh-state -->'
STATE_PREFIX = (STATE_MARKER + '\n\nDurable native reference refresh control state. '
                'Deferrals do not advance the last successful qualification.\n\n```json\n')
STATE_SUFFIX = '\n```\n'


def state_body(state):
    return STATE_PREFIX + json.dumps(state.document(), indent=2) + STATE_SUFFIX


def durable_state(client, issues, now):
    controls = [i for i in issues if STATE_MARKER in (i.get('body') or '') and 'pull_request' not in i]
    require(len(controls) <= 1, 'duplicate durable refresh control issues')
    if not controls:
        state = State(now)
        issue = client.request(f'/repos/{client.repository}/issues', 'POST', {
            'title': 'Native reference refresh control state', 'body': state_body(state)})
        return state, issue
    issue = controls[0]
    body = issue['body']
    require(body.startswith(STATE_PREFIX) and body.endswith(STATE_SUFFIX), 'durable refresh state was changed or truncated')
    state = State.read(json.loads(body[len(STATE_PREFIX):-len(STATE_SUFFIX)], object_pairs_hook=unique_object))
    return state, issue


def maintain_incident(client, issues, decision):
    action = incident_action(issues, decision)
    if action['action'] == 'none':
        return action
    path = f'/repos/{client.repository}/issues'
    if action['action'] == 'create':
        issue = client.request(path, 'POST', {
            'title': 'Independent Apple reference refresh is overdue', 'body': incident_body(decision)})
        return {**action, 'number': issue['number']}
    if action['action'] == 'close':
        client.request(path + '/' + str(action['number']), 'PATCH', {'state': 'closed', 'state_reason': 'completed'})
    else:
        client.request(path + '/' + str(action['number']), 'PATCH', {
            'state': 'open', 'title': 'Independent Apple reference refresh is overdue', 'body': incident_body(decision)})
    return action


def coordinate(client, now, contract, current_run, dispatch=False, branch='main'):
    issues = client.pages(f'/repos/{client.repository}/issues', parameters={'state': 'all'})
    state, control = durable_state(client, issues, now)
    runs = {}
    for status in ('queued', 'requested', 'pending', 'waiting', 'in_progress'):
        for run in client.pages(f'/repos/{client.repository}/actions/runs', field='workflow_runs',
                                parameters={'status': status}):
            # A run may transition while these inventories are being read.
            runs[run['id']] = run
    decision = decide(state, now, contract, list(runs.values()), current_run)
    decision['control_issue'] = control['number']
    decision['incident'] = maintain_incident(client, issues, decision)
    if dispatch and decision['decision'] == 'capture':
        require(branch == 'main', 'native refresh dispatch requires the trusted default branch')
        client.request(f'/repos/{client.repository}/actions/workflows/native.yml/dispatches', 'POST', {
            'ref': branch, 'inputs': {'reference_refresh': True}})
        decision['dispatched'] = True
    return decision


def record_qualified(client, now, manifest, pin):
    """Caller has already checked the complete campaign and published assets.

    Keep the exact reviewed-pin candidate in control history. This updates no
    approved repository file and grants no verdict to subsequent implementations.
    """
    origin = manifest['origin']
    contract, run = manifest['capture_contract_sha256'], origin['run']
    require(pin['repository'] == origin['repository'] == client.repository,
            'qualified refresh repository differs')
    campaign = client.request(f'/repos/{client.repository}/actions/runs/{run}')
    require(campaign['status'] == 'completed' and campaign['conclusion'] == 'success' and
            campaign['path'] == '.github/workflows/native.yml' and campaign['head_branch'] == 'main' and
            campaign['head_sha'] == origin['revision'] and str(campaign['run_attempt']) == origin['attempt'],
            'qualified reference campaign is incomplete or belongs to another revision/attempt')
    release = client.request(f'/repos/{client.repository}/releases/{pin["release_id"]}')
    require(release['draft'] is False and release['prerelease'] is True, 'qualified candidate is not permanently published')
    issues = client.pages(f'/repos/{client.repository}/issues', parameters={'state': 'all'})
    state, control = durable_state(client, issues, now)
    if state.successful_run == str(run) and state.capture_contract == contract:
        # Duplicate workflow completion is transport retry, not a newer
        # native capture. It must not reset the 48-hour freshness clock.
        decision = decide(state, now, contract, [], current_run=run)
        decision['incident'] = maintain_incident(client, issues, decision)
        return decision
    state = state.qualified(now, contract, run)
    client.request(f'/repos/{client.repository}/issues/{control["number"]}/comments', 'POST', {
        'body': 'Permanently published qualified reference candidate; promotion still requires review.\n\n```json\n' +
                json.dumps(pin, indent=2) + '\n```\n'})
    client.request(f'/repos/{client.repository}/issues/{control["number"]}', 'PATCH', {
        'body': state_body(state)})
    decision = decide(state, now, contract, [], current_run=run)
    decision['incident'] = maintain_incident(client, issues, decision)
    return decision


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--contract', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--dispatch', action='store_true')
    args = parser.parse_args()
    client = GitHub(os.environ['GITHUB_REPOSITORY'], os.environ['GITHUB_TOKEN'])
    decision = coordinate(client, datetime.now(timezone.utc), args.contract,
                          os.environ['GITHUB_RUN_ID'], dispatch=args.dispatch)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(decision, stream, indent=2)
        stream.write('\n')
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as stream:
            stream.write('capture=' + str(decision['decision'] == 'capture').lower() + '\n')
    print(decision['decision'] + ': ' + decision['reason'])


if __name__ == '__main__':
    main()
