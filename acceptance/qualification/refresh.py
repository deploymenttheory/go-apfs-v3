"""Coordinate native reference refresh without consuming implementation slots.

This is control-plane state, never a filesystem verdict or input identity.
Callers retain every decision, including deferral, separately from successful
candidate qualification and publication.
"""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import re

UTC = timezone.utc
INCIDENT_MARKER = '<!-- native-corpus-refresh-incident -->'
CAMPAIGN_WORKFLOWS = frozenset(('.github/workflows/native.yml',
                              '.github/workflows/ci.yml',
                              '.github/workflows/qualification.yml'))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def timestamp(value):
    require(isinstance(value, str) and value.endswith('Z'), 'UTC refresh timestamp required')
    result = datetime.fromisoformat(value.removesuffix('Z') + '+00:00')
    require(result.tzinfo is not None and result.utcoffset() == timedelta(0), 'UTC refresh timestamp required')
    return result


def formatted(value):
    require(value.tzinfo is not None and value.utcoffset() == timedelta(0), 'aware UTC clock required')
    return value.isoformat(timespec='seconds').replace('+00:00', 'Z')


@dataclass(frozen=True)
class State:
    first_observed: datetime
    last_success: datetime | None = None
    capture_contract: str | None = None
    successful_run: str | None = None

    @classmethod
    def read(cls, value):
        require(value.get('schema') == 1, 'unknown refresh control-state schema')
        first = timestamp(value['first_observed'])
        last = timestamp(value['last_success']) if value.get('last_success') else None
        contract, run = value.get('capture_contract'), value.get('successful_run')
        require((last is None and contract is None and run is None) or
                (last is not None and re.fullmatch('[a-f0-9]{64}', contract or '') and
                 re.fullmatch('[1-9][0-9]*', run or '')), 'incomplete successful-refresh identity')
        require(last is None or last >= first, 'refresh state clock order differs')
        return cls(first, last, contract, run)

    def document(self):
        return {'schema': 1, 'first_observed': formatted(self.first_observed),
                'last_success': formatted(self.last_success) if self.last_success else None,
                'capture_contract': self.capture_contract, 'successful_run': self.successful_run}

    def qualified(self, now, contract, run):
        """Call only after the permanent qualified-candidate publication exists."""
        require(self.last_success is None or now >= self.last_success,
                'refresh clock predates last success')
        result = State(self.first_observed, now, contract, str(run))
        State.read(result.document())
        return result


def active_campaigns(runs, current_run):
    """Only implementation campaigns contend; this refresh cannot block itself."""
    active = []
    seen = set()
    for run in runs:
        identity = run['id']
        require(identity not in seen, 'duplicate Actions run in contention evidence')
        seen.add(identity)
        if str(identity) == str(current_run) or run['path'] not in CAMPAIGN_WORKFLOWS:
            continue
        if run['event'] in ('pull_request', 'push', 'merge_group', 'workflow_dispatch') and run['status'] in (
                'queued', 'requested', 'pending', 'waiting', 'in_progress'):
            active.append({'id': identity, 'path': run['path'], 'event': run['event'],
                           'head_sha': run['head_sha'], 'status': run['status']})
    return sorted(active, key=lambda run: run['id'])


def decide(state, now, contract, runs, current_run):
    require(now.tzinfo is not None and now.utcoffset() == timedelta(0) and now >= state.first_observed,
            'refresh clock predates durable control state')
    require(re.fullmatch('[a-f0-9]{64}', contract or ''), 'capture contract identity required')
    require(state.last_success is None or now >= state.last_success, 'refresh clock predates last success')
    contenders = active_campaigns(runs, current_run)
    last = state.last_success or state.first_observed
    stale = now - last >= timedelta(hours=48)
    if contenders:
        decision, reason = 'deferred', 'implementation campaigns have priority'
    elif state.last_success is not None and state.capture_contract == contract and now - last < timedelta(hours=20):
        decision, reason = 'current', 'this overnight refresh is already qualified'
    else:
        decision, reason = 'capture', 'new or due independent Apple reference capture'
    return {'schema': 1, 'observed_at': formatted(now), 'decision': decision,
            'reason': reason, 'capture_contract_sha256': contract,
            'contending_runs': contenders, 'stale_refresh': stale,
            'last_success': formatted(state.last_success) if state.last_success else None,
            'successful_run': state.successful_run}


def incident_action(issues, decision):
    """Maintain one marker-addressed incident; never open one per retry."""
    existing = [issue for issue in issues if INCIDENT_MARKER in (issue.get('body') or '')
                and 'pull_request' not in issue]
    require(len(existing) <= 1, 'duplicate refresh incidents require reconciliation')
    opened = next((issue for issue in existing if issue['state'] == 'open'), None)
    if decision['stale_refresh']:
        if opened:
            return {'action': 'update', 'number': opened['number']}
        if existing:
            return {'action': 'reopen', 'number': existing[0]['number']}
        return {'action': 'create'}
    if opened and decision['last_success'] is not None:
        return {'action': 'close', 'number': opened['number']}
    return {'action': 'none'}


def incident_body(decision):
    require(decision['stale_refresh'], 'a current refresh has no stale incident')
    runs = ', '.join(str(run['id']) for run in decision['contending_runs']) or 'none'
    return (INCIDENT_MARKER + '\n\nIndependent Apple reference refresh has no successful '
            'qualification in the last 48 hours.\n\n'
            f"Last successful refresh: {decision['last_success'] or 'none since refresh tracking began'}.\n"
            f"Observed: {decision['observed_at']}. Decision: {decision['decision']}.\n"
            f"Contending implementation runs: {runs}.\n\n"
            'Deferred capture does not certify current data. Failed candidate diagnostics stay '
            'with their Actions run; approved inputs are never replaced automatically.\n')
