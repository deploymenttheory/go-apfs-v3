from datetime import datetime, timedelta, timezone
from unittest.mock import Mock
import unittest

import refresh
import refresh_control as control


class DurableRefresh(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 1, tzinfo=timezone.utc)
        self.contract = 'a' * 64
        self.client = Mock(repository='owner/filesystems')
        self.client.repository = 'owner/filesystems'
        self.issues, self.runs = [], []
        def pages(path, **kwargs):
            return self.issues if path.endswith('/issues') else [
                r for r in self.runs if r['status'] == kwargs['parameters']['status']]
        self.client.pages.side_effect = pages
        self.client.request.side_effect = self.request
        self.dispatched = []

    def request(self, path, method='GET', value=None):
        if path.endswith('/issues') and method == 'POST':
            result = {'number': len(self.issues) + 1, 'state': 'open', **value}
            self.issues.append(result)
            return result
        if '/issues/' in path and method == 'PATCH':
            self.issues[int(path.rsplit('/', 1)[-1]) - 1].update(value)
            return self.issues[int(path.rsplit('/', 1)[-1]) - 1]
        if path.endswith('/dispatches'):
            self.dispatched.append(value)
            return None
        raise AssertionError((path, method, value))

    def decide(self, hours, dispatch=True):
        return control.coordinate(self.client, self.now + timedelta(hours=hours), self.contract, 99, dispatch)

    def test_first_observed_state_survives_hourly_deferrals_and_creates_one_incident(self):
        self.runs = [{'id': 10, 'path': '.github/workflows/native.yml', 'event': 'pull_request',
                      'status': 'queued', 'head_sha': 'b' * 40}]
        for hours in (0, 1, 48, 49):
            result = self.decide(hours)
            self.assertEqual(result['decision'], 'deferred')
            self.assertIsNone(result['last_success'])
        self.assertEqual(len(self.issues), 2)
        state, _ = control.durable_state(self.client, self.issues, self.now)
        self.assertEqual(state.first_observed, self.now)
        self.assertIsNone(state.last_success)
        self.assertEqual(result['incident']['action'], 'update')
        self.assertEqual(self.dispatched, [])

    def test_full_capture_dispatch_has_no_partial_inputs_and_current_success_does_not_repeat(self):
        result = self.decide(0)
        self.assertTrue(result['dispatched'])
        self.assertEqual(self.dispatched, [{'ref': 'main', 'inputs': {'reference_refresh': True}}])
        state = refresh.State(self.now).qualified(self.now, self.contract, 123)
        self.issues[0]['body'] = control.state_body(state)
        result = self.decide(1)
        self.assertEqual(result['decision'], 'current')
        self.assertEqual(len(self.dispatched), 1)

    def test_corrupt_or_duplicate_durable_state_cannot_reset_the_stale_clock(self):
        self.decide(0, dispatch=False)
        self.issues[0]['body'] += 'changed state'
        with self.assertRaisesRegex(ValueError, 'changed or truncated'):
            self.decide(1)
        self.issues[0]['body'] = control.state_body(refresh.State(self.now))
        self.issues.append(dict(self.issues[0], number=2))
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            self.decide(2)

    def test_failed_or_other_revision_campaign_cannot_advance_success(self):
        manifest = {'origin': {'repository': self.client.repository, 'run': '123', 'attempt': '1',
                              'revision': 'b' * 40}, 'capture_contract_sha256': self.contract}
        pin = {'repository': self.client.repository, 'release_id': 4}
        campaign = {'status': 'completed', 'conclusion': 'success', 'path': '.github/workflows/native.yml',
                    'head_branch': 'main', 'head_sha': 'b' * 40, 'run_attempt': 1}
        for change in ({'conclusion': 'failure'}, {'status': 'in_progress'}, {'head_sha': 'c' * 40},
                       {'head_branch': 'other'}, {'run_attempt': 2}):
            self.client.request.side_effect = None
            self.client.request.return_value = {**campaign, **change}
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'incomplete'):
                control.record_qualified(self.client, self.now, manifest, pin)

    def test_duplicate_publication_does_not_reset_success_clock(self):
        state = refresh.State(self.now).qualified(self.now, self.contract, 123)
        self.issues = [{'number': 1, 'state': 'open', 'body': control.state_body(state)}]
        manifest = {'origin': {'repository': self.client.repository, 'run': '123', 'attempt': '1',
                              'revision': 'b' * 40}, 'capture_contract_sha256': self.contract}
        pin = {'repository': self.client.repository, 'release_id': 4}
        def request(path, method='GET', value=None):
            if path.endswith('/actions/runs/123'):
                return {'status': 'completed', 'conclusion': 'success', 'path': '.github/workflows/native.yml',
                        'head_branch': 'main', 'head_sha': 'b' * 40, 'run_attempt': 1}
            if path.endswith('/releases/4'):
                return {'draft': False, 'prerelease': True}
            raise AssertionError((path, method, value))
        self.client.request.side_effect = request
        result = control.record_qualified(self.client, self.now + timedelta(hours=30), manifest, pin)
        self.assertEqual(result['last_success'], refresh.formatted(self.now))
        after, _ = control.durable_state(self.client, self.issues, self.now)
        self.assertEqual(after.last_success, self.now)


if __name__ == '__main__':
    unittest.main()
