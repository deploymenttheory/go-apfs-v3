from datetime import datetime, timedelta, timezone
import unittest

import refresh


class RefreshCoordination(unittest.TestCase):
    def setUp(self):
        self.start = datetime(2026, 10, 1, tzinfo=timezone.utc)
        self.contract = 'a' * 64
        self.state = refresh.State(self.start)

    def run_record(self, identity=10, **values):
        return {'id': identity, 'path': '.github/workflows/native.yml',
                'event': 'pull_request', 'status': 'in_progress', 'head_sha': 'b' * 40, **values}

    def decision(self, state=None, hours=1, runs=(), contract=None):
        return refresh.decide(state or self.state, self.start + timedelta(hours=hours),
                              contract or self.contract, runs, current_run=99)

    def test_implementation_contention_defers_without_advancing_success(self):
        decision = self.decision(runs=[self.run_record()])
        self.assertEqual(decision['decision'], 'deferred')
        self.assertIsNone(decision['last_success'])
        self.assertEqual(decision['contending_runs'][0]['id'], 10)
        self.assertIsNone(self.state.last_success)

    def test_queued_unrelated_prs_remain_contenders_and_are_never_cancelled(self):
        decision = self.decision(runs=[self.run_record(10, status='queued'), self.run_record(11)])
        self.assertEqual([r['id'] for r in decision['contending_runs']], [10, 11])
        self.assertNotIn('cancel', str(decision))

    def test_portable_ci_still_has_priority_after_native_checks_finish(self):
        decision = self.decision(runs=[self.run_record(10, path='.github/workflows/ci.yml', status='queued')])
        self.assertEqual(decision['decision'], 'deferred')
        self.assertEqual(decision['contending_runs'][0]['id'], 10)

    def test_this_refresh_and_completed_or_scheduled_runs_do_not_self_block(self):
        runs = [self.run_record(99), self.run_record(10, event='schedule'),
                self.run_record(11, status='completed'), self.run_record(12, path='.github/workflows/docs.yml')]
        self.assertEqual(self.decision(runs=runs)['decision'], 'capture')

    def test_first_qualified_capture_suppresses_repeated_hourly_work(self):
        current = self.state.qualified(self.start + timedelta(hours=1), self.contract, 123)
        self.assertEqual(self.decision(current, hours=2)['decision'], 'current')
        self.assertEqual(self.decision(current, hours=21)['decision'], 'capture')
        self.assertEqual(self.decision(current, hours=2, contract='c' * 64)['decision'], 'capture')
        self.assertEqual(self.decision(current, hours=2, runs=[self.run_record()])['decision'], 'deferred')

    def test_staleness_is_not_hidden_by_contention_or_a_missing_first_success(self):
        for state in (self.state, self.state.qualified(self.start, self.contract, 123)):
            self.assertFalse(self.decision(state, hours=47)['stale_refresh'])
            decision = self.decision(state, hours=48, runs=[self.run_record()])
            self.assertTrue(decision['stale_refresh'])
            self.assertEqual(decision['decision'], 'deferred')
            self.assertIn('48 hours', refresh.incident_body(decision))

    def test_one_stale_incident_is_updated_reopened_and_closed_after_success(self):
        stale = self.decision(hours=49)
        body = refresh.incident_body(stale)
        self.assertEqual(refresh.incident_action([], stale), {'action': 'create'})
        issue = {'number': 12, 'state': 'open', 'body': body}
        self.assertEqual(refresh.incident_action([issue], stale), {'action': 'update', 'number': 12})
        issue['state'] = 'closed'
        self.assertEqual(refresh.incident_action([issue], stale), {'action': 'reopen', 'number': 12})
        issue['state'] = 'open'
        current = self.state.qualified(self.start + timedelta(hours=49), self.contract, 124)
        self.assertEqual(refresh.incident_action([issue], self.decision(current, hours=50)),
                         {'action': 'close', 'number': 12})
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            refresh.incident_action([issue, dict(issue, number=13)], stale)

    def test_durable_state_round_trips_and_rejects_incomplete_or_reversed_time(self):
        current = self.state.qualified(self.start + timedelta(hours=1), self.contract, 123)
        self.assertEqual(refresh.State.read(current.document()), current)
        for change in ({'schema': 2}, {'last_success': None}, {'successful_run': None},
                       {'last_success': '2026-09-01T00:00:00Z'}, {'capture_contract': 'wrong'}):
            document = {**current.document(), **change}
            with self.subTest(change=change), self.assertRaises(ValueError):
                refresh.State.read(document)
        with self.assertRaisesRegex(ValueError, 'clock'):
            self.decision(current, hours=0)
        with self.assertRaisesRegex(ValueError, 'clock'):
            current.qualified(self.start, self.contract, 124)


if __name__ == '__main__':
    unittest.main()
