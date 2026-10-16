from copy import deepcopy
from pathlib import Path
import unittest
from unittest.mock import Mock

import reference_campaign as campaign


class CampaignAdmission(unittest.TestCase):
    def fixture(self):
        client = Mock(repository='owner/filesystems')
        client.repository = 'owner/filesystems'
        run = {'id': 123, 'repository': {'full_name': client.repository},
               'head_repository': {'full_name': client.repository}, 'head_branch': 'main',
               'path': '.github/workflows/native.yml', 'event': 'workflow_dispatch',
               'status': 'completed', 'conclusion': 'success', 'head_sha': 'a' * 40,
               'run_attempt': 1, 'updated_at': '2026-10-16T03:00:00Z'}
        jobs = [{'id': 1, 'name': campaign.FULL_NATIVE_GATE, 'status': 'completed',
                 'conclusion': 'success', 'steps': []},
                {'id': 2, 'name': 'Independent capture execution', 'status': 'completed',
                 'conclusion': 'success', 'steps': [{'name': 'Retain required capture execution evidence',
                                                   'conclusion': 'success'}]}]
        artifacts = [{'name': name, 'size_in_bytes': 123, 'expired': False,
                      'workflow_run': {'id': 123, 'head_sha': 'a' * 40}}
                     for name in [*campaign.capture_artifacts(), 'qualification-native-capture-0']]
        ci = [{**deepcopy(run), 'id': 124, 'path': '.github/workflows/ci.yml', 'event': 'push'}]
        client.request.return_value = run
        def request(path):
            if '/git/commits/' in path:
                return {'sha': run['head_sha'], 'tree': {'sha': 'b' * 40}, 'parents': []}
            return client.request.return_value
        client.request.side_effect = request
        def pages(path, **kwargs):
            if path.endswith('/jobs'):
                return jobs
            if path.endswith('/artifacts'):
                return artifacts
            if path.endswith('/ci.yml/runs'):
                return ci
            raise AssertionError(path)
        client.pages.side_effect = pages
        return client, run, jobs, artifacts, ci

    def test_complete_campaign_keeps_exact_original_run_and_artifact_inventory(self):
        client, run, jobs, artifacts, ci = self.fixture()
        result = campaign.inspect_campaign(client, 123)
        self.assertEqual(result['state'], 'ready')
        self.assertEqual(result['origin']['revision'], run['head_sha'])
        self.assertEqual(result['origin']['run'], '123')
        self.assertEqual(len(result['captures']), 39)
        self.assertEqual(result['proof'], ['qualification-native-capture-0'])
        self.assertEqual(result['source']['tested_revision'], run['head_sha'])
        self.assertEqual(result['source']['tree_sha'], 'b' * 40)

    def test_pull_request_receipts_keep_the_actual_tested_merge_revision(self):
        client, run, *_ = self.fixture()
        run.update(event='pull_request', pull_requests=[])
        commit = {'sha': 'c' * 40, 'tree': {'sha': 'd' * 40},
                  'parents': [{'sha': 'b' * 40}, {'sha': run['head_sha']}],
                  'verification': {'verified': True}, 'committer': {'email': 'noreply@github.com'}}
        closed = {'number': 87, 'head': {'sha': run['head_sha']}, 'base': {'sha': 'b' * 40}}
        client.request.side_effect = None
        client.request.return_value = commit
        client.pages.side_effect = None
        client.pages.return_value = [closed]
        result = campaign.authenticated_checkout(client, run, commit['sha'])
        self.assertEqual(result['binding'], 'pull-request-merge')
        self.assertEqual(result['tested_revision'], 'c' * 40)
        self.assertEqual(result['run_head_sha'], 'a' * 40)
        self.assertEqual(result['pull_request'], closed)
        self.assertEqual(result['commit'], commit)
        self.assertTrue(client.pages.call_args.args[0].endswith('/commits/' + 'a' * 40 + '/pulls'))

    def test_foreign_unsigned_or_unassociated_checkouts_are_not_authenticated(self):
        for failure in ('other-event', 'other-head', 'base', 'ambiguous', 'unsigned', 'other-signer', 'other-tree'):
            client, run, *_ = self.fixture()
            run.update(event='pull_request', pull_requests=[])
            commit = {'sha': 'c' * 40, 'tree': {'sha': 'd' * 40},
                      'parents': [{'sha': 'b' * 40}, {'sha': run['head_sha']}],
                      'verification': {'verified': True}, 'committer': {'email': 'noreply@github.com'}}
            closed = {'number': 87, 'head': {'sha': run['head_sha']}, 'base': {'sha': 'b' * 40}}
            associated = [closed]
            if failure == 'other-event': run['event'] = 'push'
            elif failure == 'other-head': commit['parents'][1]['sha'] = 'e' * 40
            elif failure == 'base': closed['base']['sha'] = 'e' * 40
            elif failure == 'ambiguous': associated.append(deepcopy(closed))
            elif failure == 'unsigned': commit['verification']['verified'] = False
            elif failure == 'other-signer': commit['committer']['email'] = 'other@example.test'
            elif failure == 'other-tree': commit['tree']['sha'] = 'not-a-tree'
            client.request.side_effect = None
            client.request.return_value = commit
            client.pages.side_effect = None
            client.pages.return_value = associated
            with self.subTest(failure=failure), self.assertRaises(ValueError):
                campaign.authenticated_checkout(client, run, commit['sha'])

    def test_either_workflow_completion_can_trigger_the_same_fully_qualified_refresh(self):
        client, run, jobs, artifacts, ci = self.fixture()
        run['display_title'] = campaign.REFRESH_TITLE
        self.assertEqual(campaign.refresh_for_completion(client, 123), 123)
        completed = deepcopy(ci[0])
        client.request.return_value = completed
        client.pages.return_value = [run]
        client.pages.side_effect = None
        self.assertEqual(campaign.refresh_for_completion(client, 124), 123)
        client.pages.return_value = []
        self.assertIsNone(campaign.refresh_for_completion(client, 124))

    def test_missing_partial_foreign_or_expired_campaign_cannot_publish(self):
        for scenario in ('foreign', 'branch', 'failed', 'gate', 'capture', 'proof', 'expired',
                         'duplicate-artifact', 'artifact-origin', 'upload-step'):
            client, run, jobs, artifacts, ci = self.fixture()
            if scenario == 'foreign': run['head_repository']['full_name'] = 'other/filesystems'
            elif scenario == 'branch': run['head_branch'] = 'pull-request'
            elif scenario == 'failed': run['conclusion'] = 'failure'
            elif scenario == 'gate': jobs[0]['conclusion'] = 'skipped'
            elif scenario == 'capture': artifacts.pop(0)
            elif scenario == 'proof': artifacts.pop()
            elif scenario == 'expired': artifacts[0]['expired'] = True
            elif scenario == 'duplicate-artifact': artifacts.append(artifacts[0])
            elif scenario == 'artifact-origin': artifacts[0]['workflow_run']['head_sha'] = 'b' * 40
            elif scenario == 'upload-step': jobs[1]['steps'][0]['conclusion'] = 'skipped'
            with self.subTest(scenario=scenario), self.assertRaises(ValueError):
                campaign.inspect_campaign(client, 123)

    def test_late_or_wrong_revision_ci_is_a_wait_without_qualification(self):
        for scenario in ('missing', 'revision', 'fork', 'failed', 'pull-request'):
            client, run, jobs, artifacts, ci = self.fixture()
            if scenario == 'missing': ci.clear()
            elif scenario == 'revision': ci[0]['head_sha'] = 'b' * 40
            elif scenario == 'fork': ci[0]['head_repository']['full_name'] = 'other/filesystems'
            elif scenario == 'failed': ci[0]['conclusion'] = 'failure'
            elif scenario == 'pull-request': ci[0]['event'] = 'pull_request'
            with self.subTest(scenario=scenario):
                result = campaign.inspect_campaign(client, 123)
                self.assertEqual(result['state'], 'waiting-for-ci')
                self.assertNotIn('origin', result)

    def test_download_uses_only_authenticated_names_and_separate_ordinary_trees(self):
        client, *_ = self.fixture()
        selected = campaign.inspect_campaign(client, 123)
        execute = Mock()
        campaign.download_campaign(client.repository, 123, selected['captures'], selected['proof'], Path('/ordinary/scratch'), execute)
        self.assertEqual(execute.call_count, 2)
        first = execute.call_args_list[0].args[0]
        self.assertEqual(first[:4], ['gh', 'run', 'download', '123'])
        self.assertIn('/ordinary/scratch/captures', first)
        self.assertNotIn('qualification-native-capture-0', first)
        with self.assertRaises(ValueError):
            campaign.download_campaign(client.repository, 123, ['../unapproved'], selected['proof'], Path('/ordinary/scratch'), execute)


if __name__ == '__main__':
    unittest.main()
