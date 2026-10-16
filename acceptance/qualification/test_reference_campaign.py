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
