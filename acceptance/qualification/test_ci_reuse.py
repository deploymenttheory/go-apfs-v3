from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import ci_reuse as reuse


class CompleteCIReuse(unittest.TestCase):
    def fixture(self):
        client = Mock(repository='owner/filesystems')
        client.repository = 'owner/filesystems'
        now = datetime(2026, 10, 16, 12, tzinfo=timezone.utc)
        run = {'id': 123, 'head_sha': 'a' * 40, 'event': 'pull_request',
               'path': '.github/workflows/ci.yml', 'status': 'completed', 'conclusion': 'success',
               'repository': {'full_name': client.repository}, 'head_repository': {'full_name': client.repository},
               'updated_at': '2026-10-16T11:00:00Z', 'run_attempt': 1, 'pull_requests': []}
        pull = {'number': 1, 'merged_at': '2026-10-16T11:30:00Z', 'merge_commit_sha': 'd' * 40,
                'head': {'sha': 'a' * 40, 'repo': {'full_name': client.repository}},
                'base': {'sha': 'b' * 40, 'ref': 'main'}}
        jobs = [{'name': name, 'status': 'completed', 'conclusion': 'success', 'steps': [], 'labels': ['ubuntu-24.04']}
                for name in ('quality', 'Source and native verifier checks', 'Library race checks',
                             'Cross-build Linux, macOS and Windows on amd64 and arm64')]
        jobs.append({'name': 'Portable tests (ubuntu-24.04)', 'status': 'completed', 'conclusion': 'success',
                     'labels': ['ubuntu-24.04'], 'steps': [{'name': reuse.PROOF_STEP, 'conclusion': 'success'}]})
        artifacts = [{'id': 7, 'name': 'qualification-ci-portable-0', 'expired': False, 'size_in_bytes': 100,
                      'workflow_run': {'id': 123, 'head_sha': 'a' * 40}}]
        commit = {'sha': 'c' * 40, 'tree': {'sha': 'e' * 40},
                  'parents': [{'sha': 'b' * 40}, {'sha': 'a' * 40}],
                  'verification': {'verified': True}, 'committer': {'email': 'noreply@github.com'}}
        def pages(path, **kwargs):
            if path.endswith('/pulls'): return [pull]
            if path.endswith('/ci.yml/runs'): return [run]
            if path.endswith('/jobs'): return jobs
            if path.endswith('/artifacts'): return artifacts
            raise AssertionError(path)
        client.pages.side_effect = pages
        client.request.return_value = commit
        return client, now, run, pull, jobs, artifacts, commit

    def test_only_recent_complete_ci_for_this_merged_pr_is_eligible(self):
        client, now, run, *_ = self.fixture()
        self.assertEqual(reuse.choose(client, 'd' * 40, now), run)
        for mutation in ('failed', 'old', 'future', 'foreign', 'different-head', 'other-workflow', 'manual'):
            client, now, run, *_ = self.fixture()
            if mutation == 'failed': run['conclusion'] = 'failure'
            elif mutation == 'old': run['updated_at'] = '2026-10-14T11:00:00Z'
            elif mutation == 'future': run['updated_at'] = '2026-10-17T11:00:00Z'
            elif mutation == 'foreign': run['head_repository']['full_name'] = 'other/filesystems'
            elif mutation == 'different-head': run['head_sha'] = 'f' * 40
            elif mutation == 'other-workflow': run['path'] = '.github/workflows/native.yml'
            elif mutation == 'manual': run['event'] = 'workflow_dispatch'
            with self.subTest(mutation=mutation):
                self.assertIsNone(reuse.choose(client, 'd' * 40, now))

    def test_missing_gates_checks_uploads_or_original_artifacts_cannot_qualify(self):
        for mutation in ('gate', 'build', 'library-race', 'source-checks', 'upload', 'expired', 'duplicate', 'origin', 'partial'):
            client, _, run, _, jobs, artifacts, _ = self.fixture()
            if mutation == 'gate': jobs[0]['conclusion'] = 'skipped'
            elif mutation == 'build': jobs[3]['conclusion'] = 'skipped'
            elif mutation == 'library-race': jobs[2]['conclusion'] = 'skipped'
            elif mutation == 'source-checks': jobs[1]['conclusion'] = 'skipped'
            elif mutation == 'upload': jobs[-1]['steps'][0]['conclusion'] = 'skipped'
            elif mutation == 'expired': artifacts[0]['expired'] = True
            elif mutation == 'duplicate': artifacts.append(deepcopy(artifacts[0]))
            elif mutation == 'origin': artifacts[0]['workflow_run']['head_sha'] = 'f' * 40
            elif mutation == 'partial': jobs[-1]['status'] = 'in_progress'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                reuse.inspect(client, run)

    def execute(self, command, **kwargs):
        if command[:3] == ['gh', 'run', 'download']:
            directory = Path(command[command.index('--dir') + 1])
            directory.mkdir(parents=True)
            (directory / 'receipt.json').write_text(json.dumps({
                'origin': {'revision': 'c' * 40}, 'plan': {'environment': {'os': 'linux'}}}))
            return subprocess.CompletedProcess(command, 0)
        origin = json.loads(Path(command[command.index('-execution-origin') + 1]).read_text())
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps({
            'schema': 1, 'origin': origin['origin'], 'tree_sha': origin['tree_sha'], 'qualified_cases': 3,
            'original_receipts': [{'path': 'original/receipt.json', 'sha256': 'f' * 64, 'bytes': 100}]}), stderr='')

    def test_inheritance_keeps_original_checkout_and_receipt_digests(self):
        client, _, run, *_ = self.fixture()
        with tempfile.TemporaryDirectory() as temporary:
            result = reuse.qualify(client, run, 'e' * 40, Path(temporary) / 'inheritance', self.execute)
            self.assertTrue(result['reuse'])
            self.assertEqual(result['proof']['origin']['revision'], 'c' * 40)
            self.assertEqual(result['source']['run_head_sha'], 'a' * 40)
            self.assertEqual(result['proof']['original_receipts'][0]['sha256'], 'f' * 64)

    def test_different_tree_or_failed_evidence_never_reports_inheritance(self):
        for failure in ('tree', 'events'):
            client, _, run, *_ = self.fixture()
            def execute(command, **kwargs):
                if failure == 'events' and '-check-execution-evidence' in command:
                    return subprocess.CompletedProcess(command, 1, stdout='', stderr='original event digest differs')
                return self.execute(command, **kwargs)
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary) / 'inheritance'
                with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                    reuse.qualify(client, run, 'f' * 40 if failure == 'tree' else 'e' * 40, workspace, execute)
                self.assertFalse((workspace / 'inheritance.json').exists())

    def test_unknown_pull_request_and_manual_events_execute_full_ci(self):
        for event in ('pull_request', 'workflow_dispatch'):
            with self.subTest(event=event), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                with patch.dict('os.environ', {'GITHUB_EVENT_NAME': event, 'GITHUB_REF': 'refs/heads/main',
                                               'GITHUB_EVENT_PATH': str(root / 'missing-event.json'),
                                               'GITHUB_OUTPUT': str(root / 'output')}), \
                     patch('sys.argv', ['ci_reuse.py', '--workspace', str(root / 'decision')]), \
                     patch.object(reuse, 'GitHub') as api:
                    reuse.main()
                api.assert_not_called()
                self.assertEqual((root / 'output').read_text(), 'reuse=false\n')

    def test_failed_prior_evidence_selects_full_ci_instead_of_a_successful_skip(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.dict('os.environ', {'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF': 'refs/heads/main',
                    'GITHUB_SHA': 'd' * 40, 'GITHUB_TOKEN': 'public-control', 'GITHUB_REPOSITORY': 'owner/filesystems',
                    'GITHUB_OUTPUT': str(root / 'output')}), \
                 patch('sys.argv', ['ci_reuse.py', '--workspace', str(root / 'decision')]), \
                 patch.object(reuse, 'GitHub'), \
                 patch.object(reuse.subprocess, 'check_output', side_effect=['d' * 40, '', 'e' * 40]), \
                 patch.object(reuse.subprocess, 'run'), \
                 patch.object(reuse, 'choose', return_value={'id': 123}), \
                 patch.object(reuse, 'original_run', return_value={'id': 123}), \
                 patch.object(reuse, 'qualify', side_effect=ValueError('missing original case')):
                reuse.main()
            self.assertEqual((root / 'output').read_text(), 'reuse=false\n')
            report = json.loads((root / 'decision/decision.json').read_text())
            self.assertFalse(report['reuse'])
            self.assertIn('missing original case', report['reason'])


if __name__ == '__main__':
    unittest.main()
