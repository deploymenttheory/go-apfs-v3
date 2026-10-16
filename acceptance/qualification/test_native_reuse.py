from copy import deepcopy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import ci_reuse
import native_reuse as reuse
import test_ci_reuse as ci_controls


class CompleteNativeReuse(unittest.TestCase):
    def fixture(self, restored=False):
        client, now, run, pull, _, artifacts, commit = ci_controls.CompleteCIReuse().fixture()
        run['path'] = '.github/workflows/native.yml'
        names = [reuse.FULL_NATIVE_GATE]
        for platform in ('Linux', 'Windows', 'macOS'):
            names.append(f'Compare Go with macOS reference data ({platform})')
            names += [f'Build images from macOS {major} references ({platform})' for major in (15, 26, 27)]
        for major in (15, 26, 27):
            names += [f'Retain matched HFS catalog-growth references (macOS {major})',
                      f'Verify Linux, Windows and macOS outputs with Apple tools (macOS {major})']
        names += ([f'Record Apple filesystem reference data (macOS {major})' for major in (15, 26, 27)]
                  if not restored else ['Restore reviewed Apple filesystem reference data (macOS 15, 26 and 27)'])
        jobs = [{'name': name, 'status': 'completed', 'conclusion': 'success', 'steps': [],
                 'labels': ['ubuntu-24.04']} for name in names]
        jobs.append({'name': 'Compare Go with macOS reference data (Linux)', 'status': 'completed',
                     'conclusion': 'success', 'labels': ['ubuntu-24.04'],
                     'steps': [{'name': 'Retain required case execution evidence', 'conclusion': 'success'}]})
        jobs.remove(next(j for j in jobs[:-1] if j['name'] == jobs[-1]['name']))
        if restored:
            jobs[-2]['steps'] = [{'name': 'Restore verified original Apple reference inputs', 'conclusion': 'success'}]
            jobs[-2]['steps'] += [{'name': f'Retain reviewed original input bytes (macOS {major})',
                                  'conclusion': 'success'} for major in (15, 26, 27)]
        artifacts[0]['name'] = 'qualification-native-replay-0'
        def pages(path, **kwargs):
            if path.endswith('/pulls'): return [pull]
            if path.endswith('/native.yml/runs'): return [run]
            if path.endswith('/jobs'): return jobs
            if path.endswith('/artifacts'): return artifacts
            raise AssertionError(path)
        client.pages.side_effect = pages
        return client, now, run, jobs, artifacts, commit

    def execute(self, command, **kwargs):
        if command[:3] == ['gh', 'run', 'download']:
            directory = Path(command[command.index('--dir') + 1])
            directory.mkdir(parents=True)
            (directory / 'receipt.json').write_text(json.dumps({
                'origin': {'revision': 'c' * 40, 'job': 'replay'},
                'plan': {'stage': 'replay', 'environment': {'os': 'linux'}}}))
            return subprocess.CompletedProcess(command, 0)
        return ci_controls.CompleteCIReuse().execute(command, **kwargs)

    def test_native_selection_requires_this_merged_pr_and_its_native_workflow(self):
        client, now, run, *_ = self.fixture()
        self.assertEqual(ci_reuse.choose(client, 'd' * 40, now, workflow='native'), run)
        run['path'] = '.github/workflows/ci.yml'
        self.assertIsNone(ci_reuse.choose(client, 'd' * 40, now, workflow='native'))

    def test_full_native_proof_keeps_original_source_and_receipt_bytes(self):
        client, _, run, *_ = self.fixture()
        with tempfile.TemporaryDirectory() as temporary:
            report = reuse.qualify(client, run, 'e' * 40, Path(temporary) / 'proof', self.execute)
            self.assertTrue(report['reuse'])
            self.assertEqual(report['proof']['origin']['revision'], 'c' * 40)
            self.assertEqual(report['source']['run_head_sha'], 'a' * 40)
            self.assertEqual(report['proof']['original_receipts'][0]['sha256'], 'f' * 64)

    def test_partial_native_dispatch_and_missing_current_go_experiments_are_refused(self):
        for prefix in (reuse.FULL_NATIVE_GATE, 'Compare Go', 'Build images', 'Retain matched HFS',
                       'Verify Linux', 'Record Apple'):
            client, _, run, jobs, *_ = self.fixture()
            next(j for j in jobs if j['name'].startswith(prefix))['conclusion'] = 'skipped'
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                reuse.inspect(client, run)

    def test_missing_expired_foreign_or_duplicate_artifacts_cannot_qualify(self):
        for failure in ('expired', 'foreign', 'duplicate', 'missing', 'upload', 'interrupted'):
            client, _, run, jobs, artifacts, *_ = self.fixture()
            if failure == 'expired': artifacts[0]['expired'] = True
            elif failure == 'foreign': artifacts[0]['workflow_run']['head_sha'] = 'f' * 40
            elif failure == 'duplicate': artifacts.append(deepcopy(artifacts[0]))
            elif failure == 'missing': artifacts.clear()
            elif failure == 'upload': jobs[-1]['steps'][0]['conclusion'] = 'failure'
            elif failure == 'interrupted': jobs[-1]['status'] = 'in_progress'
            with self.subTest(failure=failure), self.assertRaises(ValueError):
                reuse.inspect(client, run)

    def test_restored_inputs_require_all_original_uploads_and_never_grant_assertions(self):
        client, _, run, jobs, *_ = self.fixture(restored=True)
        reuse.inspect(client, run)
        for step in jobs[-2]['steps']:
            step['conclusion'] = 'skipped'
            with self.subTest(step=step['name']), self.assertRaises(ValueError):
                reuse.inspect(client, run)
            step['conclusion'] = 'success'

    def test_changed_source_or_failed_original_events_never_writes_inheritance(self):
        for failure in ('tree', 'events'):
            client, _, run, *_ = self.fixture()
            def execute(command, **kwargs):
                if failure == 'events' and '-check-execution-evidence' in command:
                    return subprocess.CompletedProcess(command, 1, stdout='', stderr='changed Apple events')
                return self.execute(command, **kwargs)
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary) / 'proof'
                with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                    reuse.qualify(client, run, 'f' * 40 if failure == 'tree' else 'e' * 40, directory, execute)
                self.assertFalse((directory / 'inheritance.json').exists())

    def test_unknown_pr_manual_and_refresh_events_keep_all_native_execution(self):
        for event in ('pull_request', 'workflow_dispatch', 'schedule'):
            with self.subTest(event=event), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                with patch.dict('os.environ', {'GITHUB_EVENT_NAME': event, 'GITHUB_REF': 'refs/heads/main',
                                               'GITHUB_EVENT_PATH': str(root / 'missing-event.json'),
                                               'GITHUB_OUTPUT': str(root / 'output')}), \
                     patch('sys.argv', ['native_reuse.py', '--workspace', str(root / 'decision')]), \
                     patch.object(ci_reuse, 'GitHub') as api:
                    ci_reuse.main(workflow='native', qualifier=reuse.qualify, inspector=reuse.inspect)
                api.assert_not_called()
                self.assertEqual((root / 'output').read_text(), 'reuse=false\n')


if __name__ == '__main__':
    unittest.main()
