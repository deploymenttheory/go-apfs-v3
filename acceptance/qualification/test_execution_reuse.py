from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import ci_reuse
import execution_reuse as reuse
import native_reuse
import test_ci_reuse as ci_controls
import test_native_reuse as native_controls


class ControlClock(datetime):
    @classmethod
    def now(cls, tz=None):
        return datetime(2026, 10, 16, 12, tzinfo=timezone.utc)


class ClassifiedExecutionReuse(unittest.TestCase):
    def changes(self, classification=reuse.DOCUMENTATION):
        return {'schema': 1, 'original_revision': 'd' * 40, 'original_tree_sha': 'e' * 40,
                'current_revision': 'f' * 40, 'current_tree_sha': '7' * 40,
                'classification': classification, 'changed_paths': ['README.md'],
                'execution_reasons': [] if classification != 'full' else ['unknown execution dependency']}

    def execute(self, command, **kwargs):
        if command[0] == 'git':
            return subprocess.CompletedProcess(command, 0, stdout=b'', stderr=b'')
        if '-classify-changes-from' in command:
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps(self.changes()), stderr='')
        if command[:3] == ['gh', 'run', 'download']:
            directory = Path(command[command.index('--dir') + 1]); directory.mkdir(parents=True, exist_ok=True)
            name = 'qualification-native-replay-0' if self.workflow == 'native' else 'qualification-ci-portable-0'
            # A single --name artifact is downloaded directly to --dir.
            record = {'origin': {'revision': 'c' * 40, 'job': 'replay' if self.workflow == 'native' else 'portable'},
                      'plan': {'stage': 'replay', 'environment': {'os': 'linux'}}}
            (directory / 'receipt.json').write_text(json.dumps(record))
            self.assertEqual(directory.name, name)
            return subprocess.CompletedProcess(command, 0)
        document = json.loads(Path(command[command.index('-execution-origin') + 1]).read_text())
        projection = self.changes()
        projection['original_revision'] = document['origin']['revision']
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps({
            'schema': 1, 'origin': document['origin'], 'tree_sha': document['tree_sha'],
            'qualified_cases': 3, 'original_receipts': [{'path': 'original/receipt.json', 'sha256': 'a' * 64}],
            'source_projection': projection}), stderr='')

    def event(self, directory):
        path = directory / 'event.json'
        path.write_text(json.dumps({'pull_request': {
            'base': {'sha': 'd' * 40, 'ref': 'main', 'repo': {'full_name': 'owner/filesystems'}},
            'head': {'repo': {'full_name': 'owner/filesystems'}}}}))
        return path

    def decision(self, workflow, client, run, execute=None, event='pull_request'):
        self.workflow = workflow
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.dict('os.environ', {'GITHUB_EVENT_NAME': event, 'GITHUB_REF': 'refs/heads/main' if event == 'push' else 'refs/pull/2/merge',
                    'GITHUB_SHA': 'f' * 40, 'GITHUB_REPOSITORY': 'owner/filesystems', 'GITHUB_TOKEN': 'control',
                    'GITHUB_EVENT_PATH': str(self.event(root)), 'GITHUB_OUTPUT': str(root / 'output')}), \
                 patch('sys.argv', ['controller', '--workspace', str(root / 'decision')]), \
                 patch.object(ci_reuse, 'datetime', ControlClock), \
                 patch.object(ci_reuse, 'GitHub', return_value=client) as api, \
                 patch.object(ci_reuse.subprocess, 'check_output', side_effect=['f' * 40, '', '7' * 40]), \
                 patch.object(ci_reuse, 'choose_base', return_value=run), \
                 patch.object(ci_reuse, 'choose', return_value=run):
                ci_reuse.main(workflow=workflow, qualifier=native_reuse.qualify if workflow == 'native' else ci_reuse.qualify,
                              inspector=native_reuse.inspect if workflow == 'native' else ci_reuse.inspect,
                              execute=execute or self.execute)
            return json.loads((root / 'decision/decision.json').read_text()), (root / 'output').read_text(), api.called

    def test_documentation_pr_admits_complete_original_portable_and_native_proof(self):
        for workflow in ('ci', 'native'):
            fixture = ci_controls.CompleteCIReuse().fixture() if workflow == 'ci' else native_controls.CompleteNativeReuse().fixture()
            client, run = fixture[0], fixture[2]
            with self.subTest(workflow=workflow):
                report, output, _ = self.decision(workflow, client, run)
                self.assertTrue(report['reuse'])
                self.assertEqual(output, 'reuse=true\n')
                self.assertEqual(report['proof']['origin']['revision'], 'c' * 40)
                self.assertEqual(report['proof']['tree_sha'], 'e' * 40)
                self.assertEqual(report['proof']['source_projection']['current_tree_sha'], '7' * 40)
                self.assertEqual(report['proof']['original_receipts'][0]['sha256'], 'a' * 64)

    def test_unknown_dependencies_do_not_query_or_inherit_prior_runs(self):
        client, _, run, *_ = ci_controls.CompleteCIReuse().fixture()
        def execute(command, **kwargs):
            if '-classify-changes-from' in command:
                return subprocess.CompletedProcess(command, 0, stdout=json.dumps(self.changes('full')), stderr='')
            return self.execute(command, **kwargs)
        report, output, api_called = self.decision('ci', client, run, execute)
        self.assertFalse(report['reuse'])
        self.assertEqual(output, 'reuse=false\n')
        self.assertFalse(api_called)

    def test_missing_or_corrupt_original_proof_executes_full_documentation_ci(self):
        for failure in ('expired', 'events'):
            client, _, run, _, _, artifacts, _ = ci_controls.CompleteCIReuse().fixture()
            if failure == 'expired': artifacts[0]['expired'] = True
            def execute(command, **kwargs):
                if '-check-execution-evidence' in command and failure == 'events':
                    return subprocess.CompletedProcess(command, 1, stdout='', stderr='altered original execution events')
                return self.execute(command, **kwargs)
            with self.subTest(failure=failure):
                report, output, _ = self.decision('ci', client, run, execute)
                self.assertFalse(report['reuse'])
                self.assertEqual(output, 'reuse=false\n')

    def test_inherited_decision_is_only_a_hint_to_fresh_authenticated_original_proof(self):
        client, now, original, *_ = ci_controls.CompleteCIReuse().fixture()
        candidate = deepcopy(original); candidate.update(id=200, event='push', head_branch='main', head_sha='d' * 40)
        artifact = {'name': 'ci-inheritance-200-1', 'expired': False, 'size_in_bytes': 10,
                    'workflow_run': {'id': 200, 'head_sha': 'd' * 40}}
        client.pages.side_effect = None; client.pages.return_value = [artifact]
        client.request.return_value = original
        def execute(command, **kwargs):
            directory = Path(command[command.index('--dir') + 1])
            (directory / 'inheritance.json').write_text(json.dumps({'run': {'id': 123}}))
            return subprocess.CompletedProcess(command, 0)
        inspector = Mock(side_effect=[ValueError('inherited run has no original executions'), None])
        self.assertEqual(reuse.original_run(client, candidate, 'ci', now, inspector, execute), original)
        self.assertEqual(inspector.call_count, 2)
        client.request.assert_called_once_with('/repos/owner/filesystems/actions/runs/123')
        for failure in ('recursive', 'expired-root', 'failed-root', 'foreign-root', 'root-inherited', 'expired-hint'):
            bad = deepcopy(original)
            root_id = 200 if failure == 'recursive' else 123
            if failure == 'expired-root': bad['updated_at'] = '2026-10-14T11:00:00Z'
            elif failure == 'failed-root': bad['conclusion'] = 'failure'
            elif failure == 'foreign-root': bad['head_repository']['full_name'] = 'other/filesystems'
            elif failure == 'expired-hint': artifact['expired'] = True
            client.request.return_value = bad
            inspector = Mock(side_effect=[ValueError('inherited'), ValueError('root not original') if failure == 'root-inherited' else None])
            def invalid_hint(command, **kwargs):
                directory = Path(command[command.index('--dir') + 1])
                (directory / 'inheritance.json').write_text(json.dumps({'run': {'id': root_id}}))
                return subprocess.CompletedProcess(command, 0)
            with self.subTest(failure=failure), self.assertRaises(ValueError):
                reuse.original_run(client, candidate, 'ci', now, inspector, invalid_hint)
            artifact['expired'] = False

    def test_documentation_merge_revalidates_the_original_run_instead_of_chaining_pr_verdicts(self):
        client, _, original, _, _, _, commit = ci_controls.CompleteCIReuse().fixture()
        inherited = deepcopy(original); inherited.update(id=200, head_sha='9' * 40)
        prior_pages = client.pages.side_effect
        artifact = {'name': 'ci-inheritance-200-1', 'expired': False, 'size_in_bytes': 10,
                    'workflow_run': {'id': 200, 'head_sha': '9' * 40}}
        def pages(path, **kwargs):
            if '/runs/200/' in path:
                return [artifact] if path.endswith('/artifacts') else [
                    {'name': 'quality', 'status': 'completed', 'conclusion': 'success', 'steps': []}]
            return prior_pages(path, **kwargs)
        client.pages.side_effect = pages
        client.request.side_effect = lambda path: original if path.endswith('/actions/runs/123') else commit
        commands = []
        def execute(command, **kwargs):
            commands.append(command)
            if command[:3] == ['gh', 'run', 'download'] and command[3] == '200':
                directory = Path(command[command.index('--dir') + 1])
                (directory / 'inheritance.json').write_text(json.dumps({'run': {'id': 123}}))
                return subprocess.CompletedProcess(command, 0)
            return self.execute(command, **kwargs)
        report, output, _ = self.decision('ci', client, inherited, execute, event='push')
        self.assertTrue(report['reuse'])
        self.assertEqual(output, 'reuse=true\n')
        self.assertEqual(report['run']['id'], 123)
        self.assertEqual(report['proof']['origin']['run'], '123')
        self.assertEqual(report['proof']['origin']['revision'], 'c' * 40)
        self.assertTrue(any(command[:4] == ['gh', 'run', 'download', '123'] for command in commands))

    def test_fork_or_incomplete_pull_request_event_requires_fresh_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); event = self.event(root)
            document = json.loads(event.read_text())
            document['pull_request']['head']['repo']['full_name'] = 'fork/filesystems'
            event.write_text(json.dumps(document))
            with patch.dict('os.environ', {'GITHUB_EVENT_PATH': str(event), 'GITHUB_REPOSITORY': 'owner/filesystems'}), self.assertRaises(ValueError):
                reuse.pull_request_base()


if __name__ == '__main__':
    unittest.main()
