"""Scope comparison cannot discard host, input, instrumentation or byte differences."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import compare_campaigns


def index(run=1, **changes):
    file = {'path': 'replay/receipt.json', 'bytes': 100, 'sha256': str(run) * 64}
    environment = {'os': 'linux', 'architecture': 'amd64', 'version': 'Ubuntu 24.04',
                   'build': 'original-kernel', 'toolchain': 'go version go1.27.0 linux/amd64',
                   'race': False, 'tools': [{'path': 'compiler', 'bytes': 100, 'sha256': 'a' * 64}],
                   'flags': ['test', '-json', '-count=1', '-run', '^Original$',
                             'go-environment=' + json.dumps({'CGO_ENABLED': '0', 'GOFLAGS': '',
                                                           'GOROOT': '/compiler', 'GOTOOLDIR': '/compiler/tools'})]}
    case = {'family': 'apfs-file-edits', 'test': 'TestNativeAPFSImageEditing/macos-15/apfs/UDRO',
            'corpus': 'apfs-editing', 'manifest': 'macos-15/manifest.json', 'native_case': 'cases/apfs',
            'source': 15, 'variant': 'UDRO', 'outputs': ['OUTPUT/macos-15/apfs/peak-UDRO.dmg']}
    origin = {'revision': 'a' * 40, 'run': str(run), 'attempt': '1', 'job': 'replay'}
    invocation = {'origin': origin, 'original_receipt': file, 'stage': 'replay',
                  'production_sha256': 'b' * 64, 'environment': environment}
    item = {'original_receipt_sha256': file['sha256'], 'case': case, 'required_controls': [],
            'inputs': [{'id': 'apfs-editing', 'source_sha256': 'c' * 64, 'use': 'native-capture'}],
            'outputs': [{'path': case['outputs'][0], 'bytes': 1024, 'sha256': 'd' * 64}]}
    result = {'evidence': {'schema': 1, 'qualified_cases': 1, 'original_receipts': [file]},
              'invocations': [invocation], 'cases': [item]}
    result.update(changes)
    return result


class CampaignComparisonTests(unittest.TestCase):
    def compare(self, original, candidate):
        return compare_campaigns.compare_indexes([original], [candidate])

    def test_identical_scopes_can_run_once_after_real_duplicate_executions_are_identified(self):
        original, repeated, candidate = index(), index(2), index(3)
        report = compare_campaigns.compare_indexes([original, repeated], [candidate])
        self.assertTrue(report['scope_agreement'])
        self.assertEqual(report['baseline_scopes'], 1)
        self.assertEqual(report['baseline_repeated_scopes'], 1)
        self.assertEqual(report['candidate_repeated_scopes'], 0)
        self.assertEqual(report['plaintext_outputs'], 1)
        self.assertEqual(original['cases'][0]['inputs'][0]['source_sha256'], 'c' * 64)

    def test_installation_path_and_batch_selectors_do_not_replace_actual_compiler_identity(self):
        original, candidate = index(), index(2)
        env = candidate['invocations'][0]['environment']
        env['flags'] = ['test', '-json', '-count=1', '-run', '^Grouped$',
                        'go-environment=' + json.dumps({'CGO_ENABLED': '0', 'GOFLAGS': '',
                                                       'GOROOT': '/other/compiler', 'GOTOOLDIR': '/other/tools'})]
        self.assertTrue(self.compare(original, candidate)['scope_agreement'])
        env['tools'][0]['sha256'] = 'e' * 64
        self.assertFalse(self.compare(original, candidate)['scope_agreement'])

    def test_changed_inputs_hosts_architectures_races_versions_controls_and_formats_remain_distinct(self):
        for kind in ('input', 'auxiliary', 'host', 'architecture', 'race', 'build', 'version',
                     'build-flags', 'controls', 'format', 'source', 'current-go'):
            with self.subTest(kind=kind):
                original, candidate = index(), index(2)
                env, item = candidate['invocations'][0]['environment'], candidate['cases'][0]
                if kind == 'input': item['inputs'][0]['source_sha256'] = 'e' * 64
                elif kind == 'auxiliary': item['inputs'].append({'id': 'snapshots', 'source_sha256': 'f' * 64, 'use': 'retained'})
                elif kind == 'host': env['os'] = 'windows'
                elif kind == 'architecture': env['architecture'] = 'arm64'
                elif kind == 'race': env['race'] = True
                elif kind == 'build': env['build'] = 'another-kernel'
                elif kind == 'version': env['version'] = 'other-release'
                elif kind == 'build-flags': env['flags'][-1] = 'go-environment=' + json.dumps({'CGO_ENABLED': '0', 'GOFLAGS': '-tags=changed'})
                elif kind == 'controls': item['required_controls'] = ['copy-truncation']
                elif kind == 'format': item['case']['variant'] = 'UDZO'
                elif kind == 'source': item['case']['source'] = 26
                elif kind == 'current-go': item['inputs'][0]['use'] = 'current-go'
                self.assertFalse(self.compare(original, candidate)['scope_agreement'])

    def test_changed_plaintext_production_and_conflicting_duplicate_outputs_are_rejected(self):
        original, candidate = index(), index(2)
        candidate['cases'][0]['outputs'][0]['sha256'] = 'e' * 64
        self.assertFalse(self.compare(original, candidate)['scope_agreement'])
        with self.assertRaisesRegex(ValueError, 'conflicting deterministic plaintext'):
            compare_campaigns.inventory([original, candidate])
        candidate = index(2)
        candidate['invocations'][0]['production_sha256'] = 'f' * 64
        self.assertFalse(self.compare(original, candidate)['scope_agreement'])

    def test_reference_transport_use_does_not_change_original_source_identity(self):
        original, candidate = index(), index(2)
        candidate['cases'][0]['inputs'][0]['use'] = 'retained'
        self.assertTrue(self.compare(original, candidate)['scope_agreement'])

    def test_randomized_ciphertext_is_counted_for_independent_checks_without_raw_byte_equality(self):
        original, candidate = index(), index(2)
        for value in (original, candidate):
            value['cases'][0]['case']['variant'] = 'UDRO/encrypted-aes128'
        candidate['cases'][0]['outputs'][0]['sha256'] = 'e' * 64
        report = self.compare(original, candidate)
        self.assertTrue(report['scope_agreement'])
        self.assertEqual(report['plaintext_outputs'], 0)
        self.assertEqual(report['outputs_without_byte_comparison'], 1)

    def test_decrypted_encrypted_input_still_requires_plaintext_byte_equality(self):
        original, candidate = index(), index(2)
        for value in (original, candidate):
            value['cases'][0]['case']['variant'] = 'encrypted-input/UDRO'
        candidate['cases'][0]['outputs'][0]['sha256'] = 'e' * 64
        self.assertFalse(self.compare(original, candidate)['scope_agreement'])

    def test_fresh_native_continuations_keep_their_unique_input_and_output_hashes(self):
        original, candidate = index(), index(2)
        for value in (original, candidate):
            value['cases'][0]['case']['continuation'] = True
            value['cases'][0]['inputs'][0]['use'] = 'native-continuation'
        candidate['cases'][0]['inputs'][0]['source_sha256'] = 'e' * 64
        candidate['cases'][0]['outputs'][0]['sha256'] = 'f' * 64
        self.assertTrue(self.compare(original, candidate)['scope_agreement'])
        self.assertEqual(candidate['cases'][0]['inputs'][0]['source_sha256'], 'e' * 64)
        candidate['cases'][0]['case']['continuation'] = False
        with self.assertRaisesRegex(ValueError, 'not a continuation'):
            self.compare(original, candidate)

    def test_missing_duplicate_case_and_unknown_output_cannot_be_ignored(self):
        for kind in ('count', 'invocation', 'case-copy', 'output', 'unknown-output'):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                original, candidate = index(), index(2)
                if kind == 'count': candidate['evidence']['qualified_cases'] = 2
                elif kind == 'invocation': candidate['invocations'] = []
                elif kind == 'case-copy':
                    candidate['cases'].append(copy.deepcopy(candidate['cases'][0]))
                    candidate['evidence']['qualified_cases'] = 2
                elif kind == 'output': candidate['cases'][0]['outputs'] = []
                elif kind == 'unknown-output':
                    candidate['cases'][0]['case']['outputs'][0] = 'unexpected.data'
                    candidate['cases'][0]['outputs'][0]['path'] = 'unexpected.data'
                self.compare(original, candidate)


class CompleteCampaignAdmissionTests(unittest.TestCase):
    def run_record(self, workflow, run_id, status='completed', conclusion='success'):
        return {'id': run_id, 'path': '.github/workflows/' + workflow + '.yml',
                'repository': {'full_name': 'owner/filesystems'},
                'head_repository': {'full_name': 'owner/filesystems'},
                'head_branch': 'main', 'event': 'workflow_dispatch',
                'status': status, 'conclusion': conclusion}

    def test_incomplete_failed_foreign_or_wrong_workflow_is_refused_before_artifact_access(self):
        for kind in ('incomplete', 'failed', 'foreign', 'wrong-workflow'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                run = self.run_record('ci', 1)
                if kind == 'incomplete': run['status'] = 'queued'
                elif kind == 'failed': run['conclusion'] = 'failure'
                elif kind == 'foreign': run['head_repository']['full_name'] = 'other/filesystems'
                elif kind == 'wrong-workflow': run['path'] = '.github/workflows/native.yml'
                client = Mock(repository='owner/filesystems')
                client.request.return_value = run
                execute = Mock()
                with self.assertRaises(ValueError), patch('ci_reuse.qualify') as qualify:
                    compare_campaigns.admit_campaign(client, {'root': temporary, 'tree': 'a' * 40},
                                                      (1, 2), Path(temporary) / 'evidence',
                                                      Path(temporary) / 'verifier', execute=execute)
                qualify.assert_not_called()
                execute.assert_not_called()

    def test_both_existing_full_qualifiers_use_only_the_original_root_and_evidence_index(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            client = Mock(repository='owner/filesystems')
            client.request.side_effect = [self.run_record('ci', 1), self.run_record('native', 2)]
            calls = []

            def execute(command, **kwargs):
                calls.append((command, kwargs))
                self.assertEqual(command[1:3], ['-root', str(root)])
                self.assertIn('-execution-index', command)
                self.assertIn('-check-execution-evidence', command)
                self.assertNotIn('-replay', command)
                self.assertEqual(kwargs['cwd'], root)
                value = index(len(calls))
                value['evidence']['origin'] = {'run': str(len(calls))}
                return subprocess.CompletedProcess(command, 0, stdout=json.dumps(value), stderr='')

            def qualify(client, run, tree, target, execute):
                self.assertEqual(tree, 'a' * 40)
                target.mkdir(parents=True)
                result = execute(['go', 'run', './acceptance/qualification',
                                  '-check-execution-evidence', str(target / 'evidence'),
                                  '-execution-origin', str(target / 'origin.json')],
                                 capture_output=True, text=True)
                result.check_returncode()
                proof = json.loads(result.stdout)
                self.assertEqual(proof['origin']['run'], str(run['id']))
                return {'proof': proof}

            with patch('ci_reuse.qualify', side_effect=qualify) as ci, \
                    patch('native_reuse.qualify', side_effect=qualify) as native:
                result = compare_campaigns.admit_campaign(client, {'root': str(root), 'tree': 'a' * 40},
                                                          (1, 2), root / 'comparison', root / 'verifier',
                                                          execute=execute)
            ci.assert_called_once()
            native.assert_called_once()
            self.assertEqual(len(result['indexes']), 2)
            self.assertEqual(len(calls), 2)
            self.assertTrue((root / 'comparison/ci/index.json').is_file())
            self.assertTrue((root / 'comparison/native/index.json').is_file())

    def test_same_campaign_different_pins_and_changed_assertions_cannot_claim_equivalence(self):
        with patch('compare_campaigns.checkout') as checkout, \
                patch('compare_campaigns.assertion_sources') as assertions, \
                patch('compare_campaigns.admit_campaign') as admit, \
                patch('subprocess.run') as execute:
            with self.assertRaisesRegex(ValueError, 'independent original executions'):
                compare_campaigns.compare_campaigns(Mock(), '/old', '/new', (1, 2), (1, 2), '/comparison')
            checkout.side_effect = [{'pin_sha256': 'a'}, {'pin_sha256': 'b'}]
            with self.assertRaisesRegex(ValueError, 'pins differ'):
                compare_campaigns.compare_campaigns(Mock(), '/old', '/new', (1, 2), (3, 4), '/comparison')
            checkout.side_effect = [{'root': '/old', 'pin_sha256': 'a'}, {'root': '/new', 'pin_sha256': 'a'}]
            assertions.side_effect = [{'reader_test.go': 'a'}, {'reader_test.go': 'b'}]
            with self.assertRaisesRegex(ValueError, 'assertions or native helper sources changed'):
                compare_campaigns.compare_campaigns(Mock(), '/old', '/new', (1, 2), (3, 4), '/comparison')
            admit.assert_not_called()
            execute.assert_not_called()


if __name__ == '__main__':
    unittest.main()
