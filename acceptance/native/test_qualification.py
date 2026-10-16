"""File-only adversarial checks of execution coverage; no native tools run."""
from contextlib import ExitStack
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import qualification as proof
import qualification_capture as capture
import qualification_complete as completion


ENVIRONMENT = {'os': 'darwin', 'architecture': 'synthetic', 'version': '15.0',
               'build': 'synthetic-build', 'toolchain': 'file-only control',
               'flags': [], 'race': False,
               'tools': [{'path': 'tools/control', 'bytes': 1, 'sha256': 'a' * 64}]}
ORIGIN = {'GITHUB_SHA': 'synthetic', 'GITHUB_RUN_ID': 'synthetic',
          'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_JOB': 'control'}


class FileReplay:
    production = 'b' * 64

    def __init__(self, root, contents=(b'plain bytes', b'plain bytes')):
        self.files = {}
        self.images = []
        for host, content in zip(('linux', 'windows'), contents):
            path = root / host / 'UDRO.dmg'
            path.parent.mkdir(parents=True)
            path.write_bytes(content)  # Plain synthetic text, never an image.
            self.images.append(path)
            file = {'path': 'APFS_OUTPUT/macos-15/apfs/UDRO.dmg', 'bytes': len(content),
                    'sha256': hashlib.sha256(content).hexdigest()}
            entry = {'record': {'plan': {'environment': {'os': host},
                     'inputs': [{'id': 'control', 'tree_sha256': 'c' * 64, 'use': 'retained'}]}}}
            case = {'family': 'control', 'test': 'TestControl/macos-15/apfs/UDRO',
                    'corpus': 'control', 'manifest': 'macos-15/manifest.json',
                    'native_case': 'cases/apfs', 'source': 15, 'variant': 'UDRO',
                    'outputs': [file['path']]}
            self.files[path.resolve()] = (entry, file, [case])

    def file(self, path, verify=True):
        value = self.files[Path(path).resolve()]
        if verify:
            proof.require(proof.file_digest(path) == value[1]['sha256'], 'output changed')
        return value

    def verify_inputs(self):
        pass


class NativeExecution(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.stack.enter_context(patch.dict(os.environ, ORIGIN))
        self.stack.enter_context(patch.object(proof, 'native_environment', return_value=copy.deepcopy(ENVIRONMENT)))
        self.contract = self.stack.enter_context(patch.object(proof, 'native_contract', return_value='d' * 64))
        self.stack.enter_context(patch.object(proof, 'source_identities', return_value=(FileReplay.production, 'e' * 64)))
        self.stack.enter_context(patch.object(completion, 'source_identities', return_value=(FileReplay.production, 'e' * 64)))
        self.stack.enter_context(patch.object(completion, 'native_contract', self.contract))
        self.replay = FileReplay(self.root)

    def evidence(self, name='control', images=None):
        evidence = proof.NativeEvidence(self.replay, images or self.replay.images, self.root,
                                        self.root, name, 15, continuation=True)
        self.addCleanup(lambda: evidence.stream.close())
        return evidence

    def test_identical_plaintext_aliases_retain_every_host_obligation(self):
        evidence = self.evidence()
        with evidence.case(self.replay.images):
            self.assertEqual(self.replay.images[0].read_bytes(), b'plain bytes')
        record = evidence.finish()
        self.assertEqual(len(record['verdicts']), 2)
        proof.verify_events(evidence.events, record['plan'])
        self.assertTrue(evidence.base.with_suffix('.receipt.json').is_file())
        self.assertEqual(completion.complete([evidence.base.with_suffix('.plan.json')], self.root), 1)

    def test_completion_requires_original_plan_origin_outputs_and_all_verdicts(self):
        evidence = self.evidence()
        with evidence.case(self.replay.images):
            pass
        original = evidence.finish()
        plan = evidence.base.with_suffix('.plan.json')
        destination = evidence.base.with_suffix('.receipt.json')
        def dropped_verdict(record):
            record['verdicts'].pop()
        def skipped(record):
            record['verdicts'][0]['status'] = 'skip'
        def substituted_plan(record):
            record['plan']['environment']['race'] = True
            record['fingerprint'] = proof.identity(record['plan'])
        def wrong_origin(record):
            record['origin']['run'] = 'another-run'
        def missing_output(record):
            record['outputs'].pop()
        for mutation in (dropped_verdict, skipped, substituted_plan, wrong_origin, missing_output):
            altered = copy.deepcopy(original)
            mutation(altered)
            destination.write_text(json.dumps(altered))
            with self.subTest(mutation=mutation.__name__), self.assertRaises(ValueError):
                completion.complete([plan], self.root)
        destination.write_text(json.dumps(original))
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            completion.complete([plan, plan], self.root)
        with self.assertRaisesRegex(ValueError, 'missing/extra'):
            completion.complete([plan, self.root / 'missing.plan.json'], self.root)
        extra = self.root / 'unplanned.receipt.json'
        extra.write_text(json.dumps(original))
        with self.assertRaisesRegex(ValueError, 'missing/extra'):
            completion.complete([plan], self.root)

    def test_missing_or_duplicate_completion_cannot_qualify_a_set(self):
        evidence = self.evidence()
        with evidence.case(self.replay.images[:1]):
            pass
        with self.assertRaisesRegex(ValueError, 'missing'):
            evidence.finish()
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            with evidence.case(self.replay.images[:1]):
                pass
        self.assertFalse(evidence.base.with_suffix('.receipt.json').exists())

    def test_failed_assertion_never_publishes_a_receipt(self):
        evidence = self.evidence()
        with self.assertRaisesRegex(RuntimeError, 'deliberate failure'):
            with evidence.case(self.replay.images):
                raise RuntimeError('deliberate failure')
        with self.assertRaisesRegex(ValueError, 'failed'):
            proof.verify_events(evidence.events, evidence.plan)
        self.assertFalse(evidence.base.with_suffix('.receipt.json').exists())

    def test_changed_output_or_native_source_invalidates_completion(self):
        evidence = self.evidence()
        with evidence.case(self.replay.images):
            pass
        self.replay.images[0].write_bytes(b'changed after checking')
        with self.assertRaisesRegex(ValueError, 'changed'):
            evidence.finish()
        self.assertFalse(evidence.base.with_suffix('.receipt.json').exists())
        self.replay.images[0].write_bytes(b'plain bytes')
        self.contract.return_value = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'sources changed'):
            evidence.finish()

    def test_random_ciphertext_requires_individual_checks(self):
        self.replay = FileReplay(self.root / 'random', (b'ciphertext one', b'ciphertext two'))
        evidence = self.evidence()
        with self.assertRaisesRegex(ValueError, 'different bytes'):
            with evidence.case(self.replay.images):
                self.fail('different ciphertexts shared a verdict')
        for image in self.replay.images:
            with evidence.case([image]):
                self.assertTrue(image.read_bytes().startswith(b'ciphertext'))
        self.assertEqual(len(evidence.finish()['verdicts']), 2)

    def test_duplicate_required_outputs_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'duplicate required'):
            self.evidence(images=[self.replay.images[0]] * 2)

    def test_source_case_cannot_claim_another_source_output(self):
        self.replay.files[self.replay.images[0].resolve()][2][0]['source'] = 26
        with self.assertRaisesRegex(ValueError, 'output source differs'):
            self.evidence()

    def test_event_coverage_rejects_skips_holes_and_duplicate_verdicts(self):
        evidence = self.evidence()
        for image in self.replay.images:
            with evidence.case([image]):
                pass
        evidence.finish()
        original = evidence.events.read_text()
        verdict = next(line for line in original.splitlines(True) if '"pass"' in line and '"Test"' in line)
        for altered in (original.replace(verdict, ''), original + verdict,
                        original.replace('"pass"', '"skip"', 1)):
            evidence.events.write_text(altered)
            with self.assertRaises(ValueError):
                proof.verify_events(evidence.events, evidence.plan)


class CaptureObservations(unittest.TestCase):
    def test_capture_requires_each_reviewed_case_and_preserves_originals(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, ORIGIN), \
             patch.object(capture, 'native_environment', return_value=copy.deepcopy(ENVIRONMENT)), \
             patch.object(capture, 'native_contract', return_value='d' * 64):
            root = Path(temporary)
            contract = root / 'acceptance/qualification'
            contract.mkdir(parents=True)
            entry = {'id': 'control', 'bindings': [{'family': 'control', 'capture_class': 'apple-independent'}],
                     'captures': [{'major': 15, 'manifest': 'macos-15/manifest.json', 'contract': 'native-control', 'cases': ['cases/apfs', 'cases/hfsplus']}]}
            (contract / 'corpus.json').write_text(json.dumps({'entries': [entry]}))
            (contract / 'replay.json').write_text(json.dumps({'tests': [{'input': 'control', 'manifest': 'macos-*/manifest.json'}]}))
            source = root / 'capture/macos-15'
            source.mkdir(parents=True)
            manifest = source / 'manifest.json'
            producer = {'system': 'macOS', 'version': '15.0', 'build': 'synthetic-build', 'architecture': 'synthetic'}
            document = {'scenario': 'native-control', 'producer': producer, 'cases': [{'id': 'apfs'}]}
            manifest.write_text(json.dumps(document))
            with self.assertRaisesRegex(ValueError, 'case inventory'):
                capture.capture(15, {'control': source.parent}, root / 'missing-proof', root)
            self.assertFalse((root / 'missing-proof').exists())
            document['cases'].append({'id': 'hfsplus'})
            manifest.write_text(json.dumps(document))
            before = manifest.read_bytes()
            result = capture.capture(15, {'control': source.parent}, root / 'proof', root)
            self.assertEqual(len(result['verdicts']), 2)
            self.assertEqual(result['plan']['production_sha256'], '')
            self.assertEqual(manifest.read_bytes(), before)
            for file in result['outputs']:
                proof.verify_file(root / 'proof', file)

    def test_case_refusals_remain_explicit_capture_observations(self):
        records = capture.case_records({'cases': [{'id': 'apfs'}],
                    'rejections': [{'id': 'signed', 'status': 1}],
                    'sectorProbes': [{'capacity': 4096, 'allWritesSurvived': False}]})
        self.assertEqual(set(records), {'cases/apfs', 'rejections/signed', 'sectorProbes/4096'})
        self.assertEqual(records['rejections/signed']['status'], 1)

    def test_working_mac_is_rejected_before_capture_or_proof_io(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(capture, 'snapshot') as snapshot:
            with self.assertRaises(RuntimeError):
                capture.capture(27, {'control': Path('missing')}, Path('absent-proof'))
            snapshot.assert_not_called()


class EvidenceInputSafety(unittest.TestCase):
    def test_duplicate_json_keys_and_escaping_members_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'receipt.json'
            path.write_text('{"schema":1,"schema":2}')
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                proof.read_document(path)
            for name in ('../outside', '/absolute', 'drive:C', 'a\\b', 'a//b'):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    proof.verify_file(temporary, {'path': name, 'bytes': 0, 'sha256': 'a' * 64})


class NativeReferenceScopes(unittest.TestCase):
    def test_snapshot_parent_is_bound_in_its_retained_reference_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent = root / 'snapshot-reference'
            parent.mkdir()
            (parent / 'manifest.json').write_bytes(b'original parent manifest')
            (parent / 'apfs.dmg').write_bytes(b'original parent bytes')
            (root / 'snapshot-retained.dmg').write_bytes(b'retained lifecycle bytes')
            # The same basename in another scope must never supply the parent.
            (root / 'apfs.dmg').write_bytes(b'wrong directory')
            case = {'kind': 'snapshot-history', 'parentImage': 'apfs.dmg',
                    'parentImageSHA256': proof.file_digest(parent / 'apfs.dmg'),
                    'parentManifestSHA256': proof.file_digest(parent / 'manifest.json'),
                    'states': [{'image': 'snapshot-retained.dmg',
                                'sha256': proof.file_digest(root / 'snapshot-retained.dmg')}]}
            capture.verify_references(root, case)
            (parent / 'apfs.dmg').write_bytes(b'changed original')
            with self.assertRaisesRegex(ValueError, 'digest differs'):
                capture.verify_references(root, case)

    def test_required_continuation_parent_cannot_be_ignored_as_optional(self):
        with tempfile.TemporaryDirectory() as temporary:
            events = Path(temporary) / 'events.jsonl'
            parent = 'TestNativeAPFSImageEditingContinuation'
            child = parent + '/macos-15-apfs.raw'
            plan = {'stage': 'replay', 'required_runs': [parent, child]}
            rows = [{'Action': 'start', 'Package': proof.ACCEPTANCE_PACKAGE}]
            for action, test in [('run', parent), ('run', child), ('pass', child), ('pass', parent)]:
                rows.append({'Action': action, 'Package': proof.ACCEPTANCE_PACKAGE, 'Test': test})
            rows.append({'Action': 'pass', 'Package': proof.ACCEPTANCE_PACKAGE})
            events.write_text(''.join(json.dumps(row) + '\n' for row in rows))
            proof.verify_events(events, plan, optional={parent})
            rows = [row for row in rows if row.get('Test') != parent]
            events.write_text(''.join(json.dumps(row) + '\n' for row in rows))
            with self.assertRaisesRegex(ValueError, 'incomplete'):
                proof.verify_events(events, plan, optional={parent})


if __name__ == '__main__':
    unittest.main()
