import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import Mock

import reference_reuse as reuse


class ReferenceReuseTests(unittest.TestCase):
    def test_ci_without_a_pin_preserves_retained_replay_without_network_or_verdicts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            network, command = Mock(), Mock()
            report = reuse.prepare_ci(root / 'missing.json', root / 'assets', root / 'missing-recipes.json',
                                      run=command, fetcher=network)
            self.assertEqual(report['mode'], 'retained')
            self.assertEqual(report['controls'], '')
            self.assertFalse(report['assertions_executed'])
            network.assert_not_called()
            command.assert_not_called()

    def test_ci_requires_full_asset_admission_and_every_declared_control(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pin, recipes = root / 'pin.json', root / 'replay.json'
            pin.write_text(json.dumps({'catalog': {'sha256': 'a' * 64}}))
            recipes.write_text(json.dumps({'tests': [{'controls': ['copy-setid']},
                                                    {'controls': ['copy-truncation', 'copy-setid']}, {}]}))
            command, network = Mock(), Mock()
            report = reuse.prepare_ci(pin, root / 'assets', recipes, run=command, fetcher=network)
            self.assertEqual(report['mode'], 'reviewed')
            self.assertFalse(report['assertions_executed'])
            self.assertEqual(report['controls'], 'copy-setid,copy-truncation')
            command.assert_called_once_with(['go', 'run', './acceptance/qualification',
                                            '-check-references', str(pin), '-bundle-dir', str(root / 'assets')],
                                           check=True)
            self.assertEqual(network.call_count, 1)
            self.assertEqual(report['pin_sha256'], hashlib.sha256(pin.read_bytes()).hexdigest())
            for rejected in ('fetch', 'admission'):
                with self.subTest(rejected=rejected), self.assertRaisesRegex(ValueError, 'rejected original bytes'):
                    reuse.prepare_ci(pin, root / 'assets', recipes,
                                     run=Mock(side_effect=ValueError('rejected original bytes')) if rejected == 'admission' else command,
                                     fetcher=Mock(side_effect=ValueError('rejected original bytes')) if rejected == 'fetch' else network)

    def test_absent_pin_and_requested_refresh_require_fresh_capture(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            network, command = Mock(), Mock()
            self.assertFalse(reuse.select(root / 'absent', root, run=command, fetcher=network)['reuse'])
            pin = root / 'pin.json'
            pin.write_text('unread because refresh is explicit')
            self.assertFalse(reuse.select(pin, root, fresh=True, run=command, fetcher=network)['reuse'])
            network.assert_not_called()
            command.assert_not_called()

    def test_changed_capture_dependencies_require_fresh_apple_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pin, catalog = root / 'pin.json', root / 'catalog.json'
            pin.write_text(json.dumps({'catalog': {'sha256': 'c' * 64}}))
            catalog.write_text(json.dumps({'capture_contract_sha256': 'a' * 64, 'origin': {'run': '123'}}))
            fetcher = Mock(return_value=catalog)
            command = Mock(return_value='b' * 64 + '\n')
            self.assertFalse(reuse.select(pin, root, run=command, fetcher=fetcher)['reuse'])
            command.return_value = 'a' * 64 + '\n'
            report = reuse.select(pin, root, run=command, fetcher=fetcher)
            self.assertTrue(report['reuse'])
            self.assertEqual(report['origin'], {'run': '123'})
            self.assertTrue(fetcher.call_args.kwargs['metadata_only'])

    def test_missing_assets_do_not_fall_back_after_reference_selection(self):
        with tempfile.TemporaryDirectory() as temporary:
            pin = Path(temporary) / 'pin.json'
            pin.write_text('{}')
            with self.assertRaisesRegex(ValueError, 'changed release'):
                reuse.select(pin, temporary, fetcher=Mock(side_effect=ValueError('changed release')))

    def fixture(self, root, mapping, major=26):
        inputs = root / 'inputs'
        inputs.mkdir()
        entries = []
        for name in mapping:
            files = []
            for version in (15, 26, 27):
                data = f'original Apple {version} bytes'.encode()
                relative = f'macos-{version}/manifest.json'
                path = inputs / name / relative
                path.parent.mkdir(parents=True)
                path.write_bytes(data)
                files.append({'path': relative, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
            entries.append({'id': name, 'files': files})
        return inputs, {'corpus': {'entries': entries}}

    def test_restore_preserves_original_source_bytes_and_explicit_aliases(self):
        mapping = {
            'copy-permissions': {'artifact': 'offline-{major}', 'path': ''},
            'copy-setid-permissions': {'artifact': 'offline-{major}', 'path': ''},
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, manifest = self.fixture(root, mapping)
            before = {str(p): p.read_bytes() for p in inputs.rglob('*') if p.is_file()}
            report = reuse.restore(inputs, manifest, 'offline-26', 26, root / 'result', mapping)
            self.assertEqual(report['original_files'], 1)
            self.assertEqual((root / 'result/macos-26/manifest.json').read_bytes(), b'original Apple 26 bytes')
            self.assertEqual(before, {str(p): p.read_bytes() for p in inputs.rglob('*') if p.is_file()})
            self.assertFalse((root / 'result/macos-15').exists())

    def test_recovery_artifacts_restore_the_original_flat_source_root(self):
        mapping = {'apfs-recovery': {'artifact': 'recovery-{major}', 'path': '', 'source_root': True}}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, manifest = self.fixture(root, mapping)
            reuse.restore(inputs, manifest, 'recovery-26', 26, root / 'result', mapping)
            self.assertEqual((root / 'result/manifest.json').read_bytes(), b'original Apple 26 bytes')
            self.assertFalse((root / 'result/macos-26').exists())

    def test_native_artifact_restores_each_original_capability_directory(self):
        mapping = {'files': {'artifact': 'native-{major}', 'path': 'files'},
                   'native': {'artifact': 'native-{major}', 'path': 'volumes'}}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, manifest = self.fixture(root, mapping)
            reuse.restore(inputs, manifest, 'native-26', 26, root / 'result', mapping)
            self.assertTrue((root / 'result/files/macos-26/manifest.json').is_file())
            self.assertTrue((root / 'result/volumes/macos-26/manifest.json').is_file())

    def test_corruption_conflicting_aliases_and_unsafe_paths_never_publish(self):
        for failure in ('corruption', 'alias', 'escape', 'missing-version'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                mapping = {'files': {'artifact': 'native-{major}', 'path': ''}}
                inputs, manifest = self.fixture(root, mapping)
                if failure == 'corruption':
                    (inputs / 'files/macos-26/manifest.json').write_bytes(b'corrupt')
                elif failure == 'alias':
                    mapping['alias'] = dict(mapping['files'])
                    manifest['corpus']['entries'].append({'id': 'alias', 'files': [
                        {'path': 'macos-26/manifest.json', 'bytes': 1, 'sha256': 'd' * 64}]})
                elif failure == 'escape':
                    manifest['corpus']['entries'][0]['files'][1]['path'] = 'macos-26/../../escape'
                else:
                    manifest['corpus']['entries'][0]['files'].pop(1)
                with self.assertRaises(ValueError):
                    reuse.restore(inputs, manifest, 'native-26', 26, root / 'result', mapping)
                self.assertFalse((root / 'result').exists())
                self.assertFalse(list(root.glob('.reference-*')))

    def test_materialization_requires_go_admission_and_records_no_new_native_verdict(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mapping = reuse.artifact_inputs('apfs-recovery-reference-26', 26)
            inputs, manifest = self.fixture(root, mapping)
            manifest['origin'] = {'run': '123'}
            catalog, pin = root / 'catalog.json', root / 'pin.json'
            catalog.write_text(json.dumps(manifest))
            pin.write_text(json.dumps({'catalog': {'sha256': 'a' * 64}}))
            def admit(arguments, **kwargs):
                self.assertEqual(arguments[:4], ['go', 'run', './acceptance/qualification', '-materialize-references'])
                self.assertEqual(arguments[4], 'apfs-recovery')
                self.assertTrue(kwargs['check'])
                shutil.copytree(inputs, Path(arguments[arguments.index('-input-dir') + 1]))
            proof = root / 'proof/admission.json'
            report = reuse.materialize(pin, root, 'apfs-recovery-reference-26', 26,
                                       root / 'result', root, proof, run=admit, fetcher=Mock(return_value=catalog))
            self.assertEqual(report['kind'], 'approved-native-input-admission')
            self.assertFalse(report['assertions_executed'])
            self.assertEqual(json.loads(proof.read_text()), report)
            self.assertEqual((root / 'result/manifest.json').read_bytes(), b'original Apple 26 bytes')
            with self.assertRaisesRegex(RuntimeError, 'semantic admission failed'):
                reuse.materialize(pin, root, 'apfs-recovery-reference-26', 26,
                                  root / 'refused', root, root / 'failed-proof.json',
                                  run=Mock(side_effect=RuntimeError('semantic admission failed')),
                                  fetcher=Mock(return_value=catalog))
            self.assertFalse((root / 'refused').exists())
            self.assertFalse((root / 'failed-proof.json').exists())


if __name__ == '__main__':
    unittest.main()
