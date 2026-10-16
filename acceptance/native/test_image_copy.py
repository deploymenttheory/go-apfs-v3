import importlib
import copy
from contextlib import nullcontext
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import image_copy
import verify_image_copy


class ImageCopyControls(unittest.TestCase):
    def test_native_guard_precedes_files_and_tools(self):
        with patch.object(image_copy, 'require_disposable_host', side_effect=RuntimeError('disposable VM required')):
            for call in (lambda: image_copy.prepare(Path('absent'), None),
                         lambda: image_copy.apply(Path('absent'), [], None, None),
                         lambda: image_copy.observe(None, None, None, None),
                         lambda: image_copy.capture(Path('absent'), Path('absent'), 'apfs', 15)):
                with self.assertRaisesRegex(RuntimeError, 'disposable VM required'):
                    call()

    def test_portable_host_tree_has_no_case_collisions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'host-source'
            image_copy.host_source(root)
            self.assertEqual((root / 'zero-file').read_bytes(), b'')
            self.assertTrue((root / 'Empty').is_dir())
            for directory in (root, root / 'Nested'):
                names = [p.name.casefold() for p in directory.iterdir()]
                self.assertEqual(len(names), len(set(names)))

    def test_import_requires_no_apple_libraries(self):
        with patch('ctypes.CDLL', side_effect=AssertionError('native library loaded')):
            importlib.reload(image_copy)
            importlib.reload(verify_image_copy)

    def test_verifier_guard_precedes_files_and_tools(self):
        with patch.object(verify_image_copy, 'require_disposable_host', side_effect=RuntimeError('disposable VM required')):
            for call in (lambda: verify_image_copy.verify(None, None, None, 15, 'apfs', 'apfs'),
                         lambda: verify_image_copy.verify_continued(None, None, 15, 'apfs', 'apfs'),
                         lambda: verify_image_copy.inspect(None, None, None, None, None, None)):
                with self.assertRaisesRegex(RuntimeError, 'disposable VM required'):
                    call()

    def test_recent_source_dates_are_not_copy_operation_clocks(self):
        stamp = image_copy.STAMP * 10**9
        old = {'object': 1, 'path': 'Fixture/existing', 'birthNS': stamp - 10,
               'modifyNS': stamp - 10, 'accessNS': stamp - 10, 'changeNS': stamp + 900 * 10**9}
        existing = dict(old, modifyNS=stamp + 901 * 10**9, changeNS=stamp + 1000 * 10**9)
        preserved = dict(existing, object=2, path='Fixture/copied', birthNS=stamp + 1000 * 10**9,
                         accessNS=stamp + 902 * 10**9)
        generated = dict(preserved, object=3, path='Fixture/plain', modifyNS=stamp + 1000 * 10**9,
                         accessNS=stamp + 1000 * 10**9)
        before = {'entries': [old]}
        after = {'entries': [existing, preserved, generated]}
        setter = Mock()
        with patch.object(image_copy, 'require_disposable_host'), \
             patch.object(image_copy, 'metadata_files', side_effect=[before, copy.deepcopy(after), after]), \
             patch.dict(sys.modules, metadata_edits=SimpleNamespace(set_metadata=setter)), \
             patch.object(image_copy.time, 'time', return_value=image_copy.STAMP + 1000), \
             patch.object(image_copy.time, 'time_ns', return_value=stamp + 1000 * 10**9):
            clocks = image_copy.apply(Path('/disposable/Fixture'), [], None, None)
        self.assertEqual(set(setter.call_args_list[0].args[1]), {'birthTime'})
        self.assertEqual(set(setter.call_args_list[1].args[1]), {'birthTime', 'modifyTime', 'accessTime'})
        self.assertEqual(clocks['1'], ['changeNS'])
        self.assertEqual(clocks['2'], ['changeNS'])

    def test_divergent_host_outputs_are_rejected_before_mounting(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            corpus, outputs = root / 'corpus', root / 'outputs'
            for major in (15, 26, 27):
                directory = corpus / f'macos-{major}'
                directory.mkdir(parents=True)
                manifest = {'schema': 1, 'contract': 'existing-apfs-copy',
                            'cases': [{'id': name, 'before': {'files': {'entries': []}}, 'states': {}}
                                      for name in ('apfs', 'apfs-case-sensitive')]}
                (directory / 'manifest.json').write_text(json.dumps(manifest))
            for host, data in [('Linux', b'a'), ('Windows', b'b'), ('macOS', b'a')]:
                directory = outputs / ('apfs-copy-' + host) / 'macos-15' / 'apfs'
                directory.mkdir(parents=True)
                (directory / 'copy-UDRO.dmg').write_bytes(data)
            with patch.object(verify_image_copy, 'require_disposable_host'), \
                 patch.object(verify_image_copy, 'version'), \
                 patch('qualification_cases.image_verification') as evidence, \
                 patch.object(verify_image_copy, 'Commands') as commands:
                evidence.return_value.case.side_effect = lambda images: nullcontext()
                with self.assertRaisesRegex(ValueError, 'byte-identical'):
                    verify_image_copy.verify(corpus, outputs, root / 'continued', 15, 'apfs', 'apfs')
                commands.return_value.assert_not_called()

    def test_later_preservation_clears_only_replaced_operation_clocks(self):
        stamp = image_copy.STAMP * 10**9
        old = {'object': 1, 'path': 'Fixture/changed', 'birthNS': stamp - 10,
               'modifyNS': stamp + 950 * 10**9, 'accessNS': stamp - 10,
               'changeNS': stamp + 950 * 10**9}
        other = dict(old, object=2, path='Fixture/unchanged')
        before = {'entries': [old, other]}
        after = {'entries': [dict(old, modifyNS=stamp - 10, changeNS=stamp + 1000 * 10**9), other]}
        clocks = {'1': ['changeNS', 'modifyNS'], '2': ['changeNS', 'modifyNS']}
        with patch.object(image_copy, 'require_disposable_host'), \
             patch.object(image_copy, 'metadata_files', side_effect=[before, after, after]), \
             patch.dict(sys.modules, metadata_edits=SimpleNamespace(set_metadata=Mock())), \
             patch.object(image_copy.time, 'time', return_value=image_copy.STAMP + 1000), \
             patch.object(image_copy.time, 'time_ns', return_value=stamp + 1000 * 10**9):
            image_copy.apply(Path('/disposable/Fixture'), [], None, None, clocks)
        self.assertEqual(clocks['1'], ['changeNS'])
        self.assertEqual(clocks['2'], ['changeNS', 'modifyNS'])
