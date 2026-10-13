import copy
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import image_metadata
import verify_image_metadata


class ImageMetadataTests(unittest.TestCase):
    def test_native_source_requires_vm_before_formatting(self):
        command = MagicMock()
        with patch.object(image_metadata, 'require_disposable_host', side_effect=RuntimeError('disposable VM required')):
            with self.assertRaisesRegex(RuntimeError, 'disposable VM'):
                image_metadata.create_native_source(Path('source.raw'), 'HFS+', False, command, 64 << 20)
        command.assert_not_called()

    def test_new_source_is_formatted_before_raw_attachment(self):
        command = MagicMock()
        for journaled in (False, True):
            with self.subTest(journaled=journaled), \
                    patch.object(image_metadata, 'require_disposable_host'), \
                    patch('image_mutation.writable_copy') as copy_disk:
                image_metadata.create_native_source(Path('source.raw'), 'Case-sensitive HFS+',
                                                    journaled, command, 64 << 20)
                args = command.call_args.args
                self.assertEqual(args[:2], ('hdiutil', 'create'))
                self.assertEqual(args[args.index('-fs') + 1], 'Case-sensitive HFS+')
                self.assertEqual(' -J' in args[args.index('-fsargs') + 1], journaled)
                self.assertEqual(copy_disk.call_args.args[:2], (Path('source.dmg'), Path('source.raw')))

    def test_guards_precede_native_actions_and_output(self):
        with patch.object(image_metadata, 'require_disposable_host', side_effect=RuntimeError('disposable VM required')):
            with self.assertRaisesRegex(RuntimeError, 'disposable VM'):
                image_metadata.capture(Path('absent'), Path('absent-output'), 'apfs', 15)
            with self.assertRaisesRegex(RuntimeError, 'disposable VM'):
                image_metadata.operate(Path('absent'), {'op': 'chown', 'path': 'file'}, None)
            with self.assertRaisesRegex(RuntimeError, 'disposable VM'):
                image_metadata.apply_operations(Path('absent'), [], None)
        with patch.object(verify_image_metadata, 'require_disposable_host', side_effect=RuntimeError('disposable VM required')):
            with self.assertRaisesRegex(RuntimeError, 'disposable VM'):
                verify_image_metadata.verify(None, None, None, 15, 'apfs', 'apfs')

    def test_batch_separates_whole_second_clock_effects(self):
        root = MagicMock()
        file = root.__truediv__.return_value
        old = SimpleNamespace(st_ino=19, st_ctime_ns=100 * 10**9, st_mtime_ns=99 * 10**9)
        changed = SimpleNamespace(st_ino=19, st_ctime_ns=101 * 10**9, st_mtime_ns=99 * 10**9)
        ops = [{'op': 'xattr-remove', 'path': 'file'}, {'op': 'xattr', 'path': 'file'}]
        with patch.object(image_metadata, 'require_disposable_host'), \
             patch.object(image_metadata, 'operate') as operate, \
             patch.object(image_metadata.time, 'time', return_value=100.75), \
             patch.object(image_metadata.time, 'sleep') as sleep:
            # Two baseline stats, then the per-operation before/after stats.
            file.lstat.side_effect = [old, old, old, changed, changed, changed]
            clocks = image_metadata.apply_operations(root, ops, None)
            sleep.assert_called_once()
            self.assertAlmostEqual(sleep.call_args.args[0], 0.26)
            self.assertEqual(operate.call_count, 2)
            self.assertEqual(clocks, {'19': ['changeNS']})

    def test_unchanged_native_metadata_is_not_a_clock_effect(self):
        root = MagicMock()
        entry = SimpleNamespace(st_ino=19, st_ctime_ns=100 * 10**9, st_mtime_ns=99 * 10**9)
        root.__truediv__.return_value.lstat.return_value = entry
        with patch.object(image_metadata, 'require_disposable_host'), \
             patch.object(image_metadata, 'operate'), \
             patch.object(image_metadata.time, 'time', return_value=101.5), \
             patch.object(image_metadata.time, 'sleep') as sleep:
            clocks = image_metadata.apply_operations(root, [{'op': 'xattr', 'path': 'file', 'size': 0}], None)
            sleep.assert_not_called()
            self.assertEqual(clocks, {'19': []})

    def test_only_recorded_clock_fields_are_adjusted(self):
        entry = {'path': 'Fixture/file', 'object': 19, 'uid': 501, 'gid': 20,
                 'flags': 0x8000, 'birthNS': 1700000001234567891,
                 'changeNS': 99, 'modifyNS': 11, 'rawAttributes': {'opaque': {'size': 0, 'sha256': 'empty'}}}
        state = {'files': {'entries': [entry]}, 'clockFields': {'19': ['changeNS']}}
        actual = copy.deepcopy(state['files'])
        actual['entries'][0]['changeNS'] = image_metadata.STAMP * 10**9
        verify_image_metadata.compare(actual, state)
        for key, bad in (('object', 20), ('uid', 0), ('flags', 0), ('birthNS', 1700000001234567890),
                         ('modifyNS', 12), ('rawAttributes', {})):
            damaged = copy.deepcopy(actual)
            damaged['entries'][0][key] = bad
            with self.assertRaises(ValueError, msg=key):
                verify_image_metadata.compare(damaged, state)
        with self.assertRaises(ValueError):
            verify_image_metadata.compare(actual, dict(state, clockFields={'19': ['uid']}))

    def test_namespace_and_link_identity_are_exact(self):
        original = {'entries': [{'path': 'Fixture/a', 'object': 19}, {'path': 'Fixture/b', 'object': 19}]}
        state = {'files': original}
        bad = copy.deepcopy(original)
        bad['entries'][1]['object'] = 20
        with self.assertRaises(ValueError):
            verify_image_metadata.compare(bad, state)
        with self.assertRaises(ValueError):
            verify_image_metadata.compare({'entries': original['entries'][:1]}, state)


if __name__ == '__main__':
    unittest.main()
