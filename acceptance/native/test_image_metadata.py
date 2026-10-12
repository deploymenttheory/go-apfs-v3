import copy
from pathlib import Path
import unittest
from unittest.mock import patch

import image_metadata
import verify_image_metadata


class ImageMetadataTests(unittest.TestCase):
    def test_guards_precede_native_actions_and_output(self):
        with patch.object(image_metadata, 'require_disposable_host', side_effect=RuntimeError('disposable VM required')):
            with self.assertRaisesRegex(RuntimeError, 'disposable VM'):
                image_metadata.capture(Path('absent'), Path('absent-output'), 'apfs', 15)
            with self.assertRaisesRegex(RuntimeError, 'disposable VM'):
                image_metadata.operate(Path('absent'), {'op': 'chown', 'path': 'file'}, None)
        with patch.object(verify_image_metadata, 'require_disposable_host', side_effect=RuntimeError('disposable VM required')):
            with self.assertRaisesRegex(RuntimeError, 'disposable VM'):
                verify_image_metadata.verify(None, None, None, 15, 'apfs', 'apfs')

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
