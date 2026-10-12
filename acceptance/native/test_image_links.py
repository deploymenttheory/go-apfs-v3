import importlib
from pathlib import Path
import unittest
from unittest.mock import patch

import image_links
import verify_image_links


class ImageLinkSafetyTests(unittest.TestCase):
    def test_loading_verifier_requires_no_native_libraries(self):
        with patch('ctypes.CDLL', side_effect=AssertionError('native library loaded')):
            importlib.reload(image_links)
            importlib.reload(verify_image_links)

    def test_vm_guard_precedes_files_and_native_tools(self):
        with patch.object(image_links, 'require_disposable_host', side_effect=RuntimeError('disposable VM required')):
            calls = [lambda: image_links.prepare(Path('absent'), None),
                     lambda: image_links.apply(Path('absent'), [], None),
                     lambda: image_links.observe(Path('absent'), 'apfs', None, Path('absent')),
                     lambda: image_links.capture(Path('absent'), Path('absent'), 'apfs', 15)]
            for call in calls:
                with self.assertRaisesRegex(RuntimeError, 'disposable VM required'):
                    call()
        with patch.object(verify_image_links, 'require_disposable_host', side_effect=RuntimeError('disposable VM required')):
            with self.assertRaisesRegex(RuntimeError, 'disposable VM required'):
                verify_image_links.verify(None, None, None, 15, 'apfs', 'apfs')
            with self.assertRaisesRegex(RuntimeError, 'disposable VM required'):
                verify_image_links.verify_continued(None, None, 15, 'apfs', 'apfs')

    def test_identity_comparison_keeps_originals_aliases_and_retired_ids(self):
        before = {'entries': [{'path': 'original', 'object': 19}]}
        ids = verify_image_links.Identities(before)
        expected = {'files': {'entries': [{'path': 'original', 'object': 19},
                                         {'path': 'new', 'object': 20}]}}
        observed = {'entries': [{'path': 'original', 'object': 19}, {'path': 'new', 'object': 100}]}
        ids.compare(observed, expected)
        with self.assertRaisesRegex(ValueError, 'original inode'):
            ids.compare({'entries': [{'path': 'original', 'object': 99}, {'path': 'new', 'object': 100}]}, expected)
        with self.assertRaisesRegex(ValueError, 'distinct and retired'):
            ids.compare({'entries': [{'path': 'replacement', 'object': 100}]},
                        {'files': {'entries': [{'path': 'replacement', 'object': 21}]}})
        with self.assertRaisesRegex(ValueError, 'original inode'):
            ids.compare({'entries': [{'path': 'a', 'object': 100}, {'path': 'b', 'object': 101}]},
                        {'files': {'entries': [{'path': 'a', 'object': 20}, {'path': 'b', 'object': 20}]}})


if __name__ == '__main__':
    unittest.main()
