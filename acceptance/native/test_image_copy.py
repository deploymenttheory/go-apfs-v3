import importlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import image_copy


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
