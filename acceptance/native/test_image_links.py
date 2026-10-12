from pathlib import Path
import unittest
from unittest.mock import patch

import image_links


class ImageLinkSafetyTests(unittest.TestCase):
    def test_vm_guard_precedes_files_and_native_tools(self):
        with patch.object(image_links, 'require_disposable_host', side_effect=RuntimeError('disposable VM required')):
            calls = [lambda: image_links.prepare(Path('absent'), None),
                     lambda: image_links.apply(Path('absent'), [], None),
                     lambda: image_links.observe(Path('absent'), 'apfs', None, Path('absent')),
                     lambda: image_links.capture(Path('absent'), Path('absent'), 'apfs', 15)]
            for call in calls:
                with self.assertRaisesRegex(RuntimeError, 'disposable VM required'):
                    call()


if __name__ == '__main__':
    unittest.main()
