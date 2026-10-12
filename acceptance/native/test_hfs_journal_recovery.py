"""File-only safety checks; no native device/tool is opened by these tests."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import hfs_journal_recovery


class JournalCaptureSafety(unittest.TestCase):
    def test_working_mac_is_refused_before_output_or_native_bindings(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'capture'
            with patch.dict(os.environ, {}, clear=True), patch('ctypes.CDLL') as library:
                with self.assertRaises(RuntimeError):
                    hfs_journal_recovery.capture(27, output)
                library.assert_not_called()
            self.assertFalse(output.exists())

    def test_helper_must_own_the_exact_image_device_and_runner_identity(self):
        image = Path('/private/tmp/disposable.raw')
        record = {'image-path': str(image), 'owner-uid': os.getuid(), 'writeable': True,
                  'hdid-pid': 100, 'system-entities': [{'dev-entry': '/dev/disk99'}]}
        self.assertEqual(hfs_journal_recovery.image_helper({'images': [record]}, image, '/dev/disk99'), 100)
        for changed in ({'owner-uid': os.getuid() + 1}, {'writeable': False}, {'hdid-pid': 0},
                        {'image-path': '/private/tmp/unrelated.raw'}, {'system-entities': [{'dev-entry': '/dev/disk0'}]}):
            with self.assertRaises((ValueError, KeyError)):
                hfs_journal_recovery.image_helper({'images': [dict(record, **changed)]}, image, '/dev/disk99')


if __name__ == '__main__':
    unittest.main()
