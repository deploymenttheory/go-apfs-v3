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
                with self.assertRaises(RuntimeError):
                    hfs_journal_recovery.clone_file(output, output)
                library.assert_not_called()
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
