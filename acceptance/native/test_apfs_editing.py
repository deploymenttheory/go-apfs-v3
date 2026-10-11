"""File-only checks that native gates reject a working host and wrong outputs."""
import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import apfs_editing
import verify_apfs_editing


class APFSEditEvidence(unittest.TestCase):
    def test_working_host_rejected_before_capture_or_verification(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.dict(os.environ, {}, clear=True):
                with self.assertRaises(RuntimeError):
                    apfs_editing.capture(27, root / 'capture')
                with self.assertRaises(RuntimeError):
                    verify_apfs_editing.verify(root, root, root / 'continued', 27)
            self.assertFalse((root / 'capture').exists())
            self.assertFalse((root / 'continued').exists())

    def test_untouched_metadata_forks_and_identity_are_required(self):
        expected = {'entries': [{'path': 'Fixture/independent', 'object': 41, 'mode': 0o100644,
                                'changeNS': 1, 'sha256': 'contents',
                                'rawAttributes': {'com.apple.ResourceFork': {'sha256': 'fork', 'size': 4}}}]}
        verify_apfs_editing.compare(copy.deepcopy(expected), expected, 'peak')
        for key, value in (('object', 42), ('sha256', 'changed'), ('rawAttributes', {}), ('changeNS', 2)):
            changed = copy.deepcopy(expected)
            changed['entries'][0][key] = value
            with self.assertRaises(ValueError):
                verify_apfs_editing.compare(changed, expected, 'peak')


if __name__ == '__main__':
    unittest.main()
