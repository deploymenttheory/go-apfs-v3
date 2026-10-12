"""File-only controls for native directory evidence and identity comparison."""
import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import apfs_directory_editing
import verify_apfs_directory_editing
from apfs_editing import STAMP


class APFSDirectoryEvidence(unittest.TestCase):
    def test_working_host_rejected_before_any_capture_or_verification(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {}, clear=True):
            root = Path(tmp)
            for action in (lambda: apfs_directory_editing.capture(27, root / 'capture'),
                           lambda: verify_apfs_directory_editing.verify(root, root, root / 'continued', 27)):
                with self.assertRaises(RuntimeError):
                    action()
            self.assertFalse((root / 'capture').exists())
            self.assertFalse((root / 'continued').exists())

    def test_moves_preserve_identity_target_and_opaque_forks(self):
        before = {'entries': [{'path': 'Fixture/symlink', 'object': 42},
                              {'path': 'Fixture/independent', 'object': 41}]}
        expected = {'entries': [{'path': 'Fixture/Catalog/symlink', 'object': 42, 'mode': 0o120755,
                                'target': 'fragmented-data', 'changeNS': 1},
                               {'path': 'Fixture/Catalog/Forked', 'object': 41, 'mode': 0o100644,
                                'changeNS': 1, 'sha256': 'contents',
                                'rawAttributes': {'fork': {'sha256': 'fork', 'size': 4}}}]}
        actual = copy.deepcopy(expected)
        for entry in actual['entries']:
            entry['changeNS'] = STAMP * 1000000000
        verify_apfs_directory_editing.compare(actual, expected, before)
        for index, key, value in ((0, 'object', 99), (0, 'target', 'different'),
                                  (1, 'rawAttributes', {}), (1, 'sha256', 'wrong')):
            invalid = copy.deepcopy(actual)
            invalid['entries'][index][key] = value
            with self.assertRaises(ValueError):
                verify_apfs_directory_editing.compare(invalid, expected, before)

    def test_link_equality_and_unrelated_directory_times_are_exact(self):
        expected = {'entries': [{'path': 'Fixture/Catalog/linked', 'object': 22, 'mode': 0o100644, 'links': 2},
                                {'path': 'Fixture/third', 'object': 22, 'mode': 0o100644, 'links': 2},
                                {'path': 'Fixture/guards', 'object': 44, 'mode': 0o40755, 'changeNS': 7, 'modifyNS': 8}]}
        before = {'entries': [{'path': 'Fixture/alias', 'object': 22},
                              {'path': 'Fixture/third', 'object': 22}, {'path': 'Fixture/guards', 'object': 44}]}
        actual = copy.deepcopy(expected)
        for entry in actual['entries'][:2]:
            entry['changeNS'] = STAMP * 1000000000
        verify_apfs_directory_editing.compare(actual, expected, before)
        for index, key, value in ((1, 'object', 23), (1, 'links', 1), (2, 'changeNS', 9), (2, 'modifyNS', 9)):
            invalid = copy.deepcopy(actual)
            invalid['entries'][index][key] = value
            with self.assertRaises(ValueError):
                verify_apfs_directory_editing.compare(invalid, expected, before)


if __name__ == '__main__':
    unittest.main()
