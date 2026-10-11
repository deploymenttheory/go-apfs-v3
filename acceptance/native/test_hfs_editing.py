"""File-only checks of native admission and independent readback comparisons."""
import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import hfs_editing
import verify_hfs_editing


class ExistingHFSEvidence(unittest.TestCase):
    def test_working_host_is_refused_before_native_commands(self):
        for journaled in (False, True):
            with tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / 'capture'
                with patch.dict(os.environ, {}, clear=True), self.assertRaises(RuntimeError):
                    hfs_editing.capture(27, output, journaled)
                self.assertFalse(output.exists())

    def test_raw_attributes_identity_and_unchanged_times_are_independent_checks(self):
        expected = {'entries': [{'path': 'Fixture/independent', 'object': 42, 'mode': 0o100644,
                                'changeNS': 999, 'sha256': 'contents',
                                'rawAttributes': {'com.apple.ResourceFork': {'sha256': 'fork', 'size': 4}}}]}
        actual = copy.deepcopy(expected)
        actual['entries'][0]['changeNS'] = hfs_editing.STAMP * 1000000000
        verify_hfs_editing.compare(actual, expected, 'final')
        for field, value in (('object', 43), ('sha256', 'different'), ('rawAttributes', {})):
            changed = copy.deepcopy(actual)
            changed['entries'][0][field] = value
            with self.assertRaises(ValueError):
                verify_hfs_editing.compare(changed, expected, 'final')
        expected['entries'][0]['path'] = 'Fixture/untouched'
        actual['entries'][0]['path'] = 'Fixture/untouched'
        with self.assertRaises(ValueError):
            verify_hfs_editing.compare(actual, expected, 'final')


if __name__ == '__main__':
    unittest.main()
