"""Native verification must refuse the working Mac before any tool or output."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import verify_apfs_checkpoint_recovery as verifier


class CheckpointVerifierSafety(unittest.TestCase):
    def test_guard_precedes_version_capture_and_output_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'diagnostics'
            with patch.dict(os.environ, {}, clear=True), patch.object(verifier, 'version') as version:
                with self.assertRaises(RuntimeError):
                    verifier.verify(27, Path('missing'), Path('missing'), output)
                version.assert_not_called()
            self.assertFalse(output.exists())

    def test_hard_link_metadata_updates_leave_forks_and_other_objects_intact(self):
        original = {'entries': [{'path': 'Fixture/retained', 'mode': 0o100644,
                                'rawAttributes': {'com.apple.ResourceFork': {'sha256': 'original'}}},
                               {'path': 'Fixture/alias', 'mode': 0o100644},
                               {'path': 'Fixture/Example.app', 'mode': 0o40755, 'changeNS': 1}]}
        changed = verifier.changed_observation(original, mode=0o600)
        self.assertEqual(changed['entries'][0]['mode'], 0o100600)
        self.assertEqual(changed['entries'][1]['mode'], 0o100600)
        self.assertEqual(changed['entries'][0]['rawAttributes'], original['entries'][0]['rawAttributes'])
        self.assertEqual(changed['entries'][2], original['entries'][2])
        self.assertEqual(original['entries'][0]['mode'], 0o100644)


if __name__ == '__main__':
    unittest.main()
