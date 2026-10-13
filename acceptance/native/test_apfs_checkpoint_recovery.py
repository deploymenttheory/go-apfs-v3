"""File-only controls for native capture safety and retained geometry."""
import gzip
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import apfs_checkpoint_recovery as recovery


class CheckpointCaptureSafety(unittest.TestCase):
    def test_working_mac_is_refused_before_any_output_or_native_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'capture'
            with patch.dict(os.environ, {}, clear=True), patch.object(recovery, 'version') as version:
                with self.assertRaises(RuntimeError):
                    recovery.capture(27, output)
                version.assert_not_called()
            self.assertFalse(output.exists())

    def test_native_descriptor_geometry_is_observed_without_mounting(self):
        corpus = Path(__file__).parents[1] / 'testdata/apfs-editing'
        for major in (15, 26, 27):
            with self.subTest(major=major), tempfile.TemporaryDirectory() as temporary:
                image = Path(temporary) / 'source.raw'
                with gzip.open(corpus / f'macos-{major}/apfs-source.raw.gz', 'rb') as source:
                    image.write_bytes(source.read())
                state = recovery.checkpoints(image)
                self.assertEqual(state['blockZeroXID'], state['latest']['xid'])
                self.assertGreater(state['latest']['descriptorLength'], 1)
                self.assertGreater(state['latest']['dataLength'], 0)
                self.assertFalse(state['future'])
                with image.open('r+b') as stream:
                    stream.seek(80)
                    stream.write(bytes([1]))
                with self.assertRaises(ValueError):
                    recovery.checkpoints(image)


if __name__ == '__main__':
    unittest.main()
