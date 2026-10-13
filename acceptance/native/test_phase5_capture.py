"""File-only controls for the phase-5 collector's host boundary."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import phase5_capture as capture


class CaptureGuard(unittest.TestCase):
    def test_non_disposable_hosts_fail_before_tools_or_output(self):
        for environment in ({}, {'GITHUB_ACTIONS': 'true',
                                'RUNNER_ENVIRONMENT': 'self-hosted'}):
            with self.subTest(environment=environment), tempfile.TemporaryDirectory() as tmp:
                output = Path(tmp) / 'capture'
                with patch.dict(os.environ, environment, clear=True), \
                        patch.object(capture, 'version') as version, \
                        patch.object(capture, 'Commands') as commands:
                    with self.assertRaises(RuntimeError):
                        capture.capture(15, output)
                    version.assert_not_called()
                    commands.assert_not_called()
                    self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
