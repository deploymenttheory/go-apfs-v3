"""File-only controls for the offline editing collector's host boundary."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import apfs_geometry as capture
import hfs_metadata_growth as hfs_capture
import permission_inheritance as permissions
import apfs_directory_statistics as statistics
import verify_permission_inheritance as verify_permissions
import verify_directory_statistics as verify_statistics
from verify_apfs_offline_editing import compare_statistics


class DirectoryStatistics(unittest.TestCase):
    @staticmethod
    def values(count, size, generation):
        return f'descendants: {count}\nphysical size: {size}\ngen-count: {generation}\n'

    def test_native_stride_is_not_a_command_count(self):
        compare_statistics(self.values(2, 4096, 10), self.values(1, 0, 14),
                           self.values(1, 0, 11))

    def test_exact_totals_and_invalidation_remain_required(self):
        before, after = self.values(2, 4096, 10), self.values(1, 0, 14)
        for actual in (self.values(2, 0, 11), self.values(1, 4096, 11),
                       self.values(1, 0, 10), self.values(1, 0, 9),
                       self.values(1, 0, 0), self.values(1, 0, 2**64)):
            with self.subTest(actual=actual), self.assertRaises(ValueError):
                compare_statistics(before, after, actual)
        with self.assertRaises(ValueError):
            compare_statistics(before, before, self.values(2, 4096, 11))


class CaptureGuard(unittest.TestCase):
    def test_statistics_verification_guards_before_native_tools(self):
        with patch.dict(os.environ, {}, clear=True), \
                patch.object(verify_statistics, 'version') as version, \
                patch.object(verify_statistics, 'Commands') as commands:
            with self.assertRaises(RuntimeError):
                verify_statistics.verify(Path('missing'), Path('absent'), 15)
            version.assert_not_called()
            commands.assert_not_called()

    def test_permission_verification_guards_before_native_tools(self):
        with patch.dict(os.environ, {}, clear=True), \
                patch.object(verify_permissions, 'version') as version, \
                patch.object(verify_permissions, 'Commands') as commands:
            with self.assertRaises(RuntimeError):
                verify_permissions.verify(Path('missing'), Path('absent'), 15)
            version.assert_not_called()
            commands.assert_not_called()

    def test_non_disposable_hosts_fail_before_tools_or_output(self):
        for collector in (capture, hfs_capture, permissions, statistics):
            self.check_collector(collector)

    def check_collector(self, collector):
        for environment in ({}, {'GITHUB_ACTIONS': 'true',
                                'RUNNER_ENVIRONMENT': 'self-hosted'}):
            with self.subTest(environment=environment), tempfile.TemporaryDirectory() as tmp:
                output = Path(tmp) / 'capture'
                with patch.dict(os.environ, environment, clear=True), \
                        patch.object(collector, 'version') as version, \
                        patch.object(collector, 'Commands') as commands:
                    with self.assertRaises(RuntimeError):
                        collector.capture(15, output)
                    version.assert_not_called()
                    commands.assert_not_called()
                    self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
