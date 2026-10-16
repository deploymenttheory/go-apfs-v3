import errno
from pathlib import Path
import plistlib
import subprocess
import unittest
from unittest.mock import Mock

import snapshot_reading


class SnapshotCopyTargetCleanup(unittest.TestCase):
    def test_normal_detachment_needs_no_force_or_inventory_probe(self):
        command = Mock()
        snapshot_reading.detach_copy_target(command, '/dev/disk9', Path('/scratch/asr-target.dmg'))
        self.assertEqual([c.args for c in command.call_args_list], [
            ('diskutil', 'unmountDisk', 'force', '/dev/disk9'), ('hdiutil', 'detach', '/dev/disk9')])

    def busy_target(self, target='/scratch/asr-target.dmg', device='/dev/disk9', forced_error=None):
        def invoke(*args):
            if args == ('hdiutil', 'detach', '/dev/disk9'):
                raise subprocess.CalledProcessError(errno.EBUSY, args)
            if args == ('hdiutil', 'info', '-plist'):
                return plistlib.dumps({'images': [{'image-path': target,
                    'system-entities': [{'dev-entry': device}]}]})
            if forced_error and args[-1] == '-force':
                raise forced_error
            return b''
        return Mock(side_effect=invoke)

    def test_busy_discarded_target_is_bound_to_its_image_before_force_detach(self):
        command = self.busy_target()
        snapshot_reading.detach_copy_target(command, '/dev/disk9', Path('/scratch/asr-target.dmg'))
        self.assertEqual(command.call_args_list[-2].args, ('hdiutil', 'info', '-plist'))
        self.assertEqual(command.call_args.args, ('hdiutil', 'detach', '/dev/disk9', '-force'))

    def test_busy_retained_source_or_reassigned_device_is_never_force_detached(self):
        for path, device in (('/scratch/retained-source.dmg', '/dev/disk9'),
                             ('/scratch/asr-target.dmg', '/dev/disk11')):
            with self.subTest(path=path, device=device):
                command = self.busy_target(path, device)
                with self.assertRaisesRegex(RuntimeError, 'disposable image'):
                    snapshot_reading.detach_copy_target(command, '/dev/disk9', Path('/scratch/asr-target.dmg'))
                self.assertFalse(any('-force' in call.args for call in command.call_args_list))

    def test_other_failures_and_failed_force_detach_still_fail_capture(self):
        for code in (errno.EPERM, errno.EIO):
            with self.subTest(code=code):
                command = Mock(side_effect=[b'', subprocess.CalledProcessError(code, ['hdiutil', 'detach'])])
                with self.assertRaises(subprocess.CalledProcessError):
                    snapshot_reading.detach_copy_target(command, '/dev/disk9', Path('/scratch/asr-target.dmg'))
                self.assertEqual(command.call_count, 2)
        command = self.busy_target(forced_error=subprocess.CalledProcessError(errno.EBUSY, ['hdiutil', 'detach']))
        with self.assertRaises(subprocess.CalledProcessError):
            snapshot_reading.detach_copy_target(command, '/dev/disk9', Path('/scratch/asr-target.dmg'))


if __name__ == '__main__':
    unittest.main()
