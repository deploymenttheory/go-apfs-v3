"""File-only checks for native device selection; no Apple command is executed."""
import plistlib
import unittest

from image_repacking import attach


class DeviceSelection(unittest.TestCase):
    def command(self, entries, details=None):
        calls = []
        def fake(*argv):
            calls.append(argv)
            if argv[:2] == ('hdiutil', 'attach'):
                return plistlib.dumps({'system-entities': entries})
            if argv[:2] == ('diskutil', 'info'):
                return plistlib.dumps(details[argv[-1]])
            if argv[:2] == ('hdiutil', 'detach'):
                return b''
            self.fail(f'unexpected command: {argv}')
        return fake, calls

    def bare_apfs(self):
        # The physical device has no content hint on all three CI macOS versions.
        return [{'dev-entry': '/dev/disk5', 'potentially-mountable': False},
                {'dev-entry': '/dev/disk6s1', 'volume-kind': 'apfs',
                 'content-hint': '41504653-0000-11AA-AA11-00306543ECAC'},
                {'dev-entry': '/dev/disk6', 'content-hint': 'EF57347C-0000-11AA-AA11-00306543ECAC'}]

    def test_bare_apfs_uses_reported_physical_store(self):
        entries = self.bare_apfs()
        details = {'/dev/disk6s1': {'APFSPhysicalStores': [{'APFSPhysicalStore': 'disk5'}]},
                   '/dev/disk5': {'WholeDisk': True}}
        # Reordering must not turn the synthesized container into the source disk.
        for ordered in (entries, list(reversed(entries))):
            command, calls = self.command(ordered, details)
            self.assertEqual(attach('fixture.dmg', command)[0], '/dev/disk5')
            self.assertFalse(any(c[:2] == ('hdiutil', 'detach') for c in calls))

    def test_outside_partitioned_or_multiple_stores_are_refused_and_detached(self):
        for stores, whole in [([{'APFSPhysicalStore': 'disk0'}], True),
                              ([{'APFSPhysicalStore': 'disk5'}], False),
                              ([{'APFSPhysicalStore': 'disk5'}, {'APFSPhysicalStore': 'disk9'}], True)]:
            command, calls = self.command(self.bare_apfs(), {
                '/dev/disk6s1': {'APFSPhysicalStores': stores}, '/dev/disk5': {'WholeDisk': whole}})
            with self.assertRaises(RuntimeError):
                attach('fixture.dmg', command)
            self.assertEqual(calls[-1], ('hdiutil', 'detach', '/dev/disk5'))
            self.assertFalse(any(c[-1] == '/dev/disk0' for c in calls))

    def test_partition_maps_take_precedence_over_filesystems(self):
        for hint in ('GUID_partition_scheme', 'Apple_partition_scheme'):
            command, _ = self.command([{'dev-entry': '/dev/disk5s2', 'content-hint': 'Apple_HFS'},
                                      {'dev-entry': '/dev/disk5', 'content-hint': hint}])
            self.assertEqual(attach('fixture.dmg', command)[0], '/dev/disk5')

    def test_bare_hfs_and_ambiguous_attachments(self):
        command, _ = self.command([{'dev-entry': '/dev/disk5', 'content-hint': 'Apple_HFS'}])
        self.assertEqual(attach('fixture.dmg', command)[0], '/dev/disk5')
        command, calls = self.command([{'dev-entry': '/dev/disk5'}, {'dev-entry': '/dev/disk6'}])
        with self.assertRaises(RuntimeError):
            attach('fixture.dmg', command)
        self.assertEqual(calls[-1], ('hdiutil', 'detach', '/dev/disk5'))
