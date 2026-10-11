import tempfile
from pathlib import Path
import unittest

from image_mutation import writable_copy


class WritableCopyAdmission(unittest.TestCase):
    def check_copy(self, changed_size=False, changed_sectors=False, changed_source=False):
        with tempfile.TemporaryDirectory() as work:
            source, destination = Path(work) / 'original.dmg', Path(work) / 'private.dmg'
            source.write_bytes(b'immutable image')
            calls = []
            def command(*argv):
                calls.append(argv)
                destination.write_bytes(b'Apple envelope')
                if changed_source:
                    source.write_bytes(b'changed original')
            def disk_hash(image, command):
                if image == source:
                    return 8192, 'same sectors'
                return (12288 if changed_size else 8192,
                        'changed sectors' if changed_sectors else 'same sectors')
            result = writable_copy(source, destination, command, disk_hash)
            self.assertEqual(result, destination)
            self.assertEqual(calls, [('hdiutil', 'convert', source, '-format', 'UDRW', '-o', destination)])

    def test_exact_sector_copy_is_admitted(self):
        self.check_copy()

    def test_changed_capacity_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'disk size or sectors'):
            self.check_copy(changed_size=True)

    def test_changed_sector_bytes_are_refused(self):
        with self.assertRaisesRegex(ValueError, 'disk size or sectors'):
            self.check_copy(changed_sectors=True)

    def test_original_image_change_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'changed original'):
            self.check_copy(changed_source=True)


if __name__ == '__main__':
    unittest.main()
