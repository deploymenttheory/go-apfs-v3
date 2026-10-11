import io
import os
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

import hfs_header_growth as growth


class RawHeaders(unittest.TestCase):
    def test_raw_device_reads_are_sector_aligned_and_retain_stale_alternate(self):
        disk = bytearray(16384)
        for offset, blocks in ((1024, 2), (len(disk) - 1024, 1)):
            disk[offset:offset + 2] = b'H+'
            struct.pack_into('>II', disk, offset + 40, 4096, 4)
            struct.pack_into('>QII', disk, offset + 272, blocks * 4096, 32768, blocks)
            struct.pack_into('>II', disk, offset + 288, 1, blocks)
        disk[4096 + 8] = 1
        struct.pack_into('>H', disk, 4096 + 32, 4096)
        class Raw(io.BytesIO):
            def read(self, size):
                if self.tell() % 512 or size % 512:
                    raise OSError('unaligned raw device read')
                return super().read(size)
        with patch('builtins.open', return_value=Raw(disk)):
            state = growth.read_headers('/dev/unused', len(disk))
        self.assertEqual(state['primary']['forks']['catalog']['totalBlocks'], 2)
        self.assertEqual(state['alternate']['forks']['catalog']['totalBlocks'], 1)
        self.assertEqual(state['catalog']['nodeSize'], 4096)

    def test_working_host_is_refused_before_native_commands_or_output_creation(self):
        with patch.dict(os.environ, {}, clear=True), patch('sys.argv', [
                'hfs_header_growth.py', '--expected-major', '27',
                '--go-images', 'unused', '--output', 'unused']), \
                patch.object(growth, 'version') as native, patch.object(Path, 'mkdir') as mkdir:
            with self.assertRaisesRegex(RuntimeError, 'disposable macOS VM'):
                growth.main()
            native.assert_not_called()
            mkdir.assert_not_called()


if __name__ == '__main__':
    unittest.main()
