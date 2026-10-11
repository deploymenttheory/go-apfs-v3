"""Exercise verifier decisions with file-only codec mocks; never mount images."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zlib

import compression_output
import file_compression
from preservation import digest_values
from image_capacity import verify_capacity


class CompressionOutput(unittest.TestCase):
    def test_automatic_capacity_and_explicit_capacity_have_distinct_contracts(self):
        for size in (8 * 1024 * 1024, 9052160):
            verify_capacity(size, False, False)
        for size in (8 * 1024 * 1024 - 4096, 9052161, (1 << 40) + 4096):
            with self.assertRaises(ValueError):
                verify_capacity(size, False, False)
        verify_capacity(160 * 1024 * 1024, True, False)
        verify_capacity(64 * 1024 * 1024, False, True)
        for sensitive, empty in ((True, False), (False, True)):
            with self.assertRaises(ValueError):
                verify_capacity(9052160, sensitive, empty)

    def test_ordinary_writer_inputs_do_not_require_compression_attributes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'Fixture'
            directory = root / 'compression-writing'
            directory.mkdir(parents=True)
            path = directory / 'attribute-edge-3300'
            data = b'Ordinary native input.'
            path.write_bytes(data)
            class Observed(Exception):
                pass
            def observer(observed_root, read):
                self.assertEqual(observed_root, root)
                self.assertEqual(read(path), {'sha256': hashlib.sha256(data).hexdigest()})
                raise Observed()
            with patch('file_compression.xattr') as attribute:
                with self.assertRaises(Observed):
                    file_compression.observe(root, observer, 26)
                attribute.assert_not_called()

    def test_attribute_ownership_preserves_independent_and_inactive_values(self):
        values = {'com.apple.decmpfs': 1, 'com.apple.ResourceFork': 2, 'ordinary': 3}
        self.assertEqual(compression_output.ordinary_attributes({'flags': 0, 'attributes': {}}, values), values)
        self.assertEqual(compression_output.ordinary_attributes({'flags': 32, 'attributes': {}}, values), {'ordinary': 3})
        self.assertEqual(compression_output.ordinary_attributes({'flags': 32, 'attributes': {'com.apple.ResourceFork': 2}}, values),
                         {'com.apple.ResourceFork': 2, 'ordinary': 3})

    def test_native_codec_and_independent_fork_are_both_required(self):
        data = b'Native logical evidence.\n' * 50
        fork = b'Independent resource data.'
        attrs = {'com.apple.ResourceFork': fork}
        expected = {'flags': 0, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'attributes': digest_values(attrs)}
        actual = {'flags': 32, 'attributes': expected['attributes']}
        values = dict(attrs, **{'com.apple.decmpfs': struct.pack('<IIQ', 0x636d7066, 3, len(data)) + zlib.compress(data)})
        def codec(payload, algorithm, size):
            self.assertEqual(algorithm, 0x205)
            result = zlib.decompress(payload, -15)
            self.assertEqual(len(result), size)
            return result
        with patch('capture.native_xattrs', side_effect=lambda *args: dict(values)), patch('file_compression.codec', side_effect=codec):
            compression_output.verify(Path('Fixture/file'), expected, actual, digest_values(attrs), 'zlib')
            with self.assertRaises(ValueError):
                compression_output.verify(Path('Fixture/file'), expected, actual, digest_values(attrs), 'none')
            wrong = dict(expected, sha256='0' * 64)
            with self.assertRaises(ValueError):
                compression_output.verify(Path('Fixture/file'), wrong, actual, digest_values(attrs), 'zlib')
            values.pop('com.apple.ResourceFork')
            with self.assertRaises(ValueError):
                compression_output.verify(Path('Fixture/file'), expected, actual, digest_values(attrs), 'zlib')


if __name__ == '__main__':
    unittest.main()
