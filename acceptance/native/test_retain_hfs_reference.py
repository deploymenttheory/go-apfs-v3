import gzip
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import retain_hfs_reference as retained


class RetainedEvidence(unittest.TestCase):
    def test_sharing_storage_keeps_original_native_document_and_refuses_replacement(self):
        with tempfile.TemporaryDirectory() as work:
            source = Path(work) / 'capture'
            source.mkdir()
            disk = b'Native device evidence'
            for name in ('before.raw.gz', 'admitted.raw.gz'):
                (source / name).write_bytes(gzip.compress(disk, mtime=0))
            archive = {'image': 'before.raw.gz', 'imageSHA256': retained.digest(source / 'before.raw.gz'),
                       'diskSHA256': hashlib.sha256(disk).hexdigest()}
            admitted = dict(archive, image='admitted.raw.gz')
            recipe = source / 'capture.py'
            recipe.write_text('original native capture recipe\n')
            transcript = source / 'commands.json'
            transcript.write_text('[]\n')
            evidence = {'schema': 1, 'scenario': 'hfs-header-growth', 'complete': True,
                        'commandsSHA256': retained.digest(transcript),
                        'producer': {'version': '27.0.1', 'build': 'fixture-build', 'run': '123',
                                     'revision': 'a' * 40,
                                     'sources': [{'source': recipe.name, 'sha256': retained.digest(recipe)}]},
                        'cases': [{'id': str(i), 'before': dict(archive,headers={'primary':{'forks':{'catalog':{'totalBlocks':10}}}}),
                                   'admitted': admitted, 'after': dict(archive,checker={'status':0},headers={'primary':{'forks':{'catalog':{'totalBlocks':34}}},'alternate':{'forks':{'catalog':{'totalBlocks':34}}}})} for i in range(16)],
                        'sectorProbes': [{'capacity':i, 'allWritesSurvived':True,'markers':[]} for i in range(7)]}
            raw = json.dumps(evidence).encode()
            (source / 'manifest.json').write_bytes(raw)
            destination = Path(work) / 'macos-27'
            retained.retain(source, destination)
            index = json.loads((destination / 'manifest.json').read_text())
            actual = json.loads(gzip.decompress((destination / index['evidence']['image']).read_bytes()))
            self.assertEqual(actual['cases'][0]['admitted']['image'], archive['image'])
            self.assertEqual(gzip.decompress((destination / 'native-capture.json.gz').read_bytes()), raw)
            self.assertFalse((destination / 'admitted.raw.gz').exists())
            with self.assertRaisesRegex(ValueError, 'existing retained corpus'):
                retained.retain(source, destination)

    def test_decoded_archive_is_bounded(self):
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / 'oversized.gz'
            path.write_bytes(gzip.compress(b'x' * 1024))
            with patch.object(retained, 'LIMIT', 128), self.assertRaisesRegex(ValueError, 'excessive decoded'):
                retained.verify_archive(path, hashlib.sha256(b'x' * 1024).hexdigest())

    def test_changed_native_bytes_are_refused(self):
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / 'changed.gz'
            path.write_bytes(gzip.compress(b'changed'))
            with self.assertRaisesRegex(ValueError, 'changed decoded'):
                retained.verify_archive(path, hashlib.sha256(b'original').hexdigest())

    def test_archive_names_cannot_escape_capture(self):
        with tempfile.TemporaryDirectory() as work:
            for name in ('../before.raw.gz', 'nested/file', 'nested\\file', '.', '..'):
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'unsafe retained filename'):
                    retained.file_at(Path(work), name, 'a' * 64)


if __name__ == '__main__':
    unittest.main()
