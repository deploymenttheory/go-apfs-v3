import json
from pathlib import Path
import tempfile
import unittest

import reference_sources as references


class CaptureAssembly(unittest.TestCase):
    def test_reviewed_projection_covers_every_independent_logical_corpus(self):
        catalog = json.loads((Path(__file__).parent / 'corpus.json').read_text())
        independent = {e['id'] for e in catalog['entries'] if not any(
            b['capture_class'] == 'current-go-experiment' for b in e['bindings'])}
        mapping = references.sources()
        self.assertEqual(set(mapping), independent)
        self.assertNotIn('hfs-header-growth', mapping)
        for alias in ('copy-setid-permissions', 'copy-truncation-permissions', 'hfs-metadata-lifecycle'):
            self.assertNotEqual(mapping[alias]['capture'], alias)

    def test_source_roots_and_nested_families_preserve_original_bytes_without_siblings(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); downloads = root / 'downloads'; downloads.mkdir()
            mapping = {'files': {'artifact': 'capture-{major}', 'path': 'files', 'capture': 'files'},
                       'recovery': {'artifact': 'recovery-{major}', 'path': '', 'capture': 'recovery', 'source_root': True}}
            for major in (15, 26, 27):
                source = downloads / ('capture-' + str(major)) / 'files' / ('macos-' + str(major))
                source.mkdir(parents=True)
                (source / 'original.json').write_bytes(b'unchanged native observations')
                unrelated = downloads / ('capture-' + str(major)) / 'other-family'; unrelated.mkdir()
                (unrelated / 'exclude').write_bytes(b'another logical family')
                source = downloads / ('recovery-' + str(major)); source.mkdir()
                (source / 'original.json').write_bytes(b'unchanged native journal observations')
            original = {str(p): p.read_bytes() for p in downloads.rglob('*') if p.is_file()}
            output = root / 'assembled'
            result = references.assemble(downloads, output, mapping)
            self.assertEqual(len(json.loads(result.read_text())['inputs']), 2)
            self.assertEqual(len(list((output / 'files').rglob('original.json'))), 3)
            self.assertEqual(len(list((output / 'recovery').rglob('original.json'))), 3)
            self.assertFalse(list(output.rglob('exclude')))
            self.assertEqual(original, {str(p): p.read_bytes() for p in downloads.rglob('*') if p.is_file()})

    def test_missing_source_or_alias_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); downloads = root / 'downloads'; downloads.mkdir()
            mapping = {'files': {'artifact': 'capture-{major}', 'path': '', 'capture': 'files'}}
            with self.assertRaisesRegex(ValueError, 'missing/aliased'):
                references.assemble(downloads, root / 'assembled', mapping)


if __name__ == '__main__':
    unittest.main()
