"""File-only negative controls for the native catalog acceptance comparison."""
import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import hfs_catalog_editing
import verify_hfs_catalog_editing
from hfs_editing import STAMP


class CatalogEvidence(unittest.TestCase):
    def test_host_is_refused_before_capture_or_verification(self):
        with patch.dict(os.environ, {}, clear=True), tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            with self.assertRaises(RuntimeError):
                hfs_catalog_editing.capture_case(path, {}, 'hfsplus', path, path, None)
            with self.assertRaises(RuntimeError):
                verify_hfs_catalog_editing.verify(path, path, path, 27, False)

    def test_original_identity_contents_and_forks_cannot_be_normalized_away(self):
        entry = {'path': 'Fixture/Catalog/Forked', 'object': 41, 'mode': 0o100644,
                 'changeNS': 999, 'sha256': 'contents', 'rawAttributes': {'fork': {'size': 4, 'sha256': 'fork'}}}
        before = {'entries': [{'path': 'Fixture/independent', 'object': 41}]}
        expected = {'entries': [entry]}
        actual = copy.deepcopy(expected)
        actual['entries'][0]['changeNS'] = STAMP * 1000000000
        verify_hfs_catalog_editing.compare(actual, expected, before)
        for field, value in [('object', 42), ('sha256', 'wrong'), ('rawAttributes', {})]:
            invalid = copy.deepcopy(actual)
            invalid['entries'][0][field] = value
            with self.assertRaises(ValueError):
                verify_hfs_catalog_editing.compare(invalid, expected, before)

    def test_new_ids_can_differ_but_identity_relationships_cannot(self):
        expected = {'entries': [{'path': 'Fixture/Catalog/a', 'object': 90, 'mode': 0o100644},
                                {'path': 'Fixture/Catalog/b', 'object': 90, 'mode': 0o100644},
                                {'path': 'Fixture/Catalog/c', 'object': 91, 'mode': 0o100644}]}
        actual = copy.deepcopy(expected)
        for entry in actual['entries']:
            entry['object'] += 10
            entry['changeNS'] = STAMP * 1000000000
        verify_hfs_catalog_editing.compare(actual, expected, {'entries': []})
        for index, identity in [(1, 102), (2, 100)]:
            invalid = copy.deepcopy(actual)
            invalid['entries'][index]['object'] = identity
            with self.assertRaises(ValueError):
                verify_hfs_catalog_editing.compare(invalid, expected, {'entries': []})
        with self.assertRaises(ValueError):
            verify_hfs_catalog_editing.compare(actual, expected, {'entries': [{'path': 'Fixture/deleted', 'object': 100}]})


if __name__ == '__main__':
    unittest.main()
