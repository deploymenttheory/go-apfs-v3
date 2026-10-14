import importlib
import unittest
from unittest.mock import Mock, patch
import plistlib

import apfs_lifecycle


class APFSLifecycleControls(unittest.TestCase):
    def test_native_guard_precedes_all_files_and_tools(self):
        with patch.dict('os.environ', {}, clear=True):
            for call in (lambda: apfs_lifecycle.capture(None, None, 15),
                         lambda: apfs_lifecycle.capture_clones(None, False, None, None, None, None),
                         lambda: apfs_lifecycle.capture_revert(None, None, None, None, None, None),
                         lambda: apfs_lifecycle.capture_state(None, None, None, None, None, None, None, None),
                         lambda: apfs_lifecycle.mutate(None, None, None, None, None, None),
                         lambda: apfs_lifecycle.storage(None, None, None),
                         lambda: apfs_lifecycle.settled(None, True, None)):
                with self.assertRaisesRegex(RuntimeError, 'disposable GitHub-hosted VM'):
                    call()

    def test_import_loads_no_native_library(self):
        with patch('ctypes.CDLL', side_effect=AssertionError('native library loaded')):
            importlib.reload(apfs_lifecycle)

    def test_equal_bytes_and_independent_inodes_do_not_prove_sharing(self):
        def mapping(inode, offset):
            return {'object': inode, 'ranges': [{'physical': offset, 'length': 4096}]}
        mapped = {'data': mapping(3, 4096), 'alias': mapping(3, 4096),
                  'clone': mapping(4, 8192), 'ordinary-copy': mapping(5, 12288)}
        mapped.update({name + '/..namedfork/rsrc': value for name, value in list(mapped.items())})
        with self.assertRaisesRegex(ValueError, 'did not share physical storage'):
            apfs_lifecycle.validate_shared(mapped)
        mapped['clone']['ranges'][0]['physical'] = 4096
        apfs_lifecycle.validate_shared(mapped)

    def test_conversion_requires_explicit_settled_native_state(self):
        info = {'APFSContainerReference': 'disk42', 'DeviceIdentifier': 'disk42s1', 'FileVault': True}
        def inventory(on):
            return plistlib.dumps({'Containers': [{'Volumes': [{'DeviceIdentifier': 'disk42s1', 'CryptoMigrationOn': on}]}]})
        command = Mock(side_effect=[inventory(True), inventory(False)])
        with patch.object(apfs_lifecycle, 'require_runner'), \
             patch.object(apfs_lifecycle, 'native_info', return_value=info), \
             patch.object(apfs_lifecycle.time, 'sleep') as sleep:
            result = apfs_lifecycle.settled('disk42s1', True, command)
        self.assertFalse(result['volume']['CryptoMigrationOn'])
        sleep.assert_called_once_with(1)

    def test_missing_migration_observation_is_not_a_completed_conversion(self):
        info = {'APFSContainerReference': 'disk42', 'DeviceIdentifier': 'disk42s1', 'FileVault': True}
        command = Mock(return_value=plistlib.dumps({'Containers': [{'Volumes': [{'DeviceIdentifier': 'disk42s1'}]}]}))
        with patch.object(apfs_lifecycle, 'require_runner'), patch.object(apfs_lifecycle, 'native_info', return_value=info):
            with self.assertRaisesRegex(ValueError, 'conversion state is absent'):
                apfs_lifecycle.settled('disk42s1', True, command)

    def test_settlement_deadline_never_publishes_an_in_progress_state(self):
        info = {'APFSContainerReference': 'disk42', 'DeviceIdentifier': 'disk42s1', 'FileVault': True}
        command = Mock(return_value=plistlib.dumps({'Containers': [{'Volumes': [{'DeviceIdentifier': 'disk42s1', 'CryptoMigrationOn': True}]}]}))
        with patch.object(apfs_lifecycle, 'require_runner'), \
             patch.object(apfs_lifecycle, 'native_info', return_value=info), \
             patch.object(apfs_lifecycle.time, 'monotonic', side_effect=[0, 100]):
            with self.assertRaisesRegex(RuntimeError, 'did not settle'):
                apfs_lifecycle.settled('disk42s1', True, command)


if __name__ == '__main__':
    unittest.main()
