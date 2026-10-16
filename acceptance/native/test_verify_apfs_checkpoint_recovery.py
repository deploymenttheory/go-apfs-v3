"""Native verification must refuse the working Mac before any tool or output."""
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import verify_apfs_checkpoint_recovery as verifier


class CheckpointVerifierSafety(unittest.TestCase):
    def test_guard_precedes_version_capture_and_output_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'diagnostics'
            with patch.dict(os.environ, {}, clear=True), patch.object(verifier, 'version') as version:
                with self.assertRaises(RuntimeError):
                    verifier.verify(27, Path('missing'), Path('missing'), output)
                version.assert_not_called()
            self.assertFalse(output.exists())

    def test_hard_link_metadata_updates_leave_forks_and_other_objects_intact(self):
        original = {'entries': [{'path': 'Fixture/retained', 'mode': 0o100644,
                                'rawAttributes': {'com.apple.ResourceFork': {'sha256': 'original'}}},
                               {'path': 'Fixture/alias', 'mode': 0o100644},
                               {'path': 'Fixture/Example.app', 'mode': 0o40755, 'changeNS': 1}]}
        changed = verifier.changed_observation(original, mode=0o600)
        self.assertEqual(changed['entries'][0]['mode'], 0o100600)
        self.assertEqual(changed['entries'][1]['mode'], 0o100600)
        self.assertEqual(changed['entries'][0]['rawAttributes'], original['entries'][0]['rawAttributes'])
        self.assertEqual(changed['entries'][2], original['entries'][2])
        self.assertEqual(original['entries'][0]['mode'], 0o100644)


class ZeroSource(io.RawIOBase):
    """Stream the real 128 MiB boundary with bounded memory and no disk image."""
    def __init__(self):
        self.remaining = 128 << 20
    def read(self, size=-1):
        size = min(size, self.remaining, 64 << 10)
        self.remaining -= size
        return bytes(size)


class CheckpointOutputBindings(unittest.TestCase):
    def test_every_torn_write_scope_checks_its_own_recovered_image(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            references = root / 'references'; references.mkdir()
            outputs = root / 'recovered-Windows/macos-26'; outputs.mkdir(parents=True)
            cases = [{'id': name, 'native': {'files': {'entries': []}},
                      'source': {'uncompressedSHA256': 'a' * 64}}
                     for name in ('apfs-committed', *['control-' + str(n) for n in range(11)])]
            (references / 'recovery.json').write_text(json.dumps({
                'complete': True, 'major': 26, 'cases': cases}))
            expected = set()
            for case in cases:
                for suffix in ('-UDRO.dmg', '-UDZO.dmg', '-edited.dmg'):
                    image = outputs / (case['id'] + suffix)
                    image.write_bytes(b'ordinary synthetic output')
                    expected.add(image)
            digest = hashlib.sha256()
            for _ in range(2048):
                digest.update(bytes(64 << 10))
            faults = []
            for stage in ('data', 'metadata', 'ephemeral', 'mapping', 'superblock', 'block-zero'):
                image = outputs / ('fault-' + stage + '.dmg')
                image.write_bytes(stage.encode())
                expected.add(image)
                faults.append({'stage': stage, 'partialBytes': 7, 'trace': [{'stage': stage}],
                               'modified': stage == 'block-zero', 'output': image.name,
                               'outputSHA256': hashlib.sha256(image.read_bytes()).hexdigest(),
                               'inputSHA256': digest.hexdigest()})
            (outputs / 'faults.json').write_text(json.dumps({'schema': 1,
                'scenario': 'interrupted-Go-commits', 'producer': {'system': 'windows'},
                'source': 'apfs-committed', 'sourceSHA256': 'a' * 64,
                'modifySeconds': verifier.STAMP, 'cases': faults}))
            completed, active = set(), []
            class Evidence:
                @contextmanager
                def case(self, images):
                    image, = images
                    if image not in expected or image in completed:
                        raise ValueError('wrong or duplicate recovered output scope')
                    active.append(image)
                    yield
                    active.pop()
                    completed.add(image)
                def finish(self):
                    if completed != expected:
                        raise ValueError('required output scopes missing')
            def check(image, *args, **kwargs):
                if image.suffix == '.dmg':
                    self.assertEqual(active, [image], 'native readback is bound to another output')
            def copy(image, raw, *args):
                raw.write_bytes(b'bounded writable scratch control')
            with patch.object(verifier, 'require_disposable_host'), \
                 patch.object(verifier, 'version'), \
                 patch.object(verifier, 'Commands'), \
                 patch.object(verifier, 'check', side_effect=check), \
                 patch.object(verifier, 'writable_copy', side_effect=copy), \
                 patch.object(verifier.gzip, 'open', side_effect=lambda *args: ZeroSource()), \
                 patch('qualification_cases.recovery_verification', return_value=Evidence()):
                verifier.verify(26, references, outputs, root / 'diagnostics')
            self.assertEqual(len(completed), 42)


if __name__ == '__main__':
    unittest.main()
