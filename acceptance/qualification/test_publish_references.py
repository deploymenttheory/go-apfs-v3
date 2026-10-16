import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch
import urllib.error

import publish_references as publisher


class CandidatePublication(unittest.TestCase):
    def test_evidence_archive_is_reproducible_and_preserves_original_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence, control = root / 'evidence', root / 'control'
            target = evidence / ('native-scope-' + 'a' * 110) / '.qualification' / ('b' * 64)
            target.mkdir(parents=True); control.mkdir()
            original = b'{"original":"unchanged\\u0000 observation"}\n'
            (target / 'receipt.json').write_bytes(original)
            (control / 'origin.json').write_bytes(b'{"run":"ordinary transport control"}\n')
            first = publisher.archive_evidence(evidence, control, root / 'first.tar.gz')
            second = publisher.archive_evidence(evidence, control, root / 'second.tar.gz')
            self.assertEqual(first, second)
            with tarfile.open(root / 'first.tar.gz') as archive:
                name = 'execution/' + (target / 'receipt.json').relative_to(evidence).as_posix()
                self.assertEqual(archive.extractfile(name).read(), original)
                self.assertTrue(all(m.mtime == 0 and m.uid == 0 and m.gid == 0 for m in archive.getmembers()))
            self.assertEqual((target / 'receipt.json').read_bytes(), original)

    def test_existing_release_objects_are_reused_only_with_exact_addressed_bytes(self):
        client = Mock(repository='owner/filesystems')
        client.repository = 'owner/filesystems'
        data = b'ordinary immutable release transport'
        digest = hashlib.sha256(data).hexdigest()
        asset = {'name': 'sha256-' + digest + '.tar.gz', 'sha256': digest, 'bytes': len(data)}
        client.pages.return_value = [{'id': 12, 'name': asset['name'], 'digest': 'sha256:' + digest,
                                      'size': len(data), 'state': 'uploaded'}]
        self.assertEqual(publisher.upload_immutable(client, 7, asset, Path('/unused')), {**asset, 'id': 12})
        client.upload.assert_not_called()
        client.pages.return_value[0]['digest'] = 'sha256:' + 'a' * 64
        with self.assertRaisesRegex(ValueError, 'differs'):
            publisher.upload_immutable(client, 7, asset, Path('/unused'))

    def fixture(self, temporary, fail_proof=False):
        origin = {'repository': 'owner/filesystems', 'revision': 'b' * 40,
                  'run': '123', 'attempt': '1', 'completed_at': '2026-10-16T03:00:00Z'}
        campaign = {'state': 'ready', 'origin': origin, 'native': {'id': 123}, 'ci': {'id': 124},
                    'jobs': [], 'artifacts': [], 'captures': ['source-control'], 'proof': ['proof-control']}
        client = Mock(repository=origin['repository'])
        client.repository = origin['repository']
        client.request.side_effect = urllib.error.HTTPError('https://api.github.com/release', 404, 'absent', {}, None)
        client.create_candidate_release.return_value = {'id': 7, 'draft': True}
        client.pages.return_value = []
        uploaded = []
        def upload(release, asset, path):
            uploaded.append(asset['name'])
            return {**asset, 'id': 10 + len(uploaded)}
        client.upload.side_effect = upload
        calls = []
        def execute(command, **kwargs):
            calls.append(command)
            if '-capture-contract' in command:
                return subprocess.CompletedProcess(command, 0, stdout='a' * 64 + '\n', stderr='')
            if '-prepare-references' in command:
                candidate = Path(command[command.index('-candidate-dir') + 1]); candidate.mkdir()
                raw = b'ordinary synthetic bundle control'
                digest = hashlib.sha256(raw).hexdigest()
                (candidate / ('sha256-' + digest + '.tar.gz')).write_bytes(raw)
                publisher.write_document(candidate / 'candidate.json', {'schema': 1,
                    'capture_contract_sha256': 'a' * 64, 'corpus': {'schema': 1, 'entries': []},
                    'bundles': [{'sha256': digest, 'bytes': len(raw)}]})
                return subprocess.CompletedProcess(command, 0)
            if '-check-reference-evidence' in command:
                summary = {'schema': 1, 'capture_contract_sha256': 'a' * 64, 'origin': origin,
                           'qualified_portable_cases': 9, 'qualified_native_file_obligations': 27}
                return subprocess.CompletedProcess(command, int(fail_proof), stdout=json.dumps(summary),
                                                   stderr='deliberate failed qualification' if fail_proof else '')
            if '-check-references' in command:
                return subprocess.CompletedProcess(command, 0)
            raise AssertionError(command)
        def download(repository, run, captures, proof, workspace, execute):
            evidence = workspace / 'evidence'; evidence.mkdir()
            (evidence / 'original-events.jsonl').write_bytes(b'original control stream\n')
        def assemble(captures, target):
            target.mkdir()
            publisher.write_document(target / 'inputs.json', {'schema': 1, 'inputs': []})
            return target / 'inputs.json'
        return client, campaign, execute, calls, download, assemble

    def test_full_proof_and_final_byte_admission_precede_publication_and_review(self):
        with tempfile.TemporaryDirectory() as temporary:
            client, campaign, execute, calls, download, assemble = self.fixture(temporary)
            def finish(release):
                self.assertTrue(any('-check-references' in c for c in calls))
                self.assertEqual(len(client.upload.call_args_list), 3)
            client.finish_candidate_release.side_effect = finish
            with patch.object(publisher, 'download_campaign', side_effect=download), \
                 patch.object(publisher, 'assemble', side_effect=assemble), \
                 patch.object(publisher, 'create_promotion', return_value='https://example.test/review/1') as promotion, \
                 patch.object(publisher, 'record_qualified') as qualified:
                result = publisher.publish(client, campaign, Path(temporary) / 'publication', execute)
            self.assertEqual(result, 'https://example.test/review/1')
            self.assertEqual(promotion.call_count, 1)
            self.assertEqual(qualified.call_count, 1)
            self.assertFalse(client.create_candidate_release.call_args.args[0] == 'latest')

    def test_failed_qualification_retains_diagnostics_without_creating_a_release_or_pin(self):
        with tempfile.TemporaryDirectory() as temporary:
            client, campaign, execute, calls, download, assemble = self.fixture(temporary, fail_proof=True)
            workspace = Path(temporary) / 'publication'
            with patch.object(publisher, 'download_campaign', side_effect=download), \
                 patch.object(publisher, 'assemble', side_effect=assemble):
                with self.assertRaises(subprocess.CalledProcessError):
                    publisher.publish(client, campaign, workspace, execute)
            self.assertIn('deliberate failed', (workspace / 'control/evidence.stderr.log').read_text())
            self.assertFalse((workspace / 'references.json').exists())
            client.create_candidate_release.assert_not_called()
            client.upload.assert_not_called()
            client.finish_candidate_release.assert_not_called()


if __name__ == '__main__':
    unittest.main()
