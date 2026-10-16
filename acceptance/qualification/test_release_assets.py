import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, MagicMock
import urllib.error

import release_assets as assets


class Response(io.BytesIO):
    pass


class ReleaseTransport(unittest.TestCase):
    def pin(self, data):
        digest = hashlib.sha256(data).hexdigest()
        return {'id': 123, 'name': 'sha256-' + digest + '.tar.gz', 'bytes': len(data), 'sha256': digest}

    def test_signed_redirect_never_receives_repository_credentials(self):
        original, anonymous = Mock(), Mock()
        original.open.side_effect = urllib.error.HTTPError('https://api.example.test/asset', 302, 'redirect',
            {'Location': 'https://release-assets.example.test/signed?signature=public-control'}, None)
        data = b'bounded synthetic archive bytes'
        anonymous.open.return_value = Response(data)
        client = assets.GitHub('owner/filesystems', 'private-control-token', api='https://api.example.test',
                               opener=original, anonymous=anonymous)
        with tempfile.TemporaryDirectory() as temporary:
            path = client.download(self.pin(data), temporary)
            self.assertEqual(path.read_bytes(), data)
            client.download(self.pin(data), temporary)
        self.assertEqual(original.open.call_count, 1)
        self.assertEqual(anonymous.open.call_count, 1)
        self.assertEqual(original.open.call_args.args[0].get_header('Authorization'), 'Bearer private-control-token')
        self.assertIsNone(anonymous.open.call_args.args[0].get_header('Authorization'))

    def test_corrupt_truncated_oversized_or_interrupted_assets_never_publish(self):
        data = b'expected bytes'
        for returned in (data[:-1], b'changed bytes!', data + b'extra'):
            with self.subTest(returned=returned), tempfile.TemporaryDirectory() as temporary:
                opener = Mock(); opener.open.return_value = Response(returned)
                client = assets.GitHub('owner/filesystems', '', opener=opener)
                with self.assertRaises(ValueError):
                    client.download(self.pin(data), temporary)
                self.assertEqual(list(Path(temporary).iterdir()), [])
        with tempfile.TemporaryDirectory() as temporary:
            opener = Mock(); opener.open.return_value = MagicMock()
            response = opener.open.return_value
            response.read.side_effect = OSError('deliberate interrupted transfer')
            client = assets.GitHub('owner/filesystems', '', opener=opener)
            with self.assertRaises(OSError):
                client.download(self.pin(data), temporary)
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_unsafe_redirect_cache_or_filename_is_not_admitted(self):
        data = b'expected bytes'
        for target in ('http://assets.example.test/plain', 'https://user:password@assets.example.test/a'):
            original = Mock()
            original.open.side_effect = urllib.error.HTTPError('https://api.github.com/asset', 302, 'redirect',
                                                               {'Location': target}, None)
            client = assets.GitHub('owner/filesystems', 'private-control', opener=original, anonymous=Mock())
            with tempfile.TemporaryDirectory() as temporary, self.assertRaisesRegex(ValueError, 'unsafe'):
                client.download(self.pin(data), temporary)
            client.anonymous.open.assert_not_called()
        with tempfile.TemporaryDirectory() as temporary:
            pin = self.pin(data)
            (Path(temporary) / pin['name']).write_bytes(b'changed bytes!')
            client = assets.GitHub('owner/filesystems', '', opener=Mock())
            with self.assertRaises(ValueError):
                client.download(pin, temporary)
            client.opener.open.assert_not_called()
            pin['name'] = '../escape'
            with self.assertRaises(ValueError):
                client.download(pin, temporary)

    def test_candidate_release_is_explicitly_nonlatest_and_never_overwrites_assets(self):
        client = assets.GitHub('owner/filesystems', '', opener=Mock())
        tag = 'native-corpus-' + 'a' * 16 + '-123-1'
        client.request = Mock(return_value={'id': 4, 'tag_name': tag, 'draft': True, 'prerelease': True})
        client.create_candidate_release(tag, 'main', 'Fully qualified candidate awaiting catalog review')
        value = client.request.call_args.args[2]
        self.assertTrue(value['prerelease'])
        self.assertTrue(value['draft'])
        self.assertEqual(value['make_latest'], 'false')
        self.assertEqual(value['target_commitish'], 'main')
        with self.assertRaises(ValueError):
            client.create_candidate_release('latest', 'main', 'wrong')

    def test_upload_streams_exact_addressed_bytes_and_checks_server_digest(self):
        data = b'original captured archive bytes'
        pin = self.pin(data)
        opener = Mock()
        def receive(request, **kwargs):
            self.assertEqual(request.data.read(), data)
            self.assertEqual(request.get_header('Content-length'), str(len(data)))
            self.assertTrue(request.full_url.startswith('https://uploads.github.com/repos/owner/filesystems/'))
            return Response(json.dumps({'id': 456, 'name': pin['name'], 'size': len(data),
                'state': 'uploaded', 'digest': 'sha256:' + pin['sha256']}).encode())
        opener.open.side_effect = receive
        client = assets.GitHub('owner/filesystems', 'upload-control-token', opener=opener)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / pin['name']; path.write_bytes(data)
            self.assertEqual(client.upload(4, pin, path), {**pin, 'id': 456})
            opener.open.side_effect = lambda *a, **k: Response(json.dumps({'id': 457,
                'name': pin['name'], 'size': len(data), 'state': 'uploaded',
                'digest': 'sha256:' + 'a' * 64}).encode())
            with self.assertRaisesRegex(ValueError, 'identity'):
                client.upload(4, pin, path)

    def test_candidate_becomes_visible_only_on_explicit_completion(self):
        client = assets.GitHub('owner/filesystems', '', opener=Mock())
        client.request = Mock(return_value={'id': 4, 'draft': False, 'prerelease': True})
        client.finish_candidate_release(4)
        self.assertEqual(client.request.call_args.args, ('/repos/owner/filesystems/releases/4', 'PATCH', {
            'draft': False, 'prerelease': True, 'make_latest': 'false'}))

    def reference_release(self):
        archive = b'ordinary archive transport control'
        bundle = self.pin(archive)
        other = self.pin(b'another independent input bundle')
        other['id'] = 126
        evidence = self.pin(b'permanent qualification evidence')
        evidence.update(id=124, name='qualification-sha256-' + evidence['sha256'] + '.tar.gz')
        document = json.dumps({'schema': 1, 'origin': {'repository': 'owner/filesystems'},
            'assets': [bundle, other], 'qualification_evidence': evidence,
            'corpus': {'entries': [{'id': 'files', 'location': {'kind': 'bundle', 'bundle': {
                'sha256': bundle['sha256'], 'bytes': bundle['bytes']}}},
                {'id': 'other', 'location': {'kind': 'bundle', 'bundle': {
                'sha256': other['sha256'], 'bytes': other['bytes']}}}]}}).encode()
        catalog = self.pin(document)
        catalog.update(id=125, name='catalog-sha256-' + catalog['sha256'] + '.json')
        pin = {'schema': 1, 'repository': 'owner/filesystems', 'release_id': 4, 'catalog': catalog}
        data = {125: document, 123: archive, 124: b'permanent qualification evidence',
                126: b'another independent input bundle'}
        opener = Mock()
        opener.open.side_effect = lambda request, **kwargs: Response(data[int(request.full_url.rsplit('/', 1)[-1])])
        client = assets.GitHub(pin['repository'], 'control-token', opener=opener)
        client.request = Mock(return_value={'id': 4, 'prerelease': True, 'draft': False})
        client.pages = Mock(return_value=[{'id': a['id'], 'name': a['name'], 'size': a['bytes'],
            'state': 'uploaded'} for a in (catalog, bundle, evidence, other)])
        return pin, client

    def test_reviewed_download_checks_release_membership_and_original_bytes(self):
        pin, client = self.reference_release()
        with tempfile.TemporaryDirectory() as temporary:
            result = assets.fetch(pin, temporary, client=client)
            self.assertEqual(result.name, pin['catalog']['name'])
            self.assertEqual(len(list(Path(temporary).iterdir())), 4)
        self.assertEqual(client.opener.open.call_count, 4)

    def test_family_fetch_retains_catalog_and_proof_without_unrelated_disk_bundles(self):
        pin, client = self.reference_release()
        with tempfile.TemporaryDirectory() as temporary:
            assets.fetch(pin, temporary, client=client, inputs=['files'])
            self.assertEqual(len(list(Path(temporary).iterdir())), 3)
        self.assertEqual(client.opener.open.call_count, 3)
        requested = [c.args[0].full_url for c in client.opener.open.call_args_list]
        self.assertFalse(any(url.endswith('/126') for url in requested))
        pin, client = self.reference_release()
        with tempfile.TemporaryDirectory() as temporary, self.assertRaises(ValueError):
            assets.fetch(pin, temporary, client=client, inputs=['unknown'])

    def test_capture_policy_fetches_only_catalog_bytes_before_choosing_runner(self):
        pin, client = self.reference_release()
        with tempfile.TemporaryDirectory() as temporary:
            result = assets.fetch(pin, temporary, client=client, metadata_only=True)
            self.assertEqual(list(Path(temporary).iterdir()), [result])
        self.assertEqual(client.opener.open.call_count, 1)
        pin, client = self.reference_release()
        with tempfile.TemporaryDirectory() as temporary, self.assertRaises(ValueError):
            assets.fetch(pin, temporary, client=client, inputs=['files'], metadata_only=True)
        client.opener.open.assert_not_called()

    def test_foreign_missing_or_unpublished_release_never_downloads_inputs(self):
        for mutation in ('unpublished', 'missing', 'foreign', 'wrong-size'):
            pin, client = self.reference_release()
            if mutation == 'unpublished':
                client.request.return_value['draft'] = True
            elif mutation == 'foreign':
                pin['repository'] = 'other/filesystems'
            elif mutation == 'missing':
                client.pages.return_value.pop()
            elif mutation == 'wrong-size':
                client.pages.return_value[0]['size'] += 1
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                with self.assertRaises(ValueError):
                    assets.fetch(pin, temporary, client=client)
                self.assertEqual(client.opener.open.call_count, 1 if mutation == 'missing' else 0)


if __name__ == '__main__':
    unittest.main()
