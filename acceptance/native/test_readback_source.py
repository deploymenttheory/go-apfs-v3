"""The readback shortcut must fail closed before downloading old output bytes."""
from contextlib import ExitStack
import io
import json
import unittest
from unittest.mock import patch

import readback_source


class ReviewedInputReadbackPrerequisites(unittest.TestCase):
    def job(self, family=None):
        label = f'{family} editing controls' if family else 'filesystem reference data'
        return {'name': f'Restore reviewed Apple {label} (macOS 15, 26 and 27)',
                'conclusion': 'success', 'steps': [
                    {'name': name, 'conclusion': 'success'} for name in [
                        'Restore verified original Apple reference inputs',
                        'Retain reviewed original input bytes (macOS 15)',
                        'Retain reviewed original input bytes (macOS 26)',
                        'Retain reviewed original input bytes (macOS 27)']]}

    def test_complete_reviewed_input_restore_covers_all_original_source_versions(self):
        for family in (None, *readback_source.OFFLINE_FAMILIES):
            with self.subTest(family=family):
                job = self.job(family)
                result = readback_source.restored_input_requirements(job)
                self.assertEqual(len(result), 3)
                self.assertTrue(all(f'macOS {major}' in ' '.join(result) for major in (15, 26, 27)))

    def test_missing_skipped_failed_duplicate_or_unrelated_restore_cannot_replace_inputs(self):
        for mutation in ('missing', 'skipped', 'failed-upload', 'failed-job', 'duplicate', 'unrelated'):
            job = self.job('statistics')
            if mutation == 'missing': job['steps'].pop()
            elif mutation == 'skipped': job['steps'][0]['conclusion'] = 'skipped'
            elif mutation == 'failed-upload': job['steps'][2]['conclusion'] = 'failure'
            elif mutation == 'failed-job': job['conclusion'] = 'failure'
            elif mutation == 'duplicate': job['steps'].append(job['steps'][0])
            elif mutation == 'unrelated': job['name'] = job['name'].replace('statistics', 'unknown')
            with self.subTest(mutation=mutation):
                self.assertEqual(readback_source.restored_input_requirements(job), set())


class ArchivedReadback(unittest.TestCase):
    def run_source(self, changes=b'', failed=None):
        run = {'status': 'completed', 'path': '.github/workflows/native.yml', 'head_sha': 'a' * 40}
        names = [f'Record Apple filesystem reference data (macOS {n})' for n in (15, 26, 27)]
        names += [f'Compare Go with macOS reference data ({host})' for host in ('Linux', 'Windows', 'macOS')]
        names += [f'Build images from macOS {major} references ({host})'
                  for major in (15, 26, 27) for host in ('Linux', 'Windows', 'macOS')]
        jobs = {'jobs': [{'name': n, 'conclusion': 'failure' if n == failed else 'success'} for n in names]}
        responses = [io.BytesIO(json.dumps(value).encode()) for value in (run, jobs)]
        with ExitStack() as stack:
            stack.enter_context(patch.dict('os.environ', {'READBACK_RUN': '123', 'GITHUB_API_URL': 'https://api.example.invalid',
                                                         'GITHUB_REPOSITORY': 'test/repo', 'GH_TOKEN': 'public-test-token'}))
            stack.enter_context(patch('urllib.request.urlopen', side_effect=responses))
            fetch = stack.enter_context(patch('subprocess.run'))
            diff = stack.enter_context(patch('subprocess.check_output', return_value=changes))
            if failed:
                with self.assertRaises(ValueError):
                    readback_source.main()
                fetch.assert_not_called()
                diff.assert_not_called()
            else:
                readback_source.main()
                self.assertEqual(fetch.call_args.args[0][-1], run['head_sha'])

    def test_verifier_only_changes_are_admitted(self):
        self.run_source(b'acceptance/native/image_repacking.py\0docs/packing.md\0.github/workflows/native.yml\0')

    def test_go_tests_fixtures_and_dependencies_require_fresh_outputs(self):
        for path in ('diskimage/encrypt.go', 'acceptance/encrypted_output_test.go',
                     'acceptance/testdata/image.dmg', 'go.mod', 'go.sum', 'internal/names/tables.bin'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.run_source(path.encode() + b'\0')

    def test_each_capture_and_portable_host_must_have_passed(self):
        for name in ('Record Apple filesystem reference data (macOS 15)',
                     'Compare Go with macOS reference data (Windows)',
                     'Build images from macOS 15 references (Windows)',
                     'Build images from macOS 27 references (Linux)'):
            self.run_source(failed=name)

    def test_invalid_run_id_never_uses_network(self):
        with patch.dict('os.environ', {'READBACK_RUN': '../123'}), patch('urllib.request.urlopen') as network:
            with self.assertRaises(ValueError):
                readback_source.main()
            network.assert_not_called()


class ArchivedOfflineReadback(unittest.TestCase):
    def run_source(self, changes=b'', missing=None, paginated=False):
        run = {'status': 'completed', 'path': '.github/workflows/native.yml',
               'head_sha': 'b' * 40}
        required = readback_source.offline_required_jobs('statistics')
        jobs = [{'name': 'offline_edits / ' + name, 'conclusion': 'success'}
                for name in sorted(required) if name != missing]
        pages = [jobs]
        if paginated:
            pages.insert(0, [{'name': f'Unrelated job {n}', 'conclusion': 'success'}
                             for n in range(100)])
        responses = [io.BytesIO(json.dumps(run).encode())]
        responses += [io.BytesIO(json.dumps({'jobs': page}).encode()) for page in pages]
        with ExitStack() as stack:
            stack.enter_context(patch.dict('os.environ', {
                'READBACK_RUN': '123', 'READBACK_SCOPE': 'offline-editing',
                'READBACK_FAMILY': 'statistics', 'GITHUB_API_URL': 'https://api.example.invalid',
                'GITHUB_REPOSITORY': 'test/repo', 'GH_TOKEN': 'public-test-token'}, clear=True))
            network = stack.enter_context(patch('urllib.request.urlopen', side_effect=responses))
            fetch = stack.enter_context(patch('subprocess.run'))
            diff = stack.enter_context(patch('subprocess.check_output', return_value=changes))
            if missing:
                with self.assertRaises(ValueError):
                    readback_source.main()
                fetch.assert_not_called()
                diff.assert_not_called()
            else:
                readback_source.main()
                self.assertEqual(fetch.call_args.args[0][-1], run['head_sha'])
                if paginated:
                    self.assertTrue(network.call_args.args[0].full_url.endswith('page=2'))

    def test_selected_family_reuses_all_source_versions_and_hosts(self):
        self.run_source(b'acceptance/native/verify_apfs_offline_editing.py\0'
                        b'acceptance/native/test_offline_editing.py\0'
                        b'.github/workflows/offline-editing.yml\0')

    def test_required_jobs_can_be_beyond_the_first_api_page(self):
        self.run_source(paginated=True)

    def test_every_selected_capture_and_portable_output_must_have_passed(self):
        for name in readback_source.offline_required_jobs('statistics'):
            with self.subTest(name=name):
                self.run_source(missing=name)

    def test_changed_construction_inputs_require_fresh_outputs(self):
        for path in ('apfs/mutate.go', 'acceptance/apfs_directory_statistics_test.go',
                     'acceptance/testdata/apfs-directory-statistics/macos-15/manifest.json',
                     'go.mod', 'acceptance/native/apfs_geometry.py',
                     'acceptance/native/hfs_metadata_growth.py',
                     'acceptance/native/permission_inheritance.py',
                     'acceptance/native/container_building.py'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.run_source(path.encode() + b'\0')

    def test_unknown_family_never_uses_network(self):
        with patch.dict('os.environ', {'READBACK_RUN': '123',
                                     'READBACK_SCOPE': 'offline-editing',
                                     'READBACK_FAMILY': '../statistics'}), \
                patch('urllib.request.urlopen') as network:
            with self.assertRaises(ValueError):
                readback_source.main()
            network.assert_not_called()
