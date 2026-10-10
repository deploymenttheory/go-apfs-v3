"""The readback shortcut must fail closed before downloading old output bytes."""
from contextlib import ExitStack
import io
import json
import unittest
from unittest.mock import patch

import readback_source


class ArchivedReadback(unittest.TestCase):
    def run_source(self, changes=b'', failed=None):
        run = {'status': 'completed', 'path': '.github/workflows/native.yml', 'head_sha': 'a' * 40}
        names = [f'Record Apple filesystem reference data (macOS {n})' for n in (15, 26, 27)]
        names += [f'Compare Go with macOS reference data ({host})' for host in ('Linux', 'Windows', 'macOS')]
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
                     'Compare Go with macOS reference data (Windows)'):
            self.run_source(failed=name)

    def test_invalid_run_id_never_uses_network(self):
        with patch.dict('os.environ', {'READBACK_RUN': '../123'}), patch('urllib.request.urlopen') as network:
            with self.assertRaises(ValueError):
                readback_source.main()
            network.assert_not_called()
