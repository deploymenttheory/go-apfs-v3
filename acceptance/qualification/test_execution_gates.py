"""Exercise the actual shell completion gate without executing filesystem tools."""
import os
from pathlib import Path
import re
import subprocess
import unittest


class NativeCompletionGate(unittest.TestCase):
    def gate(self):
        workflow = Path(__file__).resolve().parents[2] / '.github/workflows/native.yml'
        section = workflow.read_text().split('\n  complete:\n', 1)[1].split('\n  hfs_reference:\n', 1)[0]
        command = section.split('        run: |\n', 1)[1]
        command = '\n'.join(line[10:] for line in command.splitlines() if line.strip())
        variables = re.findall(r'^          ([A-Z_]+):', section, re.M)
        environment = {name: 'success' for name in variables}
        environment.update(INHERITED='false', REUSED_RUN='')
        return command, environment

    def execute(self, changes):
        command, environment = self.gate()
        result = subprocess.run(['bash', '-e', '-c', command],
                                env=dict(os.environ) | environment | changes,
                                capture_output=True, text=True, check=False)
        return result.returncode == 0

    def test_each_required_native_family_must_succeed(self):
        _, environment = self.gate()
        self.assertTrue(self.execute({}))
        for name in environment:
            if name in ('INHERITED', 'REUSED_RUN'):
                continue
            for result in ('skipped', 'failure', 'cancelled', ''):
                with self.subTest(family=name, result=result):
                    self.assertFalse(self.execute({name: result}))

    def test_only_successful_admission_can_replace_fresh_native_execution(self):
        _, environment = self.gate()
        inherited = {name: 'skipped' for name in environment if name not in ('INHERITED', 'REUSED_RUN', 'EVIDENCE')}
        inherited['INHERITED'] = 'true'
        self.assertTrue(self.execute(inherited))
        for result in ('skipped', 'failure', 'cancelled', ''):
            with self.subTest(admission=result):
                self.assertFalse(self.execute(inherited | {'EVIDENCE': result}))
        for decision in ('false', '', 'unknown'):
            with self.subTest(decision=decision):
                self.assertFalse(self.execute(inherited | {'INHERITED': decision}))


if __name__ == '__main__':
    unittest.main()
