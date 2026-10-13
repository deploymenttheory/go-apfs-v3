#!/usr/bin/env python3
"""File-only portable process-interruption check using Apple-created evidence."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def check(executable, references, diagnostics, filesystem='hfs'):
    diagnostics.mkdir(parents=True)
    manifest = json.loads((references / 'recovery.json').read_text())
    case_name = 'apfs-committed' if filesystem == 'apfs' else 'hfsplus-linear'
    source = next(case['source'] for case in manifest['cases'] if case['id'] == case_name)
    if digest(references / source['image']) != source['sha256']:
        raise ValueError('native interruption source digest')
    records = []
    with tempfile.TemporaryDirectory(prefix='journal-interruption-') as temporary:
        work = Path(temporary)
        original = work / 'evidence.raw'
        with gzip.open(references / source['image'], 'rb') as reader, original.open('xb') as writer:
            shutil.copyfileobj(reader, writer, 128 << 10)
        if original.stat().st_size != source['uncompressedBytes'] or digest(original) != source['uncompressedSHA256']:
            raise ValueError('native decoded source digest')
        for attempt in range(3):
            scratch = work / f'scratch-{attempt}'
            scratch.mkdir()
            output = work / f'recovered-{attempt}.dmg'
            environment = dict(os.environ, TMPDIR=str(scratch), TMP=str(scratch), TEMP=str(scratch))
            operation = ['checkpoint', 'recover'] if filesystem == 'apfs' else ['journal', 'replay']
            argv = [str(executable.resolve()), *operation, '--image', str(original), '--output', str(output)]
            record = {'argv': argv, 'interrupted': False}
            with (diagnostics / f'output-{attempt}.log').open('wb') as log:
                process = subprocess.Popen(argv, env=environment, stdout=log, stderr=log)
                try:
                    deadline = time.monotonic() + 30
                    while process.poll() is None and time.monotonic() < deadline:
                        candidates = list(scratch.glob('.apfs-edit-disk-*'))
                        if candidates:
                            partial = candidates[0].stat().st_size
                            if 0 < partial < original.stat().st_size:
                                record.update(interrupted=True, partialBytes=partial)
                                process.kill()
                                break
                        time.sleep(0.001)
                    record['status'] = process.wait(timeout=10)
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=10)
            records.append(record)
            (diagnostics / 'interruption.json').write_text(json.dumps(records, indent=2) + '\n')
            if digest(original) != source['uncompressedSHA256']:
                raise ValueError('interrupted recovery changed source evidence')
            if record['interrupted']:
                if output.exists():
                    raise ValueError('interrupted partial staging published output')
                return
        raise ValueError('could not acquire a partial staging interruption within three attempts')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apfs', type=Path, required=True)
    parser.add_argument('--references', type=Path, required=True)
    parser.add_argument('--diagnostics', type=Path, required=True)
    parser.add_argument('--filesystem', choices=('hfs', 'apfs'), default='hfs')
    arguments = parser.parse_args()
    check(arguments.apfs, arguments.references, arguments.diagnostics, arguments.filesystem)
