#!/usr/bin/env python3
"""File-only retention of verbatim Apple checkpoint evidence and raw disks."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

from retain_hfs_recovery import archive


def retain(source, output):
    if output.exists():
        raise FileExistsError(output)
    output.mkdir(parents=True)
    shared = output / 'scripts'
    shared.mkdir()
    wanted = {filesystem + '-' + shape for filesystem in ('apfs', 'apfs-case-sensitive')
              for shape in ('data', 'mapping', 'committed', 'wrapped', 'bad-mapping', 'bad-object')}
    for major in (15, 26, 27):
        origin = source / f'apfs-recovery-reference-{major}'
        raw = (origin / 'recovery.json').read_bytes()
        document = json.loads(raw)
        if (document.get('schema') != 1 or document.get('scenario') != 'apfs-checkpoint-recovery'
                or not document.get('complete') or document['major'] != major
                or len(document['cases']) != 12 or {case['id'] for case in document['cases']} != wanted):
            raise ValueError('complete native checkpoint corpus required')
        target = output / f'macos-{major}'
        target.mkdir()
        for path in origin.iterdir():
            if path.is_file() and path.name != 'recovery.json':
                shutil.copyfile(path, target / path.name)
        for path in (origin / 'scripts').iterdir():
            if hashlib.sha256(path.read_bytes()).hexdigest() != document['producer']['sources'][path.name]:
                raise ValueError('capture source hash mismatch')
            destination = shared / path.name
            if destination.exists() and destination.read_bytes() != path.read_bytes():
                raise ValueError('native capture revisions differ across macOS versions')
            shutil.copyfile(path, destination)
        evidence = archive(raw, target / 'native-capture.json.gz')
        index = {'schema': 1, 'scenario': 'apfs-checkpoint-recovery-reference',
                 'producer': document['producer'], 'evidence': evidence,
                 'cases': [{'id': case['id'], 'sourceSHA256': case['source']['uncompressedSHA256'],
                            'latestTransaction': case['checkpoint']['latest']['xid'],
                            'selectedTransaction': case['native']['selectedXID'],
                            'derivedDamage': case.get('damage')}
                           for case in document['cases']]}
        (target / 'recovery.json').write_text(json.dumps(index, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    arguments = parser.parse_args()
    retain(arguments.source, arguments.output)
