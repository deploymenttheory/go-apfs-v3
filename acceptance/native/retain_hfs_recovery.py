#!/usr/bin/env python3
"""File-only retention: preserve native documents verbatim in hashed archives.

Large complete observations are compressed, while a readable index exposes
the cases and recovery boundaries. Identical scripts are shared across OS
versions. This utility never mounts a disk or invokes filesystem tools.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import shutil


def archive(data, output):
    encoded = gzip.compress(data, mtime=0)
    output.write_bytes(encoded)
    return {'image': output.name, 'sha256': hashlib.sha256(encoded).hexdigest(),
            'uncompressedSHA256': hashlib.sha256(data).hexdigest(), 'uncompressedBytes': len(data)}


def retain(source, output):
    if output.exists():
        raise FileExistsError(output)
    output.mkdir(parents=True)
    shared = output / 'scripts'
    shared.mkdir()
    for major in (15, 26, 27):
        origin = source / f'macos-{major}'
        raw = (origin / 'recovery.json').read_bytes()
        document = json.loads(raw)
        if not document.get('complete') or document['major'] != major or len(document['cases']) != 8:
            raise ValueError('complete eight-case native recovery document required')
        target = output / origin.name
        target.mkdir()
        for path in origin.iterdir():
            if path.is_file() and path.name != 'recovery.json':
                shutil.copyfile(path, target / path.name)
        for path in (origin / 'scripts').iterdir():
            destination = shared / path.name
            if destination.exists() and destination.read_bytes() != path.read_bytes():
                raise ValueError('native recipe versions differ across captures')
            shutil.copyfile(path, destination)
        evidence = archive(raw, target / 'native-capture.json.gz')
        index = {'schema': 1, 'scenario': 'hfs-journal-recovery-reference',
                 'producer': document['producer'], 'evidence': evidence,
                 'cases': [{'id': case['id'], 'start': case['journal']['start'], 'end': case['journal']['end'],
                            'replaySHA256': case['recovered']['replayArchive']['uncompressedSHA256']}
                           for case in document['cases']]}
        (target / 'recovery.json').write_text(json.dumps(index, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    arguments = parser.parse_args()
    retain(arguments.source, arguments.output)
