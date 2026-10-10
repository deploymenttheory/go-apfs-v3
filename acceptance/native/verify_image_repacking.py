#!/usr/bin/env python3
"""Verify every portable repack through Apple devices and filesystem APIs.

No Go code supplies the final verdict. Compare whole-disk hashes, partition and
volume inventories, exact native file observations, retained snapshot histories,
encrypted volume unlocking and preserved application signatures.
"""
import argparse
import json
from pathlib import Path
import plistlib
import tempfile

from capture import sha256
from image_repacking import Commands, PROFILES, observe, version
from verify_preservation import require


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-major', type=int, choices=[15, 26, 27], required=True)
    parser.add_argument('--corpus', type=Path, required=True)
    parser.add_argument('--outputs', type=Path, required=True)
    parser.add_argument('--producers', default='15,26,27')
    parser.add_argument('--consumers', default='Linux,Windows,macOS')
    args = parser.parse_args()
    version(args.expected_major)
    command = Commands(args.outputs / f'image-repacking-{args.expected_major}.diagnostics.json')
    checked = 0
    for major in args.producers.split(','):
        corpus = args.corpus / f'macos-{major}'
        manifest = json.loads((corpus / 'manifest.json').read_text())
        require(manifest['schema'] == 1 and manifest['scenario'] == 'image-repacking', 'corpus schema')
        require(manifest['producer']['version'].split('.')[0] == major, 'source macOS version')
        require({c['id'].removeprefix('image-repacking/') for c in manifest['cases']} == PROFILES, 'case inventory')
        for source in manifest['producer']['sources']:
            require(sha256(corpus / source['source']) == source['sha256'], 'source provenance digest')
        for case in manifest['cases']:
            require(sha256(corpus / case['image']) == case['sha256'], 'source image digest')
            require(sha256(corpus / case['observation']) == case['observationSHA256'], 'native observation digest')
            expected = json.loads((corpus / case['observation']).read_text())
            case_id = case['id'].removeprefix('image-repacking/')
            for encoding in ('UDRO', 'UDZO'):
                digests = []
                for consumer in args.consumers.split(','):
                    image = args.outputs / f'image-repacking-{consumer}' / f'macos-{major}' / case_id / (encoding + '.dmg')
                    before = sha256(image)
                    image_info = plistlib.loads(command('hdiutil', 'imageinfo', '-plist', image))
                    require(image_info['Format'] == encoding, 'requested DMG encoding')
                    command('hdiutil', 'verify', image)
                    with tempfile.TemporaryDirectory(prefix='apfs-repack-readback-') as work:
                        actual = observe(image, Path(work), command, expected['markers'])
                    for key, value in expected.items():
                        require(actual[key] == value, f'{major}/{case_id}/{consumer}/{encoding}: {key} differs from native source')
                    require(sha256(image) == before, 'verification changed output')
                    digests.append(before); checked += 1
                require(len(set(digests)) == 1, f'{major}/{case_id}/{encoding}: host output bytes differ')
    print(f'Native sector preservation, filesystem/snapshot readback and cross-host reproducibility passed: {checked} DMGs.')


if __name__ == '__main__':
    main()
