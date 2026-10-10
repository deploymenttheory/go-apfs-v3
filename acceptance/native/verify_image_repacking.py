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

import encrypted_output
from capture import sha256
from container_building import require_disposable_host
from image_outputs import verify_identical_outputs
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
    require_disposable_host()
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
                images = [args.outputs / f'image-repacking-{consumer}' / f'macos-{major}' / case_id / (encoding + '.dmg')
                          for consumer in args.consumers.split(',')]
                def verify_one(image):
                    before = sha256(image)
                    image_info = plistlib.loads(command('hdiutil', 'imageinfo', '-plist', image))
                    require(image_info['Format'] == encoding, 'requested DMG encoding')
                    command('hdiutil', 'verify', image)
                    with tempfile.TemporaryDirectory(prefix='apfs-repack-readback-') as work:
                        actual = observe(image, Path(work), command, expected['markers'])
                    for key, value in expected.items():
                        require(actual[key] == value, f'{major}/{case_id}/{encoding}: {key} differs from native source')
                    require(sha256(image) == before, 'verification changed output')
                    return before, len(images)
                checked += verify_identical_outputs(images, verify_one)
                if case_id == 'hfsx-apm-raw' and encoding == 'UDRO':
                    encrypted_output.verify(images, 128, command)
                elif case_id != 'hfsx-apm-raw' and encoding == 'UDZO':
                    encrypted_output.verify(images, 256, command)
                if case_id == 'hfsplus-gpt' and encoding == 'UDZO':
                    encrypted_output.verify(images, 256, command, directory='rewrapped', old_password='public-repack-password')
                    encrypted_output.verify_decrypted(images, command)
        encrypted_corpus = args.corpus.parent / 'encrypted-dmg' / f'macos-{major}'
        encrypted_manifest = json.loads((encrypted_corpus / 'manifest.json').read_text())
        raw_case = next(c for c in encrypted_manifest['cases'] if c['id'] == 'disk-image-encryption/hfsplus-raw-aes256')
        require(sha256(encrypted_corpus / raw_case['image']) == raw_case['sha256'], 'encrypted raw source digest')
        require(sha256(encrypted_corpus / raw_case['files']) == raw_case['filesSHA256'], 'encrypted raw observation digest')
        raw_password = json.loads((encrypted_corpus / raw_case['files']).read_text())['diskImage']['password']
        source = encrypted_corpus / raw_case['image']
        expected = encrypted_output.disk_hash(source, encrypted_output.password_command(command, source, raw_password))
        images = [args.outputs / f'image-repacking-{host}' / f'macos-{major}' / 'hfsplus-encrypted-raw' / 'UDZO.dmg'
                  for host in args.consumers.split(',')]
        require(len(images) == 3 and len({sha256(p) for p in images}) == 1, 'decrypted raw source differs across hosts')
        before = sha256(images[0])
        native = plistlib.loads(command('hdiutil', 'imageinfo', '-plist', images[0]))
        require(native['Format'] == 'UDZO' and not native['Properties']['Encrypted'], 'raw-source decryption policy')
        command('hdiutil', 'verify', images[0])
        require(encrypted_output.disk_hash(images[0], command) == expected, 'decrypted raw disk differs from Apple source')
        require(sha256(images[0]) == before, 'native verification changed decrypted raw image')
        encrypted_output.verify(images, 128, command, old_password=raw_password)
        require(sha256(source) == raw_case['sha256'], 'encrypted raw source changed during native readback')
    print(f'Native sector preservation, filesystem/snapshot readback and cross-host reproducibility passed: {checked} DMGs.')


if __name__ == '__main__':
    main()
