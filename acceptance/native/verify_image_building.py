#!/usr/bin/env python3
"""Check every portable DMG with Apple tools and independent mounted observations.

Expected values come only from native source captures. Native inode numbers may
change during construction; the path-to-inode relationship must remain bijective.
Every output image is checked without repair and attached read-only. No Go runs.
"""
import argparse
import json
from pathlib import Path
import platform
import plistlib
import stat
import subprocess
import tempfile

from capture import observe_files, native_xattrs, sha256
from preservation import digest_values
from verify_preservation import require


def verify(image, expected, sensitive, command):
    before = sha256(image)
    image_info = plistlib.loads(command('hdiutil', 'imageinfo', '-plist', image))
    require(image_info['Format'] == image.stem, 'requested DMG encoding')
    command('hdiutil', 'verify', image)
    attached = plistlib.loads(command('hdiutil', 'attach', '-readonly', '-nomount', '-plist', image))
    devices = [e['dev-entry'] for e in attached['system-entities'] if 'dev-entry' in e]
    require(len(devices) == 1, 'expected one unpartitioned volume image')
    device = devices[0]
    temporary = tempfile.TemporaryDirectory(prefix="apfs-build-readback-")
    try:
        command('/sbin/fsck_hfs', '-fn', device.replace('/dev/disk', '/dev/rdisk'))
        mount = Path(temporary.name) / "mount"
        mount.mkdir()
        command('diskutil', 'mount', 'readOnly', '-mountPoint', mount, device)
        info = plistlib.loads(command('diskutil', 'info', '-plist', device))
        require(info['VolumeName'] == 'Example', 'volume name')
        require(info['TotalSize'] == (160 if sensitive else 8) * 1024 * 1024, 'volume capacity')
        require(('case-sensitive' in info['FilesystemName'].lower()) == sensitive, 'case policy')
        # Capture the root under the same logical spelling as the input tree.
        actual = observe_files(mount)
        for entry in actual['entries']:
            entry['path'] = 'Fixture' + entry['path'][len(mount.name):]
        want = {e['path']: e for e in expected['entries']}
        got = {e['path']: e for e in actual['entries']}
        require(set(got) == set(want), f'exact directory tree: missing={set(want)-set(got)}, extra={set(got)-set(want)}')
        raw = {e['object']: e['attributes'] for e in expected['rawAttributes']}
        forward, reverse = {}, {}
        for path, entry in want.items():
            result = got[path]
            for key in ('mode', 'uid', 'gid', 'flags', 'birthSeconds', 'modifyNS', 'changeNS', 'accessNS', 'attributes'):
                require(result[key] == entry[key], f'{image.name}: {path}: {key}: {result[key]} != {entry[key]}')
            if not stat.S_ISDIR(entry['mode']):
                for key in ('size', 'links', 'sha256', 'target'):
                    require(result.get(key) == entry.get(key), f'{path}: {key}')
            old, new = entry['object'], result['object']
            require(forward.setdefault(old, new) == new and reverse.setdefault(new, old) == old, f'{path}: link identity')
            source = mount if path == 'Fixture' else mount / path.removeprefix('Fixture/')
            require(digest_values(native_xattrs(source, 0x21)) == raw[old], f'{path}: raw attributes/forks')
        command('codesign', '--verify', '--deep', '--strict', mount / 'Example.app')
    finally:
        try:
            command('hdiutil', 'detach', device)
        finally:
            temporary.cleanup()
    require(sha256(image) == before, 'native readback modified output image')
    return before, len(want)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-major', type=int, choices=[15, 26, 27], required=True)
    parser.add_argument('--corpus', type=Path, required=True)
    parser.add_argument('--outputs', type=Path, required=True)
    parser.add_argument('--producers', default='15,26,27')
    parser.add_argument('--consumers', default='Linux,Windows,macOS')
    args = parser.parse_args()
    require(platform.system() == 'Darwin', 'Apple verification requires macOS')
    require(int(subprocess.check_output(['sw_vers', '-productVersion'], text=True).split('.')[0]) == args.expected_major, 'wrong macOS verifier')
    transcript = []
    args.outputs.mkdir(parents=True, exist_ok=True)
    def command(*argv):
        print('verify:', *map(str, argv), flush=True)
        record = {'argv': list(map(str, argv)), 'status': 'started'}
        transcript.append(record)
        def save():
            (args.outputs / f'image-building-{args.expected_major}.diagnostics.json').write_text(json.dumps(transcript, indent=2) + '\n')
        save()
        try:
            r = subprocess.run(list(map(str, argv)), capture_output=True, timeout=120)
        except BaseException as error:
            record.update(status='failed', error=str(error)); save(); raise
        record.update(status=r.returncode, stdout=r.stdout.decode(errors='replace'), stderr=r.stderr.decode(errors='replace')); save()
        require(r.returncode == 0, f'command failed: {argv}: {r.stdout.decode(errors="replace")} {r.stderr.decode(errors="replace")}')
        return r.stdout
    total = 0
    for major in args.producers.split(','):
        corpus = args.corpus / f'macos-{major}'
        manifest = json.loads((corpus / 'manifest.json').read_text())
        require(manifest['schema'] == 1 and manifest['scenario'] == 'image-building', 'corpus schema')
        require(manifest['producer']['version'].split('.')[0] == major, 'source macOS version')
        require({c['id'] for c in manifest['cases']} == {'image-building/hfsplus', 'image-building/hfsx'}, 'case inventory')
        for case in manifest['cases']:
            require(sha256(corpus / case['image']) == case['sha256'], 'source image digest')
            require(sha256(corpus / case['files']) == case['filesSHA256'], 'native observation digest')
            expected = json.loads((corpus / case['files']).read_text())
            case_id = case['id'].split('/')[1]
            for encoding in ('UDRO', 'UDZO'):
                digests = []
                for consumer in args.consumers.split(','):
                    image = args.outputs / f'image-building-{consumer}' / f'macos-{major}' / case_id / (encoding + '.dmg')
                    digest, entries = verify(image, expected, case_id == 'hfsx', command)
                    digests.append(digest); total += entries
                require(len(set(digests)) == 1, f'{case_id}/{encoding}: hosts produced different image bytes')
    print(f'Apple image checks, filesystem checks, exact mounted readback and signature verification passed: {total} entries.')


if __name__ == '__main__':
    main()
