#!/usr/bin/env python3
"""Record complete native disks for sector-preserving repacking.

Reuses independently created signed-app and snapshot images. Adds native APM,
bare HFS+ and multi-volume APFS images. Native devices supply disk hashes;
no Go encoder or decoder supplies expected bytes or filesystem observations.
"""
import argparse
from contextlib import ExitStack
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import shutil
import stat
import struct
import subprocess
import tempfile

from capture import create_files, native_xattrs, observe_files, sha256
from snapshot_reading import MOUNT_APFS

PASSWORD = 'public-repack-password'
PROFILES = {'hfsplus-gpt', 'hfsx-apm-raw', 'hfsplus-bare', 'apfs-snapshots', 'apfs-volumes'}


class Commands:
    def __init__(self, diagnostics):
        self.path = diagnostics
        self.records = []

    def __call__(self, *argv, fixture_input=None, expected_success=True):
        display = [str(a) if len(str(a)) <= 256 else f'<{len(str(a))} characters>' for a in argv]
        print('native:', *display, flush=True)
        record = {'argv': list(map(str, argv)), 'status': 'started', 'expectedSuccess': expected_success}
        self.records.append(record)
        self.save()
        try:
            r = subprocess.run(list(map(str, argv)), input=fixture_input, capture_output=True, timeout=120)
        except BaseException as error:
            record.update(status='failed', error=str(error)); self.save(); raise
        record.update(status=r.returncode, stdout=r.stdout.decode(errors='replace'), stderr=r.stderr.decode(errors='replace'))
        self.save()
        if (r.returncode == 0) != expected_success:
            raise RuntimeError(f'command failed: {argv}: {record["stdout"]} {record["stderr"]}')
        return r.stdout

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.records, indent=2) + '\n')


def version(major):
    if platform.system() != 'Darwin':
        raise RuntimeError('native observation requires macOS')
    product = subprocess.check_output(['sw_vers', '-productVersion'], text=True, timeout=10).strip()
    build = subprocess.check_output(['sw_vers', '-buildVersion'], text=True, timeout=10).strip()
    if int(product.split('.')[0]) != major:
        raise RuntimeError(f'expected macOS {major}, received {product}')
    return {'system': 'macOS', 'version': product, 'build': build, 'architecture': platform.machine()}


def attach(image, command, readonly=True):
    data = plistlib.loads(command('hdiutil', 'attach', '-nomount', '-plist',
                                *(['-readonly'] if readonly else []), image))
    entries = [e for e in data['system-entities'] if 'dev-entry' in e]
    whole = [e for e in entries if e.get('content-hint') in ('GUID_partition_scheme', 'Apple_partition_scheme')]
    if not whole:
        whole = [e for e in entries if e.get('content-hint') in ('Apple_HFS', 'Apple_HFSX', 'Apple_APFS')]
    if not whole and len(entries) == 1 and entries[0].get('volume-kind'):
        whole = entries
    if len(whole) != 1:
        if entries:
            command('hdiutil', 'detach', entries[0]['dev-entry'])
        # Do not choose a synthesized APFS device or the first returned partition.
        raise RuntimeError(f'ambiguous image disk: {entries}')
    return whole[0]['dev-entry'], entries


def info(device, command):
    return plistlib.loads(command('diskutil', 'info', '-plist', device))


def files(root):
    result = observe_files(root)
    for entry in result['entries']:
        entry['rawAttributes'] = {name: {'size': len(value), 'sha256': hashlib.sha256(value).hexdigest()}
                                  for name, value in native_xattrs(root.parent / entry['path'], 0x21).items()}
        if stat.S_ISDIR(entry['mode']):
            # Native directory size and synthetic link count vary by kernel.
            del entry['size']; del entry['links']
    return result


def observe(image, work, command, markers=(), raw_output=None):
    before = sha256(image)
    device, entries = attach(image, command)
    try:
        native = info(device, command)
        size = native['TotalSize']
        digest = hashlib.sha256()
        raw_device = device.replace('/dev/disk', '/dev/rdisk')
        with open(raw_device, 'rb', buffering=0) as source, ExitStack() as stack:
            saved = stack.enter_context(gzip.GzipFile(filename=str(raw_output), mode='wb', mtime=0)) if raw_output else None
            remaining = size
            while remaining:
                data = source.read(min(1 << 20, remaining))
                if not data:
                    raise RuntimeError('short native disk read')
                digest.update(data); remaining -= len(data)
                if saved:
                    saved.write(data)
            observed_markers = []
            for marker in markers:
                source.seek(marker['offset'])
                data = source.read(marker['size'])
                actual = {'offset': marker['offset'], 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                if actual != marker:
                    raise RuntimeError('native disk lost unused-sector marker')
                observed_markers.append(actual)
        inventory = plistlib.loads(command('diskutil', 'list', '-plist', device))['AllDisksAndPartitions']
        disk = next(d for d in inventory if d['DeviceIdentifier'] == device.removeprefix('/dev/'))
        partitions = [{key: p[key] for key in ('Content', 'Size', 'DiskUUID') if key in p}
                      for p in disk.get('Partitions', [])]
        volumes = []
        for entry in entries:
            if not entry.get('volume-kind'):
                continue
            volume = entry['dev-entry']
            initial = info(volume, command)
            if initial.get('FileVault'):
                if not initial.get('Locked'):
                    command('diskutil', 'apfs', 'lockVolume', volume)
                    initial = info(volume, command)
                if not initial.get('Locked'):
                    raise RuntimeError('encrypted volume must be locked before native unlock')
                command('diskutil', 'apfs', 'unlockVolume', volume, '-stdinpassphrase', '-nomount',
                        fixture_input=(PASSWORD + '\n').encode())
            mount = work / ('mount-' + volume.removeprefix('/dev/'))
            mount.mkdir()
            command('diskutil', 'mount', 'readOnly', '-mountOptions', 'owners,noatime', '-mountPoint', mount, volume)
            details = info(volume, command)
            if details['WritableVolume'] or not os.statvfs(mount).f_flag & os.ST_RDONLY:
                raise RuntimeError('native mount must be read-only')
            record = {key: details[key] for key in ('VolumeName', 'VolumeUUID', 'FilesystemType', 'FilesystemName', 'VolumeAllocationBlockSize', 'TotalSize')}
            record['encrypted'] = bool(initial.get('FileVault'))
            record['files'] = files(mount / 'Fixture')
            if (mount / 'Fixture/Example.app').exists():
                command('codesign', '--verify', '--deep', '--strict', mount / 'Fixture/Example.app')
                record['signatureVerified'] = True
            if entry['volume-kind'] == 'apfs':
                snapshots = plistlib.loads(command('diskutil', 'apfs', 'listSnapshots', '-plist', volume))['Snapshots']
                record['snapshots'] = []
                for snapshot in snapshots:
                    target = work / ('snapshot-' + str(snapshot['SnapshotXID']))
                    target.mkdir()
                    command(MOUNT_APFS, '-o', 'rdonly,owners,nobrowse,noatime', '-s', snapshot['SnapshotName'], mount, target)
                    try:
                        record['snapshots'].append({key: snapshot[key] for key in ('SnapshotName', 'SnapshotXID', 'SnapshotUUID')} |
                                                   {'files': files(target / 'Fixture')})
                    finally:
                        command('/sbin/umount', target)
                record['snapshots'].sort(key=lambda s: s['SnapshotXID'])
            command('diskutil', 'verifyVolume', volume)
            volumes.append(record)
        if not volumes:
            raise RuntimeError('no native filesystems observed')
        return {'diskBytes': size, 'diskSHA256': digest.hexdigest(), 'partitionMap': disk['Content'],
                'partitions': partitions, 'volumes': sorted(volumes, key=lambda v: v['VolumeName']), 'markers': observed_markers}
    finally:
        command('hdiutil', 'detach', device)
        if sha256(image) != before:
            raise RuntimeError('native examination modified image')


def create(case_id, work, command):
    image = work / (case_id + '.dmg')
    layout = 'SPUD' if case_id == 'hfsx-apm-raw' else 'NONE' if case_id == 'hfsplus-bare' else 'GPTSPUD'
    filesystem = 'Case-sensitive HFS+' if case_id == 'hfsx-apm-raw' else 'HFS+' if case_id == 'hfsplus-bare' else 'APFS'
    command('hdiutil', 'create', '-size', '1100m' if filesystem == 'APFS' else '32m', '-layout', layout,
            '-fs', filesystem, '-volname', case_id, '-type', 'UDIF',
            *(['-fsargs', '-E -S ' + PASSWORD] if filesystem == 'APFS' else []), image)
    device, entries = attach(image, command, readonly=False)
    try:
        if case_id == 'hfsx-apm-raw':
            command('diskutil', 'partitionDisk', device, '2', 'APM', 'HFSX', case_id, '24m', 'Free Space', 'unused', '0')
        volumes = [e['dev-entry'] for e in entries if e.get('volume-kind')]
        if len(volumes) != 1:
            raise RuntimeError('expected one new filesystem')
        volume = volumes[0]
        initial = info(volume, command)
        if initial.get('Locked'):
            command('diskutil', 'apfs', 'unlockVolume', volume, '-stdinpassphrase', '-nomount', fixture_input=(PASSWORD + '\n').encode())
        command('diskutil', 'mount', '-mountOptions', 'owners,noatime', volume)
        mount = Path(info(volume, command)['MountPoint'])
        create_files(mount / 'Fixture', command)
        os.link(mount / 'Fixture/example.txt', mount / 'Fixture/alias')
        if filesystem == 'APFS':
            container = info(volume, command)['APFSContainerReference']
            command('diskutil', 'apfs', 'addVolume', container, 'APFSX', 'RepackData')
            listing = plistlib.loads(command('diskutil', 'apfs', 'list', '-plist', container))['Containers'][0]
            other = next(v['DeviceIdentifier'] for v in listing['Volumes'] if v['Name'] == 'RepackData')
            second = info(other, command)
            create_files(Path(second['MountPoint']) / 'Fixture', command)
    finally:
        # New APFS children can remain busy after automatic volume publication.
        # Release every mount on this disposable image before detaching its disk.
        try:
            command('diskutil', 'unmountDisk', 'force', device)
        finally:
            command('hdiutil', 'detach', device)
    markers = []
    if case_id == 'hfsx-apm-raw':
        # Native SPUD creation produces flat disk bytes. Seed only an APM entry
        # explicitly marked Apple_Free, outside the filesystem and partition map.
        with image.open('r+b') as source:
            source.seek(512); entry = source.read(512)
            count = struct.unpack_from('>I', entry, 4)[0]
            free = []
            for index in range(1, count+1):
                source.seek(index*512); entry = source.read(512)
                if entry[48:80].rstrip(b'\0') == b'Apple_Free':
                    start, length = struct.unpack_from('>II', entry, 8)
                    if length > 8:
                        free.append((start+1)*512)
            if not free:
                raise RuntimeError('native APM has no free-sector control region')
            data = (b'Allocated outside every filesystem: preserve these forensic bytes.\n' * 8)[:512].ljust(512, b'!')
            source.seek(free[0]); source.write(data)
            markers = [{'offset': free[0], 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}]
        return image, markers
    final = work / (case_id + '-encoded.dmg')
    command('hdiutil', 'convert', image, '-format', 'UDRO' if filesystem == 'APFS' else 'UDBZ', '-o', final)
    return final, markers


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-major', required=True, type=int, choices=[15, 26, 27])
    parser.add_argument('--references', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    producer = version(args.expected_major)
    output = args.output.absolute()
    if output.exists():
        parser.error('refusing to replace an existing corpus')
    output.parent.mkdir(parents=True, exist_ok=True)
    command = Commands(output.with_suffix('.diagnostics.json'))
    with tempfile.TemporaryDirectory(prefix='apfs-repack-capture-', dir=output.parent) as temporary:
        work = Path(temporary); corpus = work / 'corpus'; corpus.mkdir()
        cases = []
        parents = []
        for case_id in sorted(PROFILES):
            case_work = work / case_id; case_work.mkdir()
            if case_id in ('hfsplus-gpt', 'apfs-snapshots'):
                family, name = ('image-building', 'hfsplus') if case_id == 'hfsplus-gpt' else ('snapshots', 'apfs')
                reference = args.references / family / f'macos-{args.expected_major}'
                manifest = json.loads((reference / 'manifest.json').read_text())
                if manifest['producer']['version'].split('.')[0] != str(args.expected_major):
                    raise RuntimeError('wrong reference producer')
                case = next(c for c in manifest['cases'] if c['id'].endswith('/' + name))
                image = reference / case['image']
                if sha256(image) != case['sha256']:
                    raise RuntimeError('source reference hash mismatch')
                parent = corpus / (case_id + '-parent.json')
                shutil.copyfile(reference / 'manifest.json', parent)
                parents.append({'source': parent.name, 'sha256': sha256(parent)})
                markers = []
            else:
                image, markers = create(case_id, case_work, command)
            raw = case_id in ('hfsx-apm-raw', 'hfsplus-gpt')
            destination = corpus / (case_id + ('.raw.gz' if raw else '.dmg'))
            observation = observe(image, case_work, command, markers, destination if case_id == 'hfsplus-gpt' else None)
            if case_id == 'hfsplus-gpt':
                hfs_input = image
            elif raw:
                with image.open('rb') as source, destination.open('wb') as target, gzip.GzipFile(fileobj=target, mode='wb', mtime=0) as zipped:
                    shutil.copyfileobj(source, zipped)
                if image.stat().st_size != observation['diskBytes'] or sha256(image) != observation['diskSHA256']:
                    raise RuntimeError('raw storage differs from native disk')
            else:
                command('hdiutil', 'verify', image)
                shutil.copyfile(image, destination)
            observed = corpus / (case_id + '.json')
            observed.write_text(json.dumps(observation, indent=2) + '\n')
            cases.append({'id': 'image-repacking/' + case_id, 'image': destination.name,
                          'sha256': sha256(destination), 'observation': observed.name, 'observationSHA256': sha256(observed)})
        rejections = []
        signed = corpus / 'signed-container.dmg'
        shutil.copyfile(hfs_input, signed)
        command('codesign', '--force', '--sign', '-', '--timestamp=none', signed)
        command('codesign', '--verify', '--strict', signed)
        encrypted = corpus / 'encrypted-container.dmg'
        command('hdiutil', 'convert', hfs_input, '-format', 'UDZO', '-encryption', 'AES-128',
                '-stdinpass', '-o', encrypted, fixture_input=(PASSWORD + '\0').encode())
        command('hdiutil', 'verify', '-stdinpass', encrypted, fixture_input=(PASSWORD + '\0').encode())
        for image in (signed, encrypted):
            rejections.append({'id': image.stem, 'image': image.name, 'sha256': sha256(image)})
        sources = []
        for name in ('image_repacking.py', 'capture.py', 'snapshot_reading.py'):
            path = corpus / name
            shutil.copyfile(Path(__file__).with_name(name), path)
            sources.append({'source': name, 'sha256': sha256(path)})
        producer.update(source='image_repacking.py', sourceSHA256=sha256(corpus / 'image_repacking.py'), sources=sources + parents)
        (corpus / 'manifest.json').write_text(json.dumps({'schema': 1, 'scenario': 'image-repacking', 'producer': producer, 'cases': cases, 'rejections': rejections}, indent=2) + '\n')
        corpus.rename(output)
    print('Completed native disk-preservation references:', output)


if __name__ == '__main__':
    main()
