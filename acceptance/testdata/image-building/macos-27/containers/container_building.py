"""Native multi-volume construction references within the image-building family.

Two cases isolate shared allocation/case policy and System/Data identity. All
source images, file observations and group inventories come from Apple tools.
"""
import argparse
import errno
import json
import os
from pathlib import Path
import platform
import plistlib
import shutil
import subprocess
import tempfile

from capture import observe_files, native_xattrs, sha256
from image_building import create_signed_app, observe
import file_compression as compression
from verify_preservation import require

MIB = 1 << 20
PROFILES = (
    ('shared', 1536*MIB, [
        {'name': 'Reserved', 'reserve': 1504*MIB},
        {'name': 'Limited', 'sensitive': True, 'quota': 8*MIB},
        {'name': 'Empty', 'empty': True}]),
    ('group', 1024*MIB, [
        {'name': 'Data', 'role': 'D'},
        {'name': 'System', 'role': 'S', 'groupWith': 'Data'}]))
SOURCES = ('container_building.py', 'capture.py', 'image_building.py',
           'file_compression.py', 'preservation.py', 'metadata_edits.py', 'content_replacement.py')


def attached(image, command, readonly=False, shadow=None):
    data = plistlib.loads(command('hdiutil', 'attach', '-nomount', '-plist',
                                 *(['-readonly'] if readonly else []),
                                 *(['-shadow', shadow] if shadow else []), image))
    entries = [e for e in data['system-entities'] if 'dev-entry' in e]
    # The first device is used only for cleanup. Physical-store identity is
    # established independently from APFS and checked against this attachment.
    cleanup = entries[0]['dev-entry']
    try:
        volumes = [e['dev-entry'] for e in entries if e.get('volume-kind') == 'apfs']
        if not volumes:
            raise RuntimeError('attachment has no APFS volumes')
        info = plistlib.loads(command('diskutil', 'info', '-plist', volumes[0]))
        stores = info['APFSPhysicalStores']
        if len(stores) != 1:
            raise RuntimeError('one APFS physical store required')
        physical = '/dev/' + stores[0]['APFSPhysicalStore']
        if physical not in [e['dev-entry'] for e in entries]:
            raise RuntimeError('APFS store is outside the attached image')
        container = info['APFSContainerReference']
        inventory = plistlib.loads(command('diskutil', 'apfs', 'list', '-plist', container))['Containers']
        if len(inventory) != 1:
            raise RuntimeError('one APFS container required')
        return cleanup, physical, inventory[0]
    except BaseException:
        command('hdiutil', 'detach', cleanup)
        raise


def mount(volume, directory, command, readonly=False):
    directory.mkdir()
    command('diskutil', 'mount', *(['readOnly'] if readonly else []),
            '-mountOptions', 'owners,noatime' if readonly else 'noowners,noatime',
            '-mountPoint', directory, volume['DeviceIdentifier'])


def create_tree(root, spec, command):
    root.mkdir()
    if spec.get('empty'):
        return
    (root / 'same.txt').write_text(spec['name'] + '\n')
    os.link(root / 'same.txt', root / 'alias')
    os.symlink('same.txt', root / 'link')
    (root / 'Name').write_bytes(b'upper')
    if spec.get('sensitive'):
        (root / 'name').write_bytes(b'lower')
    compression.xattr(root / 'same.txt', 'org.go-apfs.volume', spec['name'].encode())
    compression.xattr(root / 'same.txt', compression.RESOURCE, b'independent resource fork')
    data = compression.plain(500)
    compression.install(root / 'compressed', 3, data, payload=compression.encode(3, data))
    create_signed_app(root, command)


def check_filesystem(physical, command):
    command('/System/Library/Filesystems/apfs.fs/Contents/Resources/fsck_apfs', '-n',
            physical.replace('/dev/disk', '/dev/rdisk'))


def native_allocation(image, case_id, command):
    """Exercise independent volume writes and space policy on a disposable shadow.

    The reserved volume protects all but 32 MiB of the shared container, so the
    pressure controls stay small. Exact allocation cutoffs depend on filesystem
    history; compare enforcement and successful reuse, not physical block counts.
    """
    before = sha256(image)
    result = {}
    payload = bytes(range(256)) * 2048
    with tempfile.TemporaryDirectory(prefix='apfs-container-allocation-') as temporary:
        work = Path(temporary)
        shadow = work / 'writes.shadow'
        device, _, inventory = attached(image, command, shadow=shadow)
        roots = {}
        def fill(path, maximum):
            written = 0
            try:
                with path.open('wb', buffering=0) as stream:
                    while written < maximum:
                        written += stream.write(payload)
                        os.fsync(stream.fileno())
            except OSError as error:
                require(error.errno in (errno.EDQUOT, errno.ENOSPC), 'expected quota or space exhaustion')
                require(written > 0, 'space available before enforcement')
                return {'errno': error.errno, 'writtenBytes': written}
            raise RuntimeError(f'space limit not enforced within {maximum} bytes')
        try:
            for volume in inventory['Volumes']:
                directory = work / volume['Name']
                mount(volume, directory, command)
                roots[volume['Name']] = directory / 'native-allocation'
                roots[volume['Name']].mkdir()
            if case_id == 'shared':
                result['quota'] = fill(roots['Limited'] / 'pressure', 16*MIB)
                result['reserve'] = fill(roots['Empty'] / 'pressure', 64*MIB)
                # The protected volume must still consume its reservation while
                # an unconstrained neighbour can no longer allocate data.
                with (roots['Reserved'] / 'reserved').open('wb') as stream:
                    for _ in range(32):
                        stream.write(payload)
                    stream.flush(); os.fsync(stream.fileno())
                for name in ('Limited', 'Empty'):
                    (roots[name] / 'pressure').unlink()
                (roots['Reserved'] / 'reserved').unlink()
            for name, root in roots.items():
                data = name.encode() + payload
                original = root / 'grow'
                original.write_bytes(data)
                os.link(original, root / 'alias')
                with original.open('ab') as stream:
                    stream.write(data)
                    stream.flush(); os.fsync(stream.fileno())
                original.rename(root / 'renamed')
                require((root / 'alias').read_bytes() == data*2, 'native link growth')
                (root / 'alias').unlink()
                (root / 'reused').write_bytes(data)
        finally:
            command('hdiutil', 'detach', device)
        device, physical, inventory = attached(image, command, readonly=True, shadow=shadow)
        try:
            check_filesystem(physical, command)
            for volume in inventory['Volumes']:
                directory = work / (volume['Name'] + '-read')
                mount(volume, directory, command, readonly=True)
                root = directory / 'native-allocation'
                data = volume['Name'].encode() + payload
                require((root / 'renamed').read_bytes() == data*2, 'independent volume growth survives remount')
                require((root / 'reused').read_bytes() == data, 'space reuse survives remount')
                require(not (root / 'alias').exists(), 'unlink survives remount')
                require(not (root / 'pressure').exists() and not (root / 'reserved').exists(), 'pressure files removed')
        finally:
            command('hdiutil', 'detach', device)
    require(sha256(image) == before, 'native writes changed the original image')
    result['independentWritesAndReuse'] = True
    return result


def capture(work, corpus, command, producer):
    corpus.mkdir()
    cases = []
    for case_id, size, specs in PROFILES:
        scratch = work / (case_id + '-container.dmg')
        command('hdiutil', 'create', '-size', str(size), '-fs', 'APFS', '-volname', specs[0]['name'], scratch)
        device, _, inventory = attached(scratch, command)
        try:
            container = inventory['ContainerReference']
            # Recreate the first volume so its reserve is supplied at creation.
            command('diskutil', 'apfs', 'deleteVolume', inventory['Volumes'][0]['DeviceIdentifier'])
            devices = {}
            for spec in specs:
                args = []
                for key in ('reserve', 'quota', 'role'):
                    if key in spec:
                        args += ['-' + key, str(spec[key])]
                if 'groupWith' in spec:
                    args += ['-groupWith', devices[spec['groupWith']]]
                command('diskutil', 'apfs', 'addVolume', container, 'APFSX' if spec.get('sensitive') else 'APFS',
                        spec['name'], *args, '-nomount')
                current = plistlib.loads(command('diskutil', 'apfs', 'list', '-plist', container))['Containers'][0]
                volume = next(v for v in current['Volumes'] if v['Name'] == spec['name'])
                devices[spec['name']] = volume['DeviceIdentifier']
                directory = work / (case_id + '-' + spec['name'])
                mount(volume, directory, command)
                create_tree(directory / 'Fixture', spec, command)
                command('diskutil', 'unmount', volume['DeviceIdentifier'])
                command('diskutil', 'mount', '-mountOptions', 'owners,noatime',
                        '-mountPoint', directory, volume['DeviceIdentifier'])
                # noowners permits portable fixture creation on root-owned new
                # volumes, but its stored UID/GID 99 is a process-dependent
                # sentinel. Re-enable ownership before assigning it: chown while
                # noowners is active is intentionally ineffective on APFS.
                for parent, dirs, files in os.walk(directory / 'Fixture', followlinks=False):
                    for path in [Path(parent), *[Path(parent) / name for name in dirs + files]]:
                        os.chown(path, os.getuid(), os.getgid(), follow_symlinks=False)
        finally:
            command('hdiutil', 'detach', device)
        image = corpus / (case_id + '.dmg')
        command('hdiutil', 'convert', scratch, '-format', 'UDZO', '-o', image)
        before = sha256(image)
        device, physical, inventory = attached(image, command, readonly=True)
        try:
            check_filesystem(physical, command)
            raw = command('diskutil', 'apfs', 'listVolumeGroups', '-plist', inventory['ContainerReference'])
            groups = plistlib.loads(raw)['Containers'][0].get('VolumeGroups', [])
            (corpus / (case_id + '-groups.plist')).write_bytes(raw)
            (corpus / (case_id + '-volumes.plist')).write_bytes(plistlib.dumps(inventory))
            volumes = []
            for spec in specs:
                volume = next(v for v in inventory['Volumes'] if v['Name'] == spec['name'])
                directory = work / (case_id + '-' + spec['name'] + '-read')
                mount(volume, directory, command, readonly=True)
                details = plistlib.loads(command('diskutil', 'info', '-plist', volume['DeviceIdentifier']))
                files = observe(directory / 'Fixture', observe_files, native_xattrs)
                files['lookups'] = []
                for name in ('Name', 'name', 'NAME'):
                    path = directory / 'Fixture' / name
                    try:
                        object_id = path.lstat().st_ino
                    except FileNotFoundError:
                        object_id = 0
                    files['lookups'].append({'path': 'Fixture/' + name, 'object': object_id})
                if not spec.get('empty'):
                    command('codesign', '--verify', '--deep', '--strict', directory / 'Fixture/Example.app')
                group = next((g['APFSVolumeGroupUUID'] for g in groups
                              if any(v['DeviceIdentifier'] == volume['DeviceIdentifier'] for v in g['Volumes'])), '')
                volumes.append({'name': volume['Name'], 'uuid': volume['APFSVolumeUUID'],
                                'sensitive': 'case-sensitive' in details['FilesystemName'].lower(),
                                'roles': volume['Roles'], 'group': group,
                                'reserve': volume['CapacityReserve'], 'quota': volume['CapacityQuota'],
                                'empty': spec.get('empty', False), 'files': files})
        finally:
            command('hdiutil', 'detach', device)
        if sha256(image) != before:
            raise RuntimeError('native observations changed their source image')
        observation = corpus / (case_id + '.json')
        allocation = native_allocation(image, case_id, command)
        observation.write_text(json.dumps({'size': size, 'containerUUID': inventory['APFSContainerUUID'],
                                           'volumes': volumes, 'allocation': allocation}, indent=2) + '\n')
        cases.append({'id': case_id, 'image': image.name, 'sha256': before,
                      'observation': observation.name, 'observationSHA256': sha256(observation),
                      'groups': case_id + '-groups.plist', 'groupsSHA256': sha256(corpus / (case_id + '-groups.plist')),
                      'inventory': case_id + '-volumes.plist', 'inventorySHA256': sha256(corpus / (case_id + '-volumes.plist'))})
    sources = []
    for name in SOURCES:
        shutil.copyfile(Path(__file__).with_name(name), corpus / name)
        sources.append({'source': name, 'sha256': sha256(corpus / name)})
    (corpus / 'manifest.json').write_text(json.dumps({'schema': 1, 'scenario': 'image-building/containers',
                                                   'producer': producer, 'sources': sources, 'cases': cases}, indent=2) + '\n')


def main():
    # Focused local capture uses the same helper as the complete family in CI.
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--expected-major', type=int, required=True)
    args = parser.parse_args()
    version = subprocess.check_output(['sw_vers', '-productVersion'], text=True).strip()
    if platform.system() != 'Darwin' or int(version.split('.')[0]) != args.expected_major or args.output.exists():
        parser.error('requires matching macOS and a new output directory')
    producer = {'system': 'macOS', 'version': version, 'architecture': platform.machine(),
                'build': subprocess.check_output(['sw_vers', '-buildVersion'], text=True).strip()}
    records = []
    args.output.parent.mkdir(parents=True, exist_ok=True)
    def command(*argv):
        print('native:', *map(str, argv), flush=True)
        record = {'argv': list(map(str, argv)), 'status': 'started'}; records.append(record)
        def save():
            args.output.with_suffix('.diagnostics.json').write_text(json.dumps(records, indent=2) + '\n')
        save()
        try:
            r = subprocess.run(list(map(str, argv)), capture_output=True, timeout=120)
        except BaseException as error:
            record.update(status='failed', error=str(error)); save(); raise
        record.update(status=r.returncode, stdout=r.stdout.decode(errors='replace'), stderr=r.stderr.decode(errors='replace')); save()
        if r.returncode:
            raise RuntimeError(record)
        return r.stdout
    with tempfile.TemporaryDirectory(prefix='apfs-containers-', dir=args.output.parent) as temporary:
        work = Path(temporary)
        capture(work, work / 'corpus', command, producer)
        (work / 'corpus').rename(args.output)


if __name__ == '__main__':
    main()
