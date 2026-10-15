#!/usr/bin/env python3
"""Apple clone storage, snapshot revert and software-encryption controls.

Apple tools create every state; native mounts/checkers supply observations.
Go is never invoked. Existing snapshot capture is reused with original provenance.
All native operations are restricted to disposable GitHub-hosted macOS VMs.
"""
import argparse
from contextlib import contextmanager
import errno
import json
import os
from pathlib import Path
import plistlib
import shutil
import signal
import tempfile
import time
import zipfile

from capture import sha256
from container_building import attached, check_filesystem
from image_repacking import Commands, files, version
from snapshot_reading import MOUNT_APFS, snapshot_attributes
from verify_preservation import require

APFS_UTIL = '/System/Library/Filesystems/apfs.fs/Contents/Resources/apfs.util'
PASSWORD = 'public-lifecycle-initial'
REPLACEMENT = 'public-lifecycle-replacement-\u03bb'
PEER_PASSWORD = 'public-lifecycle-peer'
SOURCES = ('apfs_lifecycle.py', 'apfs_storage.c', 'apfs_snapshot.c', 'apfs_snapshot.entitlements', 'capture.py', 'container_building.py',
           'image_repacking.py', 'snapshot_reading.py', 'verify_preservation.py',
           'file_compression.py', 'image_building.py', 'metadata_edits.py',
           'content_replacement.py', 'preservation.py')
STATES = ('clone-shared', 'clone-diverged', 'clone-truncated', 'clone-final-owner',
          'encrypted', 'password-changed', 'encrypted-edited', 'decrypted')


def require_runner():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted':
        raise RuntimeError('APFS lifecycle controls require a disposable GitHub-hosted VM')


def native_info(volume, command):
    require_runner()
    return plistlib.loads(command('diskutil', 'info', '-plist', volume))


def mount(volume, directory, command, readonly=False):
    require_runner()
    directory.mkdir()
    command('diskutil', 'mount', *(['readOnly'] if readonly else []),
            '-mountOptions', 'owners,noatime', '-mountPoint', directory, volume)
    detail = native_info(volume, command)
    require(detail.get('GlobalPermissionsEnabled'), 'native mount must expose stored ownership')
    require(bool(detail['WritableVolume']) != readonly, 'native mount write policy differs')


def unlock(volume, password, command):
    require_runner()
    command('diskutil', 'apfs', 'unlockVolume', volume, '-user', 'disk', '-stdinpassphrase', '-nomount',
            fixture_input=(password + '\n').encode())


def settled(volume, encrypted, command, deadline_seconds=90):
    """Capture every probe; require explicit non-migrating native state."""
    require_runner()
    deadline = time.monotonic() + deadline_seconds
    while True:
        detail = native_info(volume, command)
        inventory = plistlib.loads(command('diskutil', 'apfs', 'list', '-plist',
                                          detail['APFSContainerReference']))
        records = [v for c in inventory['Containers'] for v in c['Volumes']
                   if v['DeviceIdentifier'] == detail['DeviceIdentifier']]
        require(len(records) == 1, 'conversion volume must remain in its container')
        record = records[0]
        require(isinstance(record.get('CryptoMigrationOn'), bool), 'native conversion state is absent')
        if not record['CryptoMigrationOn'] and bool(detail.get('FileVault')) == encrypted:
            return {'info': detail, 'volume': record}
        if time.monotonic() >= deadline:
            raise RuntimeError('native APFS conversion did not settle before deadline')
        time.sleep(1)


def storage(root, helper, command):
    require_runner()
    result = {}
    for name in ('data', 'clone', 'alias', 'ordinary-copy', 'replacement', 'replacement-alias'):
        path = root / name
        if not path.exists() or not path.stat().st_size:
            continue
        result[name] = json.loads(command(helper, path))
        fork = Path(str(path) + '/..namedfork/rsrc')
        try:
            present = fork.stat().st_size
        except FileNotFoundError:
            present = 0
        if present:
            result[name + '/..namedfork/rsrc'] = json.loads(command(helper, fork))
    return result


def overlap(left, right):
    return any(max(a['physical'], b['physical']) < min(a['physical'] + a['length'], b['physical'] + b['length'])
               for a in left['ranges'] for b in right['ranges'])


def validate_shared(mapped):
    require(mapped['data']['object'] != mapped['clone']['object'], 'clone needs an independent inode')
    require(mapped['data']['object'] == mapped['alias']['object'], 'alias must remain a hard link')
    for suffix in ('', '/..namedfork/rsrc'):
        require(overlap(mapped['data' + suffix], mapped['clone' + suffix]), 'native clone did not share physical storage')
        require(not overlap(mapped['data' + suffix], mapped['ordinary-copy' + suffix]), 'ordinary copy unexpectedly shares storage')


def capture_state(scratch, case_id, label, passwords, work, output, command, helper):
    require_runner()
    image = output / (case_id + '-' + label + '.dmg')
    command('hdiutil', 'convert', scratch, '-format', 'UDZO', '-o', image)
    original = sha256(image)
    cleanup, physical, inventory = attached(image, command, readonly=True)
    try:
        # fsck can read plaintext volumes independently. For encrypted volumes
        # diskutil verifyVolume is invoked after authenticated native unlock.
        if not passwords:
            check_filesystem(physical, command)
        observations = []
        for volume in inventory['Volumes']:
            device = volume['DeviceIdentifier']
            initial = native_info(device, command)
            name = initial['VolumeName']
            password = passwords.get(name)
            require(bool(initial.get('FileVault')) == (password is not None), 'unexpected volume encryption policy')
            if password is not None:
                require(initial.get('Locked'), 'encrypted reference must start locked')
                rejected = [PASSWORD] if name == 'Primary' and password == REPLACEMENT else []
                rejected.append('public-incorrect-lifecycle-password')
                for candidate in rejected:
                    command('diskutil', 'apfs', 'unlockVolume', device, '-user', 'disk', '-stdinpassphrase',
                            '-nomount', fixture_input=(candidate + '\n').encode(), expected_success=False)
                    require(native_info(device, command).get('Locked'), 'rejected password unlocked volume')
                unlock(device, password, command)
            else:
                rejected = []
            directory = work / (case_id + '-read-' + label + '-' + name)
            mount(device, directory, command, readonly=True)
            command('diskutil', 'verifyVolume', device)
            detail = native_info(device, command)
            snapshots = plistlib.loads(command('diskutil', 'apfs', 'listSnapshots', '-plist', device))['Snapshots']
            attrs = {s['name']: s for s in snapshot_attributes(directory)}
            require(set(attrs) == {s['SnapshotName'] for s in snapshots}, 'native snapshot inventories disagree')
            history = []
            for snapshot in snapshots:
                pin = work / (case_id + '-' + label + '-history-' + str(snapshot['SnapshotXID']))
                pin.mkdir()
                command(MOUNT_APFS, '-o', 'rdonly,owners,nobrowse', '-s', snapshot['SnapshotName'], directory, pin)
                try:
                    history.append({'name': snapshot['SnapshotName'], 'xid': snapshot['SnapshotXID'],
                                    'uuid': snapshot['SnapshotUUID'], 'attributes': attrs[snapshot['SnapshotName']],
                                    'files': files(pin / 'Fixture')})
                finally:
                    command('/sbin/umount', pin)
            observed = {'name': name, 'uuid': detail['VolumeUUID'].upper(),
                        'caseSensitive': 'case-sensitive' in detail['FilesystemName'].lower(),
                        'encrypted': password is not None, 'publicFixturePassword': password,
                        'rejectedPublicFixturePasswords': rejected, 'nativeInfo': detail,
                        'cryptoUsers': plistlib.loads(command('diskutil', 'apfs', 'listCryptoUsers', '-plist', device)),
                        'files': files(directory / 'Fixture'), 'snapshots': history,
                        'storage': storage(directory / 'Fixture', helper, command), 'checkerStatus': 0}
            if (directory / 'Fixture/Example.app').exists():
                command('codesign', '--verify', '--deep', '--strict', directory / 'Fixture/Example.app')
                observed['signatureStatus'] = 0
            observations.append(observed)
        return {'label': label, 'image': image.name, 'sha256': original, 'volumes': observations}
    finally:
        command('hdiutil', 'detach', cleanup)
        require(sha256(image) == original, 'read-only native observation changed image')


def fixture(root, command):
    require_runner()
    from file_compression import RESOURCE, xattr
    from image_building import create_signed_app
    command('sudo', 'mkdir', root)
    command('sudo', 'chown', f'{os.getuid()}:{os.getgid()}', root)
    with (root / 'data').open('wb') as stream:
        stream.write(bytes(range(256)) * 1024 + b'end')
        stream.flush()
        os.fsync(stream.fileno())
    xattr(root / 'data', RESOURCE, bytes(range(256)) * 128 + b'fork')
    xattr(root / 'data', 'org.go-apfs.clone', b'independent metadata')
    os.chmod(root / 'data', 0o6755)
    os.link(root / 'data', root / 'alias')
    (root / 'replacement').write_bytes(b'Existing destination with hard-link alias\n')
    os.link(root / 'replacement', root / 'replacement-alias')
    command('/bin/cp', '-c', root / 'data', root / 'clone')
    command('/bin/cp', '-p', root / 'data', root / 'ordinary-copy')
    command('/bin/cp', '-c', root / 'data', root / 'replacement')
    create_signed_app(root, command, source_directory=root.parent.parent)


def mutate(scratch, label, case_id, fs, work, command, password=None, major=27):
    require_runner()
    from file_compression import RESOURCE, xattr
    cleanup, _, inventory = attached(scratch, command)
    cross_volume = None
    try:
        primary = next(v for v in inventory['Volumes'] if v['Name'] == 'Primary')
        device = primary['DeviceIdentifier']
        if password is not None:
            unlock(device, password, command)
        directory = work / (case_id + '-write-' + label)
        mount(device, directory, command)
        root = directory / 'Fixture'
        if label == 'clone-shared':
            fixture(root, command)
            command('diskutil', 'apfs', 'addVolume', inventory['ContainerReference'], fs, 'Peer', '-nomount')
            peer_inventory = plistlib.loads(command('diskutil', 'apfs', 'list', '-plist', inventory['ContainerReference']))['Containers'][0]
            peer = next(v for v in peer_inventory['Volumes'] if v['Name'] == 'Peer')
            peer_dir = work / (case_id + '-write-peer-plain')
            mount(peer['DeviceIdentifier'], peer_dir, command)
            command('sudo', 'mkdir', peer_dir / 'Fixture')
            command('sudo', 'chown', f'{os.getuid()}:{os.getgid()}', peer_dir / 'Fixture')
            (peer_dir / 'Fixture/preserved-peer').write_bytes(b'Independent plaintext peer contents.\n')
            # The installed macOS 15 cp rejects EXDEV; the captured macOS 26/27
            # tools fall back. Preserve that difference and the absent legacy
            # destination instead of preparing a successful copy over the error.
            command('/bin/cp', '-c', root / 'data', peer_dir / 'Fixture/data',
                    expected_success=major != 15)
            record = command.records[-1]
            cross_volume = {'status': record['status'], 'stderr': record['stderr'],
                            'destinationExists': (peer_dir / 'Fixture/data').exists()}
            require(cross_volume['destinationExists'] == (major != 15), 'native cross-volume cp destination differs')
            if major == 15:
                require(record['status'] == 1 and 'Cross-device link' in record['stderr'], 'unexpected legacy clone refusal')
        elif label == 'clone-diverged':
            with (root / 'clone').open('r+b') as stream:
                stream.seek(8193)
                stream.write(b'Independent native clone data\n')
                stream.flush()
                os.fsync(stream.fileno())
            xattr(root / 'clone', RESOURCE, b'Independent native clone fork\n' * 1024)
            xattr(root / 'clone', 'org.go-apfs.clone', b'changed clone metadata')
            os.chmod(root / 'clone', 0o640)
        elif label == 'clone-truncated':
            with (root / 'clone').open('r+b') as stream:
                stream.truncate(4097)
                stream.flush()
                os.fsync(stream.fileno())
        elif label == 'clone-final-owner':
            (root / 'data').unlink()
            (root / 'alias').unlink()
            (root / 'replacement').unlink()
            # Reuse after shared references are removed, without disturbing survivors.
            (root / 'native-allocation').write_bytes(b'Native allocation after unlink\n' * 2048)
        elif label == 'encrypted':
            command('diskutil', 'apfs', 'encryptVolume', device, '-user', 'disk', '-stdinpassphrase',
                    fixture_input=(PASSWORD + '\n').encode())
            settled(device, True, command)
            command('diskutil', 'apfs', 'addVolume', inventory['ContainerReference'], fs, 'EncryptedPeer',
                    '-stdinpassphrase', '-nomount', fixture_input=(PEER_PASSWORD + '\n').encode())
            peer_inventory = plistlib.loads(command('diskutil', 'apfs', 'list', '-plist', inventory['ContainerReference']))['Containers'][0]
            peer = next(v for v in peer_inventory['Volumes'] if v['Name'] == 'EncryptedPeer')
            unlock(peer['DeviceIdentifier'], PEER_PASSWORD, command)
            peer_dir = work / (case_id + '-write-peer-encrypted')
            mount(peer['DeviceIdentifier'], peer_dir, command)
            fixture(peer_dir / 'Fixture', command)
        elif label == 'password-changed':
            command('diskutil', 'apfs', 'changePassphrase', device, '-user', 'disk',
                    '-oldStdinpassphrase', '-newStdinpassphrase',
                    fixture_input=(PASSWORD + '\n' + REPLACEMENT + '\n').encode())
        elif label == 'encrypted-edited':
            command('/bin/cp', '-c', root / 'ordinary-copy', root / 'data')
            os.link(root / 'data', root / 'alias')
            with (root / 'data').open('r+b') as stream:
                stream.seek(512)
                stream.write(b'Native encrypted write with shared crypto IDs\n')
                stream.flush()
                os.fsync(stream.fileno())
            xattr(root / 'clone', RESOURCE, b'Changed encrypted resource fork\n' * 1024)
        elif label == 'decrypted':
            command('diskutil', 'apfs', 'decryptVolume', device, '-user', 'disk', '-stdinpassphrase',
                    fixture_input=(REPLACEMENT + '\n').encode())
            settled(device, False, command)
        else:
            raise ValueError('unknown lifecycle state')
    finally:
        command('hdiutil', 'detach', cleanup)
    return cross_volume


def capture_clones(case_id, sensitive, work, output, command, helper, major=27):
    require_runner()
    scratch = work / (case_id + '.dmg')
    fs = 'APFSX' if sensitive else 'APFS'
    # Native 128 MiB containers permit only one volume. Reuse the independently
    # qualified three-volume geometry from container_building.py rather than
    # inferring the private formatter's size-to-volume-limit algorithm.
    command('hdiutil', 'create', '-size', '1536m', '-layout', 'NONE', '-fs',
            'Case-sensitive APFS' if sensitive else 'APFS', '-volname', 'Primary', scratch)
    states, passwords, cross_volume = [], {}, None
    for label in STATES:
        result = mutate(scratch, label, case_id, fs, work, command, passwords.get('Primary'), major)
        if result is not None:
            cross_volume = result
        if label == 'encrypted':
            passwords = {'Primary': PASSWORD, 'EncryptedPeer': PEER_PASSWORD}
        elif label == 'password-changed':
            passwords['Primary'] = REPLACEMENT
        elif label == 'decrypted':
            del passwords['Primary']
        state = capture_state(scratch, case_id, label, passwords, work, output, command, helper)
        if label == 'clone-shared':
            primary = next(v for v in state['volumes'] if v['name'] == 'Primary')
            validate_shared(primary['storage'])
        states.append(state)
        # Unpublished progress preserves the actual completed observations if a
        # later native operation fails. The complete manifest owns these values
        # on success; do not retain a second copy in the finished corpus.
        (output / (case_id + '-progress.json')).write_text(json.dumps(states, indent=2) + '\n')
    return {'id': case_id, 'kind': 'clone-encryption', 'crossVolumeCopy': cross_volume, 'states': states}


def snapshot_operation(helper, directory, operation, names, command):
    """Observe the API result; only Apple's explicit EPERM is an unavailable control."""
    require_runner()
    result = json.loads(command('sudo', '--preserve-env=GITHUB_ACTIONS,RUNNER_ENVIRONMENT',
                                helper, operation, directory, *names))
    require(result.get('api') == 'fs_snapshot_' + operation, 'snapshot API observation differs')
    require((result.get('status'), result.get('errno')) in ((0, 0), (-1, errno.EPERM)),
            'unexpected native snapshot API failure: ' + str(result))
    return result | {'names': list(names)}


def snapshot_observer(baseline, entitled, command):
    """Probe launch policy before native I/O; preserve a killed entitled binary."""
    require_runner()
    probe = ('sudo', '--preserve-env=GITHUB_ACTIONS,RUNNER_ENVIRONMENT')
    response = command(*probe, entitled, '--probe', expected_success=None)
    status = command.records[-1]['status']
    require(status in (0, -signal.SIGKILL), 'unexpected snapshot observer launch failure')
    active = entitled if status == 0 else baseline
    if status != 0:
        response = command(*probe, baseline, '--probe')
    require(json.loads(response) == {'schema': 1, 'probe': 'snapshot-api-observer'}, 'snapshot observer probe differs')
    return active, {'signedLaunchStatus': status, 'activeTool': str(active),
                    'developerEntitlement': status == 0,
                    'blocker': 'https://github.com/deploymenttheory/go-apfs-v3/issues/74' if status != 0 else None}


def capture_snapshot_history(case_id, reference, work, output, command, helper, snapshot_helper):
    require_runner()
    manifest_path = reference / 'manifest.json'
    original_manifest = json.loads(manifest_path.read_text())
    source = next(c for c in original_manifest['cases'] if c['id'] == 'snapshot-reading/' + case_id)
    original = reference / source['image']
    require(sha256(original) == source['sha256'], 'parent snapshot image digest differs')
    scratch = work / ('snapshot-' + case_id + '.dmg')
    command('hdiutil', 'convert', original, '-format', 'UDRW', '-o', scratch)
    prefix = 'snapshot-' + case_id
    before = capture_state(scratch, prefix, 'retained', {}, work, output, command, helper)
    @contextmanager
    def writable(label):
        cleanup, _, inventory = attached(scratch, command)
        try:
            require(len(inventory['Volumes']) == 1, 'one snapshot control volume required')
            volume = inventory['Volumes'][0]['DeviceIdentifier']
            directory = work / (prefix + '-write-' + label)
            mount(volume, directory, command)
            yield volume, directory
        finally:
            command('hdiutil', 'detach', cleanup)

    controls = []
    with writable('names') as (volume, directory):
        snapshots = plistlib.loads(command('diskutil', 'apfs', 'listSnapshots', '-plist', volume))['Snapshots']
        require(len(snapshots) == 2, 'snapshot control needs two independent retained snapshots')
        selected = min(snapshots, key=lambda s: s['SnapshotXID'])
        created_name, renamed_name = 'native-caf\u00e9', 'renamed-cafe\u0301'
        created = snapshot_operation(snapshot_helper, directory, 'create', (created_name,), command)
        controls.append(created)
        controls.append(snapshot_operation(snapshot_helper, directory, 'rename',
                         (created_name if created['status'] == 0 else selected['SnapshotName'], renamed_name), command))
        require(created['status'] == controls[-1]['status'], 'create/rename availability differs; a separate control is required')
    named = capture_state(scratch, prefix, 'named' if created['status'] == 0 else 'api-refused',
                          {}, work, output, command, helper)
    if created['status'] == 0:
        history = named['volumes'][0]['snapshots']
        require(len(history) == 3 and renamed_name in {s['name'] for s in history}, 'native snapshot rename not observed')
    else:
        require(named['volumes'][0]['files'] == before['volumes'][0]['files'] and
                named['volumes'][0]['snapshots'] == before['volumes'][0]['snapshots'],
                'refused snapshot APIs changed live files or retained history')
    with writable('revert') as (volume, directory):
        if created['status'] == 0:
            command('sudo', 'diskutil', 'apfs', 'deleteSnapshot', volume, '-name', renamed_name, '-wait')
        reverted = snapshot_operation(snapshot_helper, directory, 'revert', (selected['SnapshotName'],), command)
        controls.append(reverted)
        if reverted['status'] != 0:
            # This is a separate positive deletion control, never a revert.
            newer = max(snapshots, key=lambda s: s['SnapshotXID'])
            command('sudo', 'diskutil', 'apfs', 'deleteSnapshot', volume, '-xid', str(newer['SnapshotXID']), '-wait')
    after = capture_state(scratch, prefix, 'reverted' if reverted['status'] == 0 else 'deleted-newer',
                          {}, work, output, command, helper)
    prior = next(s for s in before['volumes'][0]['snapshots'] if s['xid'] == selected['SnapshotXID'])
    remaining = after['volumes'][0]['snapshots']
    require([s['xid'] for s in remaining] == [selected['SnapshotXID']], 'native history removal did not preserve the selected snapshot')
    expected = prior if reverted['status'] == 0 else before['volumes'][0]
    require(after['volumes'][0]['files'] == expected['files'], 'native snapshot operation changed unexpected live contents or metadata')
    with writable('continued') as (_, directory):
        marker = directory / 'Fixture/native-history-write'
        with marker.open('wb') as stream:
            stream.write(b'Continued native write with retained history\n')
            stream.flush()
            os.fsync(stream.fileno())
    continued = capture_state(scratch, prefix, 'continued', {}, work, output, command, helper)
    require(continued['volumes'][0]['snapshots'] == after['volumes'][0]['snapshots'],
            'continued native write changed retained historical observations')
    require(sha256(original) == source['sha256'], 'revert control changed original snapshot evidence')
    return {'id': prefix, 'kind': 'snapshot-history', 'selectedName': selected['SnapshotName'],
            'selectedXID': selected['SnapshotXID'], 'parentManifestSHA256': sha256(manifest_path),
            'parentImage': source['image'], 'parentImageSHA256': source['sha256'],
            'nativeAPIs': controls,
            'blocker': 'https://github.com/deploymenttheory/go-apfs-v3/issues/74' if any(c['status'] != 0 for c in controls) else None,
            'states': [before, named, after, continued]}


def capture(reference, output, major):
    require_runner()
    producer = version(major)
    require(not output.exists(), 'refusing to replace lifecycle evidence')
    output.parent.mkdir(parents=True, exist_ok=True)
    command = Commands(output.with_suffix('.diagnostics.json'))
    with tempfile.TemporaryDirectory(prefix='apfs-lifecycle-', dir=output.parent) as temporary:
        work = Path(temporary)
        corpus = work / 'corpus'
        corpus.mkdir()
        helper = work / 'apfs-storage'
        command('xcrun', 'clang', '-Wall', '-Wextra', '-Werror', '-O2',
                Path(__file__).with_name('apfs_storage.c'), '-o', helper)
        snapshot_helper = work / 'apfs-snapshot'
        command('xcrun', 'clang', '-Wall', '-Wextra', '-Werror', '-O2',
                Path(__file__).with_name('apfs_snapshot.c'), '-o', snapshot_helper)
        entitled_helper = work / 'apfs-snapshot-entitled'
        shutil.copyfile(snapshot_helper, entitled_helper)
        entitled_helper.chmod(0o755)
        command('codesign', '--force', '--sign', '-', '--entitlements',
                Path(__file__).with_name('apfs_snapshot.entitlements'), entitled_helper)
        command('codesign', '--display', '--entitlements', '-', entitled_helper)
        selected_helper, producer['snapshotObserver'] = snapshot_observer(snapshot_helper, entitled_helper, command)
        producer['tools'] = [{'path': str(path), 'sha256': sha256(path)} for path in
                             (Path('/bin/cp'), Path('/usr/sbin/diskutil'), Path('/usr/bin/hdiutil'),
                              Path(APFS_UTIL), Path(MOUNT_APFS), Path('/usr/bin/codesign'), helper,
                              snapshot_helper, entitled_helper)]
        producer['sources'] = []
        for name in SOURCES:
            source = corpus / name
            shutil.copyfile(Path(__file__).with_name(name), source)
            producer['sources'].append({'source': name, 'sha256': sha256(source)})
        try:
            cases = [capture_clones('apfs' + ('-case-sensitive' if sensitive else ''), sensitive,
                                    work, corpus, command, helper, major) for sensitive in (False, True)]
            cases += [capture_snapshot_history(case_id, reference, work, corpus, command, helper, selected_helper)
                      for case_id in ('apfs', 'apfs-case-sensitive')]
        except BaseException as error:
            command.save()
            shutil.copyfile(command.path, corpus / 'commands.json')
            retain_incomplete(corpus, output, producer, error)
            raise
        # Preserve parent observations and collector bytes, rather than creating
        # an undocumented naming projection of the prior native evidence.
        parent = corpus / 'snapshot-reference'
        parent.mkdir()
        for path in reference.iterdir():
            if path.is_file() and (path.suffix != '.dmg' or path.name in ('apfs.dmg', 'apfs-case-sensitive.dmg')):
                shutil.copyfile(path, parent / path.name)
        manuals = corpus / 'manuals'
        manuals.mkdir()
        for name in ('diskutil.8', 'apfs.util.8', 'newfs_apfs.8'):
            original = Path('/usr/share/man/man8') / name
            shutil.copyfile(original, manuals / name)
        command.save()
        shutil.copyfile(command.path, corpus / 'commands.json')
        manifest = {'schema': 1, 'contract': 'apfs-native-lifecycle', 'producer': producer,
                    'commandsSHA256': sha256(corpus / 'commands.json'), 'cases': cases,
                    'limits': ['Snapshot API success/refusal is recorded per operation; issue 74 blocks unavailable positive mutation controls.',
                               'Conversion controls cover ordinary volumes; conversion of retained encrypted history remains a separate gate.',
                               'Software key profiles are established by native unlock and keybag decoding, not AES primitive support.']}
        (corpus / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
        for progress in corpus.glob('*-progress.json'):
            progress.unlink()
        corpus.rename(output)


def retain_incomplete(corpus, output, producer, error):
    """Preserve failed native states as diagnostics, never as a reference corpus."""
    failed = {'complete': False, 'producer': producer, 'error': str(error),
              'files': [{'path': str(p.relative_to(corpus)), 'sha256': sha256(p)}
                        for p in sorted(corpus.rglob('*')) if p.is_file()]}
    (corpus / 'incomplete.json').write_text(json.dumps(failed, indent=2) + '\n')
    with zipfile.ZipFile(output.with_suffix('.incomplete.zip'), 'x', compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(corpus.rglob('*')):
            if path.is_file():
                archive.write(path, path.relative_to(corpus))


def main():
    require_runner()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--references', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--expected-major', required=True, type=int, choices=(15, 26, 27))
    args = parser.parse_args()
    capture(args.references, args.output.absolute(), args.expected_major)


if __name__ == '__main__':
    main()
