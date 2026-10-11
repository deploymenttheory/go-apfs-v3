"""Independent Apple catalog create/move/unlink controls for existing HFS images.

Runs only on disposable GitHub VMs. Each source comes from the existing HFS
editing family; expected observations are never supplied by the Go editor.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil

from hfs_editing import STAMP, CAPACITY, payload, read_journal
from hfs_header_growth import attach, read_headers, retain_file
from image_repacking import files
from container_building import require_disposable_host

COUNT = 96

def filename(number):
    return f'{number:03d}-' + 'x' * 100


def apply(root, phase, command, host):
    catalog = root / 'Catalog'
    if phase == 'catalog':
        host.write_bytes(payload('catalog', 8193))
        os.chmod(host, 0o644)
        command('/bin/mkdir', '-p', '-m', '0750', catalog / 'A/B')
        command('/bin/mkdir', catalog / 'other', catalog / 'obsolete')
        for number in range(COUNT):
            command('/bin/cp', host, catalog / 'A/B' / filename(number))
        command('/bin/cp', host, catalog / 'obsolete/child')
        command('/bin/cp', host, catalog / 'caf\u00e9:resource')
        command('/bin/mv', root / 'independent', catalog / 'forked')
        command('/bin/mv', catalog / 'forked', catalog / 'Forked')
        command('/bin/mv', catalog / 'A/B', catalog / 'other/Moved')
        command('/bin/mv', catalog / 'other/Moved' / filename(1), root / 'small')
        command('/bin/mv', root / 'alias', catalog / 'linked')
        command('/bin/rm', root / 'fragmented-data')
        command('/bin/rm', '-r', catalog / 'obsolete')
        # The offline contract uses a supplied creation clock and parent UID/GID.
        # Normalize those explicit fields through Apple's native setattr API;
        # ctime remains the native clock and is compared under a stated policy.
        from metadata_edits import set_metadata
        time = {'value': '2025-06-07T08:09:10.000000000Z'}
        for path in [catalog / 'caf\u00e9:resource', root / 'small', *list((catalog / 'other/Moved').iterdir()),
                     catalog / 'other/Moved', catalog / 'other', catalog / 'A', catalog]:
            set_metadata(path, {'birthTime': time, 'modifyTime': time, 'accessTime': time}, command)
    else:
        command('/bin/rm', catalog / 'linked', root / 'inline-compressed', root / 'resource-compressed')
        for number in range(0, COUNT, 2):
            command('/bin/rm', catalog / 'other/Moved' / filename(number))
        command('/bin/rm', '-r', catalog / 'A')
        command('/bin/mkdir', catalog / 'reused')
        command('/bin/cp', host, catalog / 'reused/contents')
        from metadata_edits import set_metadata
        time = {'value': '2025-06-07T08:09:10.000000000Z'}
        for path in [catalog / 'reused', catalog / 'reused/contents']:
            set_metadata(path, {'birthTime': time, 'modifyTime': time, 'accessTime': time}, command)


def observe_catalog(image, work, command):
    mount = work / ('catalog-read-' + image.stem)
    device = attach(image, command, readonly=True)
    try:
        command('sudo', '/sbin/fsck_hfs', '-fn', device.replace('/dev/disk', '/dev/rdisk'))
        headers = read_headers(image, CAPACITY)
        mount.mkdir()
        command('diskutil', 'mount', 'readOnly', '-mountOptions', 'owners,noatime', '-mountPoint', mount, device)
        command('codesign', '--verify', '--deep', '--strict', mount / 'Fixture/Example.app')
        observed = files(mount / 'Fixture')
        observed['rawAttributes'] = [{'object': item['object'], 'attributes': item['rawAttributes']}
                                     for item in observed['entries']]
        result = {'files': observed, 'headers': headers, 'checkerStatus': 0}
        journal = read_journal(image)
        if journal is not None:
            result['journal'] = journal
        return result
    finally:
        command('hdiutil', 'detach', device)


def capture_case(source, before, filesystem, work, output, command):
    require_disposable_host()
    result = {'id': filesystem, 'source': None, 'before': before, 'states': {}}
    current = source
    host = work / 'catalog-payload'
    for phase in ('catalog', 'catalog-final'):
        edited = work / (filesystem + '-' + phase + '.raw')
        shutil.copyfile(current, edited)
        device = attach(edited, command, writable=True)
        try:
            mount = work / (filesystem + '-' + phase + '-write')
            mount.mkdir()
            command('diskutil', 'mount', '-mountOptions', 'noowners,noatime', '-mountPoint', mount, device)
            apply(mount / 'Fixture', phase, command, host)
        finally:
            command('hdiutil', 'detach', device)
        state = observe_catalog(edited, work, command)
        state['archive'] = retain_file(edited, output / (filesystem + '-' + phase + '.raw.gz'))
        result['states'][phase] = state
        current = edited
    return result


def write_manifest(output, producer, cases, major, journaled):
    producer = dict(producer)
    producer['sources'] = dict(producer['sources'])
    name = Path(__file__).name
    producer['sources'][name] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    shutil.copyfile(__file__, output / name)
    manifest = {'schema': 1, 'major': major, 'producer': producer, 'cases': cases,
                'contract': 'journaled-hfs-catalog-edits' if journaled else 'existing-hfs-catalog-edits',
                'modificationSeconds': STAMP, 'capacityBytes': CAPACITY,
                'commandsSHA256': hashlib.sha256((output / 'commands.json').read_bytes()).hexdigest()}
    (output / 'catalog-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
