"""Measure Apple image sizing and caller-available space on disposable CI VMs.

These are native controls, not an expected Go sizing formula. They distinguish
physical free blocks from usable space and compare native allocation on images
created by Apple and Go from the same source tree.
"""
import errno
import json
import os
from pathlib import Path
import plistlib
import tempfile

from capture import sha256
from verify_preservation import require


def verify_capacity(size, sensitive, empty):
    if empty or sensitive:
        require(size == (64 if empty else 160) * 1024 * 1024, 'requested volume capacity')
    else:
        # Added ordinary input bytes can exceed the shared 8 MiB minimum.
        require(8 * 1024 * 1024 <= size <= 1 << 40 and size % 4096 == 0,
                'automatic volume capacity')


def space(root):
    value = os.statvfs(root)
    return {'blockSize': value.f_frsize, 'blocks': value.f_blocks,
            'freeBlocks': value.f_bfree, 'availableBlocks': value.f_bavail}


def measure(image, command):
    """Bounded native writes to a private shadow; original sectors stay intact."""
    from container_building import require_disposable_host
    require_disposable_host()
    before = sha256(image)
    with tempfile.TemporaryDirectory(prefix='apfs-capacity-measure-') as work:
        work = Path(work)
        mount = work / 'mount'; mount.mkdir()
        attached = plistlib.loads(command('hdiutil', 'attach', '-plist', '-nobrowse',
            '-owners', 'off', '-shadow', work / 'writes.shadow', '-mountpoint', mount, image))
        device = attached['system-entities'][0]['dev-entry']
        try:
            info = plistlib.loads(command('diskutil', 'info', '-plist', mount))
            result = {'totalBytes': info['TotalSize'], 'before': space(mount),
                      'nativeSpace': {key: value for key, value in info.items()
                                      if key in ('APFSContainerFree', 'APFSContainerSize',
                                                 'CapacityInUse', 'FreeSpace')}}
            payload = bytes(range(256)) * 256
            written = 0
            failure = None
            try:
                with (mount / 'native-capacity-probe').open('wb', buffering=0) as stream:
                    # Stop at 8 MiB: this measures small-image admission, not
                    # unbounded disk pressure or the application's host disk.
                    for _ in range(128):
                        count = stream.write(payload)
                        written += count
                        require(count == len(payload), 'native probe short write')
                        os.fsync(stream.fileno())
            except OSError as error:
                if error.errno != errno.ENOSPC:
                    raise
                failure = 'ENOSPC'
            result.update(writtenBytes=written, stopped=failure or '8-MiB-limit', after=space(mount))
        finally:
            command('hdiutil', 'detach', device)
    require(sha256(image) == before, 'native capacity probe changed original image')
    return result


def compare(corpus, outputs, command, major):
    """Use one native source producer for all four filesystem profiles."""
    from container_building import require_disposable_host
    require_disposable_host()
    source = corpus / 'macos-15'
    manifest = json.loads((source / 'manifest.json').read_text())
    results = []
    report = outputs / f'image-capacity-{major}.diagnostics.json'
    for case in manifest['cases']:
        case_id = case['id'].split('/')[1]
        source_image = source / case['image']
        require(sha256(source_image) == case['sha256'], 'capacity source digest')
        filesystem = case['expected']['filesystem']
        native_format = ('Case-sensitive ' if case['expected']['caseSensitive'] else '') + (
            'APFS' if filesystem == 'APFS' else 'HFS+')
        go_image = outputs / 'image-building-Linux/macos-15' / case_id / 'UDRO.dmg'
        result = {'case': case_id, 'go': measure(go_image, command)}
        results.append(result)
        report.write_text(json.dumps(results, indent=2) + '\n')
        with tempfile.TemporaryDirectory(prefix='apfs-capacity-control-') as work:
            work = Path(work)
            mount = work / 'source'; mount.mkdir()
            attached = plistlib.loads(command('hdiutil', 'attach', '-readonly', '-plist',
                '-nobrowse', '-mountpoint', mount, source_image))
            device = attached['system-entities'][0]['dev-entry']
            try:
                for policy in ('automatic', 'matching-go-capacity'):
                    image = work / f'{policy}.dmg'
                    # Explicit sizing is observed too: Apple's copy/formatter
                    # may refuse an image this small. Record that honestly.
                    arguments = [] if policy == 'automatic' else [
                        '-sectors', str(result['go']['totalBytes'] // 512)]
                    created = command('hdiutil', 'create', '-srcfolder', mount / 'Fixture',
                        '-fs', native_format, '-layout', 'NONE', '-volname', 'Example',
                        '-format', 'UDRO', *arguments, image,
                        expected_success=True if policy == 'automatic' else None)
                    result['apple-' + policy] = (measure(image, command) if created is not None
                        else {'created': False})
                    report.write_text(json.dumps(results, indent=2) + '\n')
            finally:
                command('hdiutil', 'detach', device)
        print('Native capacity control:', json.dumps(result, sort_keys=True), flush=True)
        require(result['apple-matching-go-capacity'].get('created') is not False,
                f'{case_id}: Apple cannot build the same source at the Go capacity')
    return results
