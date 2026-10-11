"""Isolate HFS catalog growth across Apple envelopes and shadow/direct writes.

This diagnostic records every control's verdict; the ordinary acceptance gate
still independently qualifies the original Go output. Native operations require
a disposable VM, and direct writes use private Apple-converted copies only.
"""
import argparse
import json
from pathlib import Path
import struct
import subprocess
import tempfile

import container_building as containers
from capture import sha256
from verify_image_building import verify_native_allocation


def headers(device):
    def decode(raw):
        return {'signature': raw[:2].decode('ascii'),
                'blockSize': struct.unpack_from('>I', raw, 40)[0],
                'totalBlocks': struct.unpack_from('>I', raw, 44)[0],
                'catalogBytes': struct.unpack_from('>Q', raw, 272)[0],
                'catalogBlocks': struct.unpack_from('>I', raw, 284)[0],
                'catalogExtents': [struct.unpack_from('>II', raw, 288 + i * 8) for i in range(8)]}
    with open(device, 'rb', buffering=0) as stream:
        stream.seek(1024)
        primary = decode(stream.read(512))
        stream.seek(primary['blockSize'] * primary['totalBlocks'] - 1024)
        alternate = decode(stream.read(512))
    return {'primary': primary, 'alternate': alternate}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    containers.require_disposable_host()
    before = sha256(args.image)
    results = []
    args.output.parent.mkdir(parents=True, exist_ok=True)
    def command(*argv, fixture_input=None, expected_success=True):
        print('HFS header control:', *map(str, argv), flush=True)
        record = {'argv': list(map(str, argv))}
        results.append(record)
        try:
            r = subprocess.run(record['argv'], input=fixture_input, capture_output=True, timeout=120)
            record.update(status=r.returncode, stdout=r.stdout.decode(errors='replace'), stderr=r.stderr.decode(errors='replace'))
            if Path(str(argv[0])).name == 'fsck_hfs':
                try:
                    record['headers'] = headers(str(argv[-1]))
                except (OSError, ValueError, struct.error) as error:
                    record['headerReadError'] = str(error)
                print('HFS header values:', json.dumps(record.get('headers', record)), flush=True)
            if expected_success is not None and (r.returncode == 0) != expected_success:
                raise ValueError(f'{argv}: {r.stdout.decode(errors="replace")} {r.stderr.decode(errors="replace")}')
            return r.stdout
        finally:
            args.output.write_text(json.dumps(results, indent=2) + '\n')
    with tempfile.TemporaryDirectory(prefix='apfs-hfs-header-controls-') as work:
        work = Path(work)
        for encoding in ('original', 'UDRO', 'UDRW'):
            image = args.image if encoding == 'original' else work / f'{encoding}.dmg'
            if encoding != 'original':
                command('hdiutil', 'convert', args.image, '-format', encoding, '-o', image)
            verdict = {'control': encoding, 'writes': 'direct' if encoding == 'UDRW' else 'shadow'}
            try:
                verify_native_allocation(image, command, apfs=False, file_compression='none', use_shadow=encoding != 'UDRW')
                verdict['passed'] = True
            except (OSError, ValueError) as error:
                verdict.update(passed=False, error=str(error))
            results.append(verdict)
            args.output.write_text(json.dumps(results, indent=2) + '\n')
            print('HFS header control verdict:', json.dumps(verdict), flush=True)
    if sha256(args.image) != before:
        raise ValueError('HFS diagnostic changed original Go image')


if __name__ == '__main__':
    main()
