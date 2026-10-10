"""Independent HFS image-building inputs, including an Apple-signed app bundle.

Apple tools create every source filesystem and signature. Final observations are
captured from a read-only mount; Go is never invoked to produce expectations.
"""
import os
import plistlib
import struct
from pathlib import Path

from preservation import digest_values
import file_compression as compression


def create(root, command, sensitive, create_files):
    create_files(root, command)
    (root / 'deep-catalog').mkdir()
    # Long keys force index nodes above the first index level in the Go builder.
    for i in range(300):
        (root / 'deep-catalog' / (f'{i:04}-' + 'long-name-' * 14)).write_bytes(f'entry {i}\n'.encode())
    os.link(root / 'example.txt', root / 'alias')
    os.link(root / 'example.txt', root / 'many/alias')
    (root / 'case').mkdir()
    (root / 'case/Name').write_bytes(b'upper')
    if sensitive:
        (root / 'case/name').write_bytes(b'lower')
    for name in ('CON', '._ordinary', 'a:b', 'a\\b', 'line\nbreak'):
        (root / name).write_bytes(b'Ordinary source name: ' + name.encode())
    compression.xattr(root / 'example.txt', 'com.apple.FinderInfo', b'TEXTttxt' + bytes(24))
    compression.xattr(root, 'org.go-apfs.root', b'root attribute')
    # Force an attribute B-tree with several leaves and external attribute forks.
    for i in range(40):
        compression.xattr(root / 'example.txt', f'org.go-apfs.attribute-{i:03}', bytes([i]) * 1500)
    data = compression.plain(1200)
    compression.install(root / 'compressed-inline', 3, data, payload=compression.encode(3, data))
    data = compression.plain(65553)
    compression.install(root / 'compressed-resource', 4, data,
                        blocks=[compression.encode(4, data[i:i+65536]) for i in range(0, len(data), 65536)])
    for kind in (1, 7):
        small = compression.plain(73)
        compression.install(root / f'compressed-type-{kind}', kind, small,
                            payload=small if kind == 1 else compression.stored(kind, small))
    plain = root.parent / 'lzvn-source'
    plain.write_bytes(compression.plain(65553))
    command('ditto', '--hfsCompression', '--noclone', plain, root / 'compressed-lzvn')
    if struct.unpack_from('<I', compression.xattr(root / 'compressed-lzvn', compression.ATTRIBUTE), 4)[0] != 8:
        raise RuntimeError('native ditto must supply type-8 LZVN storage')
    app = root / 'Example.app'
    (app / 'Contents/MacOS').mkdir(parents=True)
    (app / 'Contents/Resources').mkdir()
    (app / 'Contents/Resources/message.txt').write_bytes(b'Signed resource preserved by image construction.\n')
    (app / 'Contents/Info.plist').write_bytes(plistlib.dumps({
        'CFBundleIdentifier': 'org.go-apfs.acceptance', 'CFBundleExecutable': 'Example',
        'CFBundleName': 'Example', 'CFBundlePackageType': 'APPL', 'CFBundleVersion': '1'}))
    source = root.parent / 'example.c'
    source.write_text('int main(void) { return 0; }\n')
    command('xcrun', 'clang', '-arch', 'arm64', '-arch', 'x86_64', '-mmacosx-version-min=11.0',
            source, '-o', app / 'Contents/MacOS/Example')
    command('codesign', '--force', '--sign', '-', '--timestamp=none', app)
    command('codesign', '--verify', '--deep', '--strict', app)


def observe(root, observe_files, native_xattrs):
    result = observe_files(root)
    result['rawAttributes'] = [
        {'object': entry['object'], 'attributes': digest_values(native_xattrs(root.parent / entry['path'], 0x21))}
        for entry in result['entries']]
    return result
