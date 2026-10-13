"""Compile inventoried, unmodified Apple HFS debug formatter only in CI VMs."""
import hashlib
import json
from pathlib import Path
import shutil

from container_building import require_disposable_host
from verify_preservation import require


def build(output, command):
    require_disposable_host()
    source = Path(__file__).parent / 'reference/hfs'
    inventory = json.loads((source / 'source.json').read_text())
    for entry in inventory['files']:
        actual = hashlib.sha256((source / entry['path']).read_bytes()).hexdigest()
        require(actual == entry['sha256'], 'pinned Apple HFS source changed')
    require(hashlib.sha256((source / 'newfs_hfs/wipefs.h').read_bytes()).hexdigest()
            == inventory['wipefsSHA256'], 'pinned Apple libutil header changed')
    include = output / 'include/hfs'
    include.mkdir(parents=True)
    for name in ('hfs_format.h', 'hfs_mount.h'):
        shutil.copyfile(source / 'core' / name, include / name)
    binary = output / 'newfs_hfs_debug'
    command('xcrun', 'clang', '-std=gnu17', '-DDEBUG_BUILD=1',
            '-Wno-deprecated-declarations', '-I', output / 'include',
            '-I', source / 'newfs_hfs',
            *(source / 'newfs_hfs' / name for name in
              ('newfs_hfs.c', 'makehfs.c', 'hfs_endian.c')),
            '-framework', 'CoreFoundation', '-framework', 'CoreServices',
            '-framework', 'IOKit', '-lutil', '-o', binary)
    record = dict(inventory)
    record['binarySHA256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
    record['sdkVersion'] = command('xcrun', '--show-sdk-version').decode().strip()
    (output / 'build.json').write_text(json.dumps(record, indent=2) + '\n')
    return binary, record
