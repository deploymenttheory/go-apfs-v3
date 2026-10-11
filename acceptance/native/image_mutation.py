"""Admit an exact private raw-device copy for native mutation checks."""
import hashlib
import os

from capture import sha256
from verify_preservation import require


def copy_disk(source, destination, command):
    from container_building import require_disposable_host
    from image_repacking import attach, info
    require_disposable_host()
    device, _ = attach(source, command)
    try:
        size = info(device, command)['TotalSize']
        digest = hashlib.sha256()
        with open(device.replace('/dev/disk', '/dev/rdisk'), 'rb', buffering=0) as reader, destination.open('xb') as writer:
            remaining = size
            while remaining:
                data = reader.read(min(1 << 20, remaining))
                require(data, 'short native device during writable copy')
                require(writer.write(data) == len(data), 'short native writable copy')
                digest.update(data)
                remaining -= len(data)
            writer.flush()
            os.fsync(writer.fileno())
        return size, digest.hexdigest()
    finally:
        command('hdiutil', 'detach', device)


def writable_copy(source, destination, command, disk_hash, copy_device=copy_disk):
    before = sha256(source)
    sectors = copy_device(source, destination, command)
    require(disk_hash(destination, command) == sectors,
            'native writable copy changed disk size or sectors')
    require(sha256(source) == before, 'native writable copy changed original image')
    return destination
