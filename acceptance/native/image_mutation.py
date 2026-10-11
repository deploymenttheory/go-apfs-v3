"""Admit a private Apple-converted writable image for native mutation checks."""
from capture import sha256
from verify_preservation import require


def writable_copy(source, destination, command, disk_hash):
    before = sha256(source)
    sectors = disk_hash(source, command)
    command('hdiutil', 'convert', source, '-format', 'UDRW', '-o', destination)
    require(disk_hash(destination, command) == sectors,
            'native writable conversion changed disk size or sectors')
    require(sha256(source) == before, 'native writable conversion changed original image')
    return destination
