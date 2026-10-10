"""Qualify fresh encrypted envelopes through Apple's image driver.

Each randomized ciphertext must unlock independently. Complete native device
hashes must equal the plaintext image whose filesystem/metadata/signatures were
already checked. No Go decoder supplies this verdict.
"""
import hashlib
import plistlib

from capture import sha256
from container_building import require_disposable_host
from image_repacking import attach, info
from verify_preservation import require

PASSWORD = 'public-output-λ-😀'
BUILD_PROFILES = {('apfs', 'UDRO'): 128, ('apfs-case-sensitive', 'UDZO'): 256,
                  ('hfsplus', 'UDZO'): 128, ('hfsx', 'UDRO'): 256, ('group', 'UDZO'): 256}


def disk_hash(image, command):
    require_disposable_host()
    device, _ = attach(image, command)
    try:
        size = info(device, command)['TotalSize']
        digest = hashlib.sha256()
        with open(device.replace('/dev/disk', '/dev/rdisk'), 'rb', buffering=0) as stream:
            remaining = size
            while remaining:
                data = stream.read(min(1 << 20, remaining))
                require(data, 'short native encrypted-image device')
                digest.update(data)
                remaining -= len(data)
        return size, digest.hexdigest()
    finally:
        command('hdiutil', 'detach', device)


def verify(images, bits, command):
    """images are the plaintext outputs; encrypted siblings use the same format."""
    require_disposable_host()
    require(len(images) == 3, 'all portable encryption producers required')
    require(len({sha256(p) for p in images}) == 1, 'plaintext hosts differ')
    expected = disk_hash(images[0], command)
    ciphertexts = []
    for plain in images:
        image = plain.parent / 'encrypted' / plain.name
        before = sha256(image)
        def unlocked(*argv, **kwargs):
            if str(argv[0]) == 'hdiutil' and str(image) in list(map(str, argv)):
                argv = (*argv[:2], '-stdinpass', *argv[2:])
                kwargs['fixture_input'] = PASSWORD.encode() + b'\0'
            return command(*argv, **kwargs)
        native = plistlib.loads(unlocked('hdiutil', 'imageinfo', '-plist', image))
        require(native['Format'] == plain.stem and native['Properties']['Encrypted'], 'native encrypted output format')
        store, ciphers = native['Backing Store Information'], []
        while isinstance(store, dict):
            if 'Encryption' in store:
                ciphers.append(store['Encryption'])
            store = store.get('Backing Store Information')
        require(ciphers == [f'AES-{bits}'], 'native output cipher')
        command('hdiutil', 'imageinfo', '-plist', '-stdinpass', image,
                fixture_input=b'public-wrong-output-password\0', expected_success=False)
        unlocked('hdiutil', 'verify', image)
        require(disk_hash(image, unlocked) == expected, 'encryption changed decoded disk sectors')
        require(sha256(image) == before, 'native encrypted readback changed output')
        ciphertexts.append(before)
    require(len(set(ciphertexts)) == len(images), 'independent builds reused encrypted output bytes')
    print(f'Apple decrypted {len(images)} distinct AES-{bits} images to the exact qualified disk: {images[0]}', flush=True)
