"""Apple-created encrypted APFS volumes and independent locked/unlocked reads.

All passwords here are public fixture inputs. No Go code creates or observes
these images. Only disposable image devices returned by hdiutil are modified.
"""

import ctypes
import json
import os
from pathlib import Path
import plistlib
import stat
import struct


def capture(work, corpus, command, create_files, observe_files, sha256):
    (corpus / "cryptography.json").write_text(json.dumps(crypto_reference(), indent=2) + "\n")
    profiles = [
        ("apfs", False, "apfs-v3-public-fixture", None),
        ("apfs-case-sensitive", True, "public-initial-password", "public-\u03bb-\U0001f600"),
        ("apfs-long-password", False, "public-" + "long-password-" * 8, None),
        ("apfs-changed-password", True, "public-old-password", "public-new-password"),
    ]

    def info(device):
        return plistlib.loads(command("diskutil", "info", "-plist", device))

    def attach(image, readonly=False):
        attached = plistlib.loads(command("hdiutil", "attach", "-plist", "-nomount",
                                          *(["-readonly"] if readonly else []), image))
        devices = [e["dev-entry"] for e in attached["system-entities"] if "dev-entry" in e]
        if not devices:
            raise RuntimeError("no disposable image device")
        try:
            volumes = [d for d in devices if info(d).get("VolumeUUID")]
            if len(volumes) != 1:
                raise RuntimeError("expected one encrypted APFS volume")
            return devices[0], volumes[0]
        except BaseException:
            command("hdiutil", "detach", devices[0])
            raise

    def unlock(volume, password, success=True):
        result = command("diskutil", "apfs", "unlockVolume", volume,
                         "-stdinpassphrase", "-nomount", "-plist", fixture_input=password.encode() + b"\n",
                         expected_success=success)
        if success:
            # The default removable-media mount substitutes the current user's
            # ownership for on-disk IDs. Observe real ownership on both mounts.
            command("diskutil", "mount", "-mountOptions", "owners", volume)
            if not info(volume).get("GlobalPermissionsEnabled"):
                raise RuntimeError("native mount must expose on-disk ownership")
        return result

    cases = []
    for case_id, sensitive, initial, replacement in profiles:
        scratch = work / (case_id + "-writable.dmg")
        name = "v3-" + case_id
        fsargs = "-E -S " + initial
        command("hdiutil", "create", "-size", "64m", "-layout", "GPTSPUD",
                "-fs", "Case-sensitive APFS" if sensitive else "APFS", "-fsargs", fsargs,
                "-volname", name, "-type", "UDIF", scratch)
        device, volume = attach(scratch)
        try:
            unlock(volume, initial)
            root = Path(info(volume)["MountPoint"]) / "Fixture"
            create_files(root, command)
            os.link(root / "example.txt", root / "hard-link")
            # Shared then modified encrypted extents exercise clone crypto IDs.
            lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
            lib.clonefile.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
            if lib.clonefile(os.fsencode(root / "binary.bin"), os.fsencode(root / "clone.bin"), 0):
                raise OSError(ctypes.get_errno(), "clonefile")
            with (root / "clone.bin").open("r+b") as stream:
                stream.seek(4609)
                stream.write(b"Modified cloned encrypted extent.")
            plain = work / (case_id + "-plain")
            plain.write_bytes(b"Encrypted native compressed file.\n" * 8192)
            command("ditto", "--hfsCompression", plain, root / "compressed")
            if not (root / "compressed").stat().st_flags & stat.UF_COMPRESSED:
                raise RuntimeError("ditto did not produce compressed storage")
            if replacement is not None:
                command("diskutil", "apfs", "changePassphrase", volume, "-user", "disk",
                        "-oldPassphrase", initial, "-newPassphrase", replacement)
        finally:
            command("hdiutil", "detach", device)
        password = initial if replacement is None else replacement
        rejected = ["public-incorrect-password", ""]
        if replacement is not None:
            rejected.append(initial)
        image = corpus / (case_id + ".dmg")
        command("hdiutil", "convert", scratch, "-format", "UDZO", "-o", image)
        before = sha256(image)
        device, volume = attach(image, readonly=True)
        try:
            locked = info(volume)
            if not locked.get("Locked") or not locked.get("FileVault"):
                raise RuntimeError("native volume must start locked and encrypted")
            locked_path = corpus / (case_id + "-locked.plist")
            locked_path.write_bytes(plistlib.dumps(locked))
            for candidate in rejected:
                unlock(volume, candidate, success=False)
                if not info(volume).get("Locked"):
                    raise RuntimeError("incorrect password unlocked the native volume")
            unlock(volume, password)
            raw = command("diskutil", "info", "-plist", volume)
            native = plistlib.loads(raw)
            if native.get("Locked") or native.get("WritableVolume") or not native.get("MountPoint"):
                raise RuntimeError("expected unlocked read-only native mount")
            if native["VolumeName"] != name or ("case-sensitive" in native["FilesystemName"].lower()) != sensitive:
                raise RuntimeError("native volume profile differs")
            raw_path = corpus / (case_id + "-diskutil.plist")
            raw_path.write_bytes(raw)
            observation = observe_files(Path(native["MountPoint"]) / "Fixture")
            observation["encryption"] = {
                "password": password, "rejectedPasswords": rejected,
                "lockedBefore": locked["Locked"], "lockedAfterFailures": True,
                "unlockedReadOnly": not native["Locked"] and not native["WritableVolume"],
                "lockedObservation": locked_path.name, "lockedObservationSHA256": sha256(locked_path),
            }
            files = corpus / (case_id + "-files.json")
            files.write_text(json.dumps(observation, indent=2) + "\n")
        finally:
            command("hdiutil", "detach", device)
        if sha256(image) != before:
            raise RuntimeError("native read-only unlock changed image bytes")
        command("hdiutil", "verify", image)
        cases.append({"id": "file-encryption/" + case_id, "image": image.name,
                      "sha256": before, "observation": raw_path.name,
                      "observationSHA256": sha256(raw_path), "files": files.name,
                      "filesSHA256": sha256(files), "expected": {
                          "filesystem": "APFS", "name": native["VolumeName"],
                          "caseSensitive": sensitive, "blockSize": native["VolumeAllocationBlockSize"],
                          "size": native["TotalSize"], "uuid": native["VolumeUUID"].upper()}})
    return cases


def crypto_reference():
    """Independent Apple CommonCrypto results; these keys are public test data.

    AES-256-XTS vectors qualify the primitive only. newfs_apfs offers no cipher
    selector, so they do not assert a native AES-256-XTS volume profile.
    """
    c = ctypes
    lib = c.CDLL("/usr/lib/system/libcommonCrypto.dylib")
    lib.CCCryptorCreateWithMode.argtypes = [c.c_uint32] * 4 + [c.c_void_p, c.c_void_p, c.c_size_t,
        c.c_void_p, c.c_size_t, c.c_int, c.c_uint32, c.POINTER(c.c_void_p)]
    lib.CCCryptorEncryptDataBlock.argtypes = [c.c_void_p, c.c_void_p, c.c_void_p, c.c_size_t, c.c_void_p]
    lib.CCCryptorRelease.argtypes = [c.c_void_p]
    lib.CCKeyDerivationPBKDF.argtypes = [c.c_uint32, c.c_void_p, c.c_size_t, c.c_void_p,
        c.c_size_t, c.c_uint32, c.c_uint32, c.c_void_p, c.c_size_t]
    for function in (lib.CCSymmetricKeyWrap, lib.CCSymmetricKeyUnwrap):
        function.argtypes = [c.c_uint32, c.c_void_p, c.c_size_t, c.c_void_p, c.c_size_t,
                            c.c_void_p, c.c_size_t, c.c_void_p, c.POINTER(c.c_size_t)]

    def check(status):
        if status != 0:
            raise RuntimeError(f"CommonCrypto status {status}")

    result = {"schema": 1, "api": "Apple CommonCrypto", "xts": [], "passwordKeys": [], "wrappedKeys": []}
    for half in (16, 32):
        key = bytes(range(half * 2))
        for sector in (0, 123, 0x100000003):
            ref = c.c_void_p()
            check(lib.CCCryptorCreateWithMode(0, 8, 0, 0, None, key[:half], half,
                                            key[half:], half, 0, 0, c.byref(ref)))
            plain = bytes((i * 31 + i // 17) % 256 for i in range(1024))
            ciphertext = b""
            try:
                for i in range(2):
                    output = c.create_string_buffer(512)
                    check(lib.CCCryptorEncryptDataBlock(ref, struct.pack("<QQ", sector + i, 0),
                                                       plain[i * 512:(i + 1) * 512], 512, output))
                    ciphertext += output.raw
            finally:
                check(lib.CCCryptorRelease(ref))
            result["xts"].append({"key": key.hex(), "sector": sector, "plain": plain.hex(),
                                  "ciphertext": ciphertext.hex()})
    for password, rounds in ((b"", 1), (b"public\x00password", 2), ("caf\u00e9-\u03bb-\U0001f600".encode(), 1000)):
        salt = bytes(range(16))
        output = c.create_string_buffer(32)
        check(lib.CCKeyDerivationPBKDF(2, password, len(password), salt, len(salt), 3, rounds, output, 32))
        result["passwordKeys"].append({"password": password.hex(), "salt": salt.hex(),
                                       "iterations": rounds, "key": output.raw.hex()})
    for key_size in (16, 32):
        for plain_size in (16, 32):
            key, plain = bytes(range(key_size)), bytes(range(64, 64 + plain_size))
            output, size = c.create_string_buffer(plain_size + 8), c.c_size_t(plain_size + 8)
            check(lib.CCSymmetricKeyWrap(1, b"\xa6" * 8, 8, key, len(key), plain, len(plain), output, c.byref(size)))
            wrapped = output.raw[:size.value]
            decoded, length = c.create_string_buffer(plain_size), c.c_size_t(plain_size)
            check(lib.CCSymmetricKeyUnwrap(1, b"\xa6" * 8, 8, key, len(key), wrapped, len(wrapped), decoded, c.byref(length)))
            if decoded.raw != plain:
                raise RuntimeError("CommonCrypto key wrap readback differs")
            damaged = bytes([wrapped[0] ^ 1]) + wrapped[1:]
            length.value = plain_size
            rejection = lib.CCSymmetricKeyUnwrap(1, b"\xa6" * 8, 8, key, len(key), damaged, len(damaged), decoded, c.byref(length))
            if rejection == 0:
                raise RuntimeError("CommonCrypto accepted damaged wrapped key")
            result["wrappedKeys"].append({"key": key.hex(), "plain": plain.hex(), "wrapped": wrapped.hex(),
                                          "damaged": damaged.hex(), "nativeRejection": rejection})
    return result
