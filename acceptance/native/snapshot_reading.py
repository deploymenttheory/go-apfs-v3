"""Apple snapshot history on disposable APFS images; no Go-produced expectations.

Apple Software Restore creates temporary snapshots while copying a volume.
Mounting one keeps it alive while the copy completes. This collector retains
those Apple-created snapshots on disposable images and records their real names.
No system volume is selected, and production Go never calls native APIs.
"""

import ctypes
import errno
import json
import os
from pathlib import Path
import plistlib
import signal
import subprocess
import time
import stat
import struct
import sys


MOUNT_APFS = "/System/Library/Filesystems/apfs.fs/Contents/Resources/mount_apfs"


def snapshot_attributes(mount, fd=None):
    """Public sys/snapshot.h API; invoked in its own bounded native command."""
    lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    owned = fd is None
    if owned:
        fd = os.open(mount, os.O_RDONLY | os.O_DIRECTORY)
    else:
        os.lseek(fd, 0, os.SEEK_SET)
    try:
        class AttrList(ctypes.Structure):
            _fields_ = [("count", ctypes.c_uint16), ("reserved", ctypes.c_uint16),
                        ("common", ctypes.c_uint32), ("volume", ctypes.c_uint32),
                        ("directory", ctypes.c_uint32), ("file", ctypes.c_uint32),
                        ("fork", ctypes.c_uint32)]

        # ATTR_CMN_RETURNED_ATTRS | NAME | CRTIME | MODTIME | CHGTIME.
        request = AttrList(5, 0, 0x80000e01, 0, 0, 0, 0)
        lib.fs_snapshot_list.argtypes = [ctypes.c_int, ctypes.POINTER(AttrList),
                                        ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32]
        result = []
        while True:
            buffer = ctypes.create_string_buffer(65536)
            count = lib.fs_snapshot_list(fd, ctypes.byref(request), buffer, len(buffer), 0)
            if count < 0:
                raise OSError(ctypes.get_errno(), "fs_snapshot_list")
            if count == 0:
                break
            data, offset = buffer.raw, 0
            for _ in range(count):
                length, common = struct.unpack_from("=II", data, offset)
                if length < 32 or offset + length > len(data) or not common & 1:
                    raise RuntimeError("invalid native snapshot attribute record")
                cursor = offset + 24  # record length and attribute_set_t
                relative, size = struct.unpack_from("=iI", data, cursor)
                start = cursor + relative
                if size == 0 or start < offset or start + size > offset + length:
                    raise RuntimeError("invalid native snapshot name bounds")
                raw = data[start:start + size]
                if raw[-1] != 0:
                    raise RuntimeError("unterminated native snapshot name")
                entry = {"name": os.fsdecode(raw[:-1])}
                cursor += 8
                for mask, field in [(0x200, "createNS"), (0x400, "modifyNS"), (0x800, "changeNS")]:
                    if common & mask:
                        if cursor + 16 > offset + length:
                            raise RuntimeError("invalid native snapshot timestamp bounds")
                        seconds, nanos = struct.unpack_from("=qq", data, cursor)
                        entry[field] = seconds * 1_000_000_000 + nanos
                        cursor += 16
                result.append(entry)
                offset += length
            if len(result) > 4096:
                raise RuntimeError("excessive native snapshot inventory")
        return result
    finally:
        if owned:
            os.close(fd)



def retain_snapshot(mount, target, pin):
    """Retain ASR's snapshot using an ordinary native read-only mount.

    Stop our child after its snapshot appears, mount it, then let the copy finish
    normally. No process injection, signature changes or entitlement is involved.
    A missed snapshot or unsuccessful copy fails capture, never fabricates data.
    """
    fd = os.open(mount, os.O_RDONLY | os.O_DIRECTORY)
    process, pinned = None, False
    try:
        argv = ["/usr/sbin/asr", "restore", "--source", mount, "--target", target,
                "--erase", "--noprompt"]
        process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        name = "com.apple.asr." + str(process.pid)
        deadline = time.monotonic() + 30
        while process.poll() is None and time.monotonic() < deadline:
            if any(s["name"] == name for s in snapshot_attributes(mount, fd)):
                process.send_signal(signal.SIGSTOP)
                break
            time.sleep(0.001)
        else:
            raise RuntimeError("ASR snapshot was not observed before copy completion/deadline")
        subprocess.run([MOUNT_APFS, "-o", "rdonly,owners,nobrowse", "-s", name, mount, pin],
                       check=True, capture_output=True, timeout=15)
        pinned = True
        process.send_signal(signal.SIGCONT)
        stdout, stderr = process.communicate(timeout=45)
        if process.returncode:
            raise RuntimeError(("ASR copy failed", process.returncode, stdout.decode(), stderr.decode()))
        if not any(s["name"] == name for s in snapshot_attributes(mount, fd)):
            raise RuntimeError("ASR snapshot disappeared while mounted")
        return {"name": name, "argv": argv, "status": process.returncode,
                "stdout": stdout.decode(), "stderr": stderr.decode()}
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
        if pinned:
            subprocess.run(["/sbin/umount", pin], check=True, capture_output=True, timeout=15)
        os.close(fd)

def capture(work, corpus, command, create_files, observe_files, sha256):
    helper = Path(__file__).resolve()

    def create_snapshot(mount, sequence):
        target = work / ("asr-target-" + str(sequence) + ".dmg")
        command("hdiutil", "create", "-size", "128m", "-fs", "APFS", "-type", "UDIF", target)
        raw = command("hdiutil", "attach", "-plist", "-owners", "on", target)
        entities = plistlib.loads(raw)["system-entities"]
        device = next(e["dev-entry"] for e in entities if "dev-entry" in e)
        try:
            target_mount = next(e["mount-point"] for e in entities if "mount-point" in e)
            pin = work / ("asr-pin-" + str(sequence))
            pin.mkdir()
            result = json.loads(command(sys.executable, helper, "retain", mount, target_mount, pin))
            if not any(s["SnapshotName"] == result["name"] for s in inventory(mount)["Snapshots"]):
                raise RuntimeError("native snapshot did not survive unmount")
            return result["name"]
        finally:
            # ASR remounts its disposable target and can leave mounted APFS
            # children. Unmount the whole target before detaching its image.
            command("diskutil", "unmountDisk", "force", device)
            # DiskImages can still report EBUSY after that unmount succeeds.
            # Retry only this scratch-target cleanup; retain every attempt in
            # the transcript and fail on other errors or persistent EBUSY.
            for attempt in range(6):
                try:
                    command("hdiutil", "detach", device)
                    break
                except subprocess.CalledProcessError as error:
                    if error.returncode != errno.EBUSY or attempt == 5:
                        raise
                    time.sleep(1)


    def info(device):
        return plistlib.loads(command("diskutil", "info", "-plist", device))

    def inventory(mount):
        return plistlib.loads(command("diskutil", "apfs", "listSnapshots", "-plist", mount))

    def attach(image, encrypted, image_password=None, readonly=False):
        raw = command("hdiutil", "attach", "-plist", "-nomount", "-owners", "on",
                      *(["-readonly"] if readonly else []),
                      *(["-stdinpass"] if image_password is not None else []), image,
                      fixture_input=None if image_password is None else image_password.encode() + b"\0")
        devices = [e["dev-entry"] for e in plistlib.loads(raw)["system-entities"] if "dev-entry" in e]
        if not devices:
            raise RuntimeError("missing disposable image device")
        try:
            volumes = [(d, info(d)) for d in devices]
            volumes = [(d, i) for d, i in volumes if i.get("VolumeUUID")]
            if len(volumes) != 1:
                raise RuntimeError("expected one disposable APFS volume")
            volume, initial = volumes[0]
            if encrypted:
                if not initial.get("Locked"):
                    # Native attachment can reuse an unlock after ASR. Establish
                    # an observed locked state before testing the APFS credential.
                    command("diskutil", "apfs", "lockVolume", volume)
                    initial = info(volume)
                if not initial.get("Locked") or not initial.get("FileVault"):
                    raise RuntimeError("could not establish locked encrypted APFS")
                if image_password is not None:
                    command("diskutil", "apfs", "unlockVolume", volume, "-stdinpassphrase", "-nomount", "-plist",
                            fixture_input=image_password.encode() + b"\n", expected_success=False)
                    if not info(volume).get("Locked"):
                        raise RuntimeError("DMG credential unlocked APFS")
                command("diskutil", "apfs", "unlockVolume", volume, "-stdinpassphrase", "-nomount", "-plist",
                        fixture_input=b"apfs-v3-public-fixture\n")
            command("diskutil", "mount", "-mountOptions", "owners", volume)
            native = info(volume)
            if not native.get("GlobalPermissionsEnabled") or bool(native["WritableVolume"]) == readonly:
                raise RuntimeError("incorrect native mount ownership or read-only state")
            return devices[0], Path(native["MountPoint"]), initial
        except BaseException:
            command("hdiutil", "detach", devices[0])
            raise

    def mutate(root, stage):
        (root / "hard-link").write_bytes(("contents " + stage + "\n").encode())
        os.chmod(root / "example.txt", 0o740 if stage == "middle" else 0o604)
        os.chflags(root / "example.txt", 0 if stage == "middle" else stat.UF_HIDDEN)
        command("xattr", "-w", "org.go-apfs.binary", "attribute " + stage, root / "example.txt")
        with open(str(root / "example.txt") + "/..namedfork/rsrc", "wb") as stream:
            stream.write(("resource " + stage).encode() * 4097)
        with (root / "clone.bin").open("r+b") as stream:
            stream.seek(4609)
            stream.write(("clone " + stage).encode())
        with (root / "sparse").open("r+b") as stream:
            stream.seek(65537)
            stream.write(("sparse " + stage).encode())
        (root / "generation.txt").write_text(stage + "\n")
        (root / "ReadMe").write_text(stage + " filename lookup\n")

    cases = []
    for case_id, sensitive, encrypted in [("apfs", False, False),
            ("apfs-case-sensitive", True, False), ("apfs-encrypted-dmg", False, True)]:
        scratch = work / (case_id + "-writable.dmg")
        name = "v3-snapshots-" + case_id
        command("hdiutil", "create", "-size", "128m", "-layout", "GPTSPUD",
                "-fs", "Case-sensitive APFS" if sensitive else "APFS",
                *(["-fsargs", "-E -S apfs-v3-public-fixture"] if encrypted else []),
                "-volname", name, "-type", "UDIF", scratch)
        device, mount, _ = attach(scratch, encrypted)
        try:
            empty = inventory(mount)
            if empty["Snapshots"]:
                raise RuntimeError("new native volume unexpectedly has snapshots")
            root = mount / "Fixture"
            create_files(root, command)
            os.link(root / "example.txt", root / "hard-link")
            lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
            lib.clonefile.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
            if lib.clonefile(os.fsencode(root / "binary.bin"), os.fsencode(root / "clone.bin"), 0):
                raise OSError(ctypes.get_errno(), "clonefile")
            plain = work / (case_id + "-plain")
            plain.write_bytes(b"Compressed contents retained in APFS snapshots.\n" * 8192)
            command("ditto", "--hfsCompression", plain, root / "compressed")
            if not (root / "compressed").stat().st_flags & stat.UF_COMPRESSED:
                raise RuntimeError("native compression precondition failed")
            for filename in ("vanished", "rename-source", "generation.txt", "ReadMe"):
                (root / filename).write_text("before\n")
            # Allocated, compressible padding gives the observer time to pin ASR's
            # snapshot. It is outside Fixture and carries no expected file results.
            (mount / "asr-padding").write_bytes(b"A" * (16 * 1024 * 1024))
            before_name = create_snapshot(mount, case_id + "-before")
            mutate(root, "middle")
            (root / "vanished").unlink()
            (root / "rename-source").rename(root / "renamed")
            after_name = create_snapshot(mount, case_id + "-after")
            mutate(root, "live")
            (root / "renamed").rename(root / "live-name")
            (root / "vanished").write_text("new live inode\n")
            deleted_name = create_snapshot(mount, case_id + "-deleted")
            deleted = next(s for s in inventory(mount)["Snapshots"] if s["SnapshotName"] == deleted_name)
            command("diskutil", "apfs", "deleteSnapshot", mount, "-name", deleted_name, "-wait")
            if encrypted:
                command("diskutil", "apfs", "lockVolume", mount)
        finally:
            command("hdiutil", "detach", device)
        image_password = "public-snapshot-image-password" if encrypted else None
        image = corpus / (case_id + ".dmg")
        command("hdiutil", "convert", scratch, "-format", "UDZO", "-o", image,
                *(["-encryption", "AES-256", "-stdinpass"] if encrypted else []),
                fixture_input=None if image_password is None else image_password.encode() + b"\0")
        before = sha256(image)
        device, mount, locked = attach(image, encrypted, image_password, readonly=True)
        try:
            raw = command("diskutil", "info", "-plist", mount)
            native = plistlib.loads(raw)
            if native["VolumeName"] != name or ("case-sensitive" in native["FilesystemName"].lower()) != sensitive:
                raise RuntimeError("native snapshot filesystem profile differs")
            raw_path = corpus / (case_id + "-diskutil.plist")
            raw_path.write_bytes(raw)
            native_snapshots = inventory(mount)
            entries = native_snapshots["Snapshots"]
            if {s["SnapshotName"] for s in entries} != {before_name, after_name}:
                raise RuntimeError("incorrect retained snapshot inventory")
            plist_path = corpus / (case_id + "-snapshots.plist")
            plist_path.write_bytes(plistlib.dumps(native_snapshots))
            attrs = snapshot_attributes(mount)
            if {s["name"] for s in attrs} != {s["SnapshotName"] for s in entries}:
                raise RuntimeError("native snapshot enumeration APIs disagree")
            observation = observe_files(mount / "Fixture")
            snapshots = []
            for snapshot in entries:
                target = work / (case_id + "-snapshot-" + str(snapshot["SnapshotXID"]))
                target.mkdir()
                command(MOUNT_APFS, "-o", "rdonly,owners,nobrowse", "-s", snapshot["SnapshotName"], mount, target)
                try:
                    observed = observe_files(target / "Fixture")
                    if not os.statvfs(target).f_flag & os.ST_RDONLY:
                        raise RuntimeError("snapshot mount must be read-only")
                    observed["lookups"] = []
                    for spelling in ("ReadMe", "readme", "vanished", "rename-source", "renamed", "live-name"):
                        try:
                            object_id = (target / "Fixture" / spelling).lstat().st_ino
                        except FileNotFoundError:
                            object_id = 0
                        observed["lookups"].append({"path": "Fixture/" + spelling, "object": object_id})
                    snapshot_files = corpus / (case_id + "-snapshot-" + str(snapshot["SnapshotXID"]) + ".json")
                    snapshot_files.write_text(json.dumps(observed, indent=2) + "\n")
                    attribute = next(a for a in attrs if a["name"] == snapshot["SnapshotName"])
                    snapshots.append({"name": snapshot["SnapshotName"], "xid": snapshot["SnapshotXID"],
                        "uuid": snapshot["SnapshotUUID"], "attributes": attribute,
                        "files": snapshot_files.name, "filesSHA256": sha256(snapshot_files), "readOnly": True})
                finally:
                    command("/sbin/umount", target)
            observation["snapshots"] = {"emptyBefore": empty["Snapshots"] == [],
                "inventory": plist_path.name, "inventorySHA256": sha256(plist_path),
                "deletedName": deleted["SnapshotName"], "deletedXID": deleted["SnapshotXID"], "entries": snapshots}
            if encrypted:
                locked_path = corpus / (case_id + "-locked.plist")
                locked_path.write_bytes(plistlib.dumps(locked))
                # Rejected credentials are already qualified by the encryption
                # families. This family records only its own native unlock.
                observation["snapshotPasswords"] = {"image": image_password, "volume": "apfs-v3-public-fixture",
                    "lockedObservation": locked_path.name, "lockedObservationSHA256": sha256(locked_path)}
            files = corpus / (case_id + "-files.json")
            files.write_text(json.dumps(observation, indent=2) + "\n")
            command("diskutil", "verifyVolume", mount)
        finally:
            command("hdiutil", "detach", device)
        if sha256(image) != before:
            raise RuntimeError("native snapshot examination changed image bytes")
        command("hdiutil", "verify", *(["-stdinpass"] if encrypted else []), image,
                fixture_input=None if image_password is None else image_password.encode() + b"\0")
        cases.append({"id": "snapshot-reading/" + case_id, "image": image.name, "sha256": before,
            "observation": raw_path.name, "observationSHA256": sha256(raw_path), "files": files.name,
            "filesSHA256": sha256(files), "expected": {"filesystem": "APFS", "name": name,
                "caseSensitive": sensitive, "blockSize": native["VolumeAllocationBlockSize"],
                "size": native["TotalSize"], "uuid": native["VolumeUUID"].upper()}})
    return cases


if __name__ == "__main__":
    if sys.argv[1] != "retain":
        raise ValueError("unknown snapshot helper operation")
    print(json.dumps(retain_snapshot(*sys.argv[2:])))
