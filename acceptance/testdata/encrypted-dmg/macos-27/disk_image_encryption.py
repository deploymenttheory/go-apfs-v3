"""Apple-created AES-128/256 DMGs, observed through final read-only mounts.

The image password and an optional APFS volume password are independent public
fixture inputs. Native imageinfo verifies rejected credentials without attaching
a device. No Go code supplies expected data or creates these images.
"""

import json
import os
from pathlib import Path
import plistlib
import stat


def capture(work, corpus, command, create_files, observe_files, sha256):
    profiles = [
        ("apfs-aes128", "APFS", "APFS", False, 128, "UDZO", False, False),
        ("apfs-case-sensitive-aes256", "Case-sensitive APFS", "APFS", True, 256, "UDZO", False, False),
        ("hfsplus-aes128", "HFS+", "HFS+", False, 128, "UDZO", False, False),
        ("hfsx-aes256", "Case-sensitive HFS+", "HFSX", True, 256, "UDZO", True, False),
        ("hfsplus-raw-aes256", "HFS+", "HFS+", False, 256, "UDRW", False, False),
        ("apfs-nested-aes256", "APFS", "APFS", False, 256, "UDZO", False, True),
    ]

    def attach(image, password=None, volume_password=None, readonly=False):
        options = ["-readonly"] if readonly else []
        if volume_password is not None:
            options.append("-nomount")
        if password is not None:
            options.append("-stdinpass")
        raw = command("hdiutil", "attach", "-plist", "-nobrowse", "-noautoopen", "-owners", "on",
                      *options, image, fixture_input=None if password is None else password.encode() + b"\0")
        entities = plistlib.loads(raw)["system-entities"]
        devices = [e["dev-entry"] for e in entities if "dev-entry" in e]
        if not devices:
            raise RuntimeError("no attached fixture device")
        try:
            if volume_password is None:
                mounts = [Path(e["mount-point"]) for e in entities if "mount-point" in e]
                if len(mounts) != 1:
                    raise RuntimeError("expected one mounted filesystem")
                return devices[0], mounts[0], None
            volumes = []
            for device in devices:
                native = plistlib.loads(command("diskutil", "info", "-plist", device))
                if native.get("VolumeUUID"):
                    volumes.append((device, native))
            if len(volumes) != 1 or not volumes[0][1].get("Locked"):
                raise RuntimeError("image unlock must leave the APFS volume locked")
            volume, locked = volumes[0]
            if password is not None:
                for candidate in (password, "public-incorrect-password"):
                    command("diskutil", "apfs", "unlockVolume", volume, "-stdinpassphrase", "-nomount", "-plist",
                            fixture_input=candidate.encode() + b"\n", expected_success=False)
                    after = plistlib.loads(command("diskutil", "info", "-plist", volume))
                    if not after.get("Locked"):
                        raise RuntimeError("image password must not unlock the APFS volume")
            command("diskutil", "apfs", "unlockVolume", volume, "-stdinpassphrase", "-nomount", "-plist",
                    fixture_input=volume_password.encode() + b"\n")
            command("diskutil", "mount", "-mountOptions", "owners", volume)
            native = plistlib.loads(command("diskutil", "info", "-plist", volume))
            if not native.get("GlobalPermissionsEnabled"):
                raise RuntimeError("native mount must expose stored ownership")
            return devices[0], Path(native["MountPoint"]), locked
        except BaseException:
            command("hdiutil", "detach", devices[0])
            raise

    cases = []
    for case_id, native_format, expected_format, sensitive, bits, image_format, change_password, nested in profiles:
        image_password = "public-dmg-\u03bb-\U0001f600" if sensitive else "public-dmg-password"
        volume_password = "apfs-v3-public-fixture" if nested else None
        scratch = work / (case_id + "-writable.dmg")
        name = "v3-" + case_id
        fsargs = ["-fsargs", "-E -S " + volume_password] if nested else []
        command("hdiutil", "create", "-size", "8m" if image_format == "UDRW" else "64m", "-layout", "GPTSPUD",
                "-fs", native_format, *fsargs, "-volname", name, "-type", "UDIF", scratch)
        device, mount, _ = attach(scratch, volume_password=volume_password)
        try:
            root = mount / "Fixture"
            create_files(root, command)
            os.link(root / "example.txt", root / "hard-link")
            plain = work / (case_id + "-plain")
            plain.write_bytes(b"Native files inside an encrypted disk image.\n" * 8192)
            command("ditto", "--hfsCompression", plain, root / "compressed")
            if not (root / "compressed").stat().st_flags & stat.UF_COMPRESSED:
                raise RuntimeError("ditto did not create compressed storage")
        finally:
            command("hdiutil", "detach", device)
        image = corpus / (case_id + ".dmg")
        command("hdiutil", "convert", scratch, "-format", image_format, "-encryption", f"AES-{bits}",
                "-stdinpass", "-o", image, fixture_input=image_password.encode() + b"\0")
        rejected = ["public-incorrect-password", ""]
        if change_password:
            replacement = "public-changed-image-password"
            command("hdiutil", "chpass", image, "-oldstdinpass", "-newstdinpass",
                    fixture_input=image_password.encode() + b"\0" + replacement.encode() + b"\0")
            rejected.append(image_password)
            image_password = replacement
        before = sha256(image)
        for candidate in rejected:
            command("hdiutil", "imageinfo", "-plist", "-stdinpass", image,
                    fixture_input=candidate.encode() + b"\0", expected_success=False)
        image_info_path = corpus / (case_id + "-imageinfo.plist")
        raw = command("hdiutil", "imageinfo", "-plist", "-stdinpass", image,
                      fixture_input=image_password.encode() + b"\0")
        image_info_path.write_bytes(raw)
        native_image = plistlib.loads(raw)
        if not native_image["Properties"]["Encrypted"] or native_image["Format"] != image_format:
            raise RuntimeError("native image envelope profile differs")
        # The backing-store encryption dictionary is Apple-reported, independent
        # of the format bytes interpreted by Go.
        store, ciphers = native_image["Backing Store Information"], []
        while isinstance(store, dict):
            if "Encryption" in store:
                ciphers.append(store["Encryption"])
            store = store.get("Backing Store Information")
        if ciphers != [f"AES-{bits}"]:
            raise RuntimeError(f"unexpected native ciphers: {ciphers}")
        device, mount, locked = attach(image, image_password, volume_password, readonly=True)
        try:
            raw = command("diskutil", "info", "-plist", mount)
            native = plistlib.loads(raw)
            if native.get("WritableVolume") or not native.get("GlobalPermissionsEnabled"):
                raise RuntimeError("native final mount must be read-only with ownership enabled")
            if native["VolumeName"] != name or ("case-sensitive" in native["FilesystemName"].lower()) != sensitive:
                raise RuntimeError("native filesystem name or case policy differs")
            raw_path = corpus / (case_id + "-diskutil.plist")
            raw_path.write_bytes(raw)
            observation = observe_files(mount / "Fixture")
            observation["diskImage"] = {"password": image_password, "rejectedPasswords": rejected,
                "keyBits": bits, "nativeFormat": image_format, "unlockedReadOnly": not native["WritableVolume"],
                "imageObservation": image_info_path.name, "imageObservationSHA256": sha256(image_info_path)}
            if nested:
                locked_path = corpus / (case_id + "-locked.plist")
                locked_path.write_bytes(plistlib.dumps(locked))
                observation["encryption"] = {"password": volume_password,
                    "rejectedPasswords": [image_password, "public-incorrect-password"],
                    "lockedBefore": locked["Locked"], "lockedAfterFailures": True, "unlockedReadOnly": not native["WritableVolume"],
                    "lockedObservation": locked_path.name, "lockedObservationSHA256": sha256(locked_path)}
            files = corpus / (case_id + "-files.json")
            files.write_text(json.dumps(observation, indent=2) + "\n")
        finally:
            command("hdiutil", "detach", device)
        if sha256(image) != before:
            raise RuntimeError("native read-only examination changed encrypted image")
        if image_format != "UDRW":
            command("hdiutil", "verify", "-stdinpass", image, fixture_input=image_password.encode() + b"\0")
        expected = {"filesystem": expected_format, "name": native["VolumeName"], "caseSensitive": sensitive,
                    "blockSize": native["VolumeAllocationBlockSize"], "size": native["TotalSize"]}
        if expected_format == "APFS":
            expected["uuid"] = native["VolumeUUID"].upper()
        cases.append({"id": "disk-image-encryption/" + case_id, "image": image.name, "sha256": before,
                      "observation": raw_path.name, "observationSHA256": sha256(raw_path),
                      "files": files.name, "filesSHA256": sha256(files), "expected": expected})
    return cases
