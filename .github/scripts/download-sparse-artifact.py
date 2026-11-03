#!/usr/bin/env python3
"""Verify an Actions artifact and extract exact bytes with bounded disk storage.

The downloaded ZIP is a private cache: after verifying its complete digest,
release input ranges only after their entries have been decoded and checked.
The existing output-storage step independently checks each image's manifest.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import zipfile


def punch_hole(fd, offset, length):
    import fcntl

    # Darwin fpunchhole_t: flags/reserved uint32, offset/length off_t.
    # https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/fcntl.h
    if length:
        fcntl.fcntl(fd, 99, struct.pack("=IIqq", 0, 0, offset, length))


def deallocate_zero_blocks(path):
    # APFS can eagerly allocate small seek-created holes. Make verified zero
    # ranges explicit, using the allocation unit rather than preferred I/O size.
    block_size = os.statvfs(path).f_frsize
    chunk_size = max(128 * 1024, block_size)
    if block_size <= 0 or chunk_size % block_size:
        raise ValueError("unsupported sparse storage block size")
    zeros = bytes(chunk_size)
    with path.open("r+b") as output:
        start = None
        offset = 0
        while True:
            chunk = output.read(chunk_size)
            if chunk == zeros:
                if start is None:
                    start = offset
            else:
                if start is not None:
                    punch_hole(output.fileno(), start, offset - start)
                    start = None
                if not chunk:
                    break
            offset += len(chunk)


def extract_sparse(archive_path, destination):
    zeros = bytes(128 * 1024)
    seen = set()
    with archive_path.open("r+b") as cache, zipfile.ZipFile(cache) as archive:
        entries = sorted(archive.infolist(), key=lambda entry: entry.header_offset)
        block_size = os.fstatvfs(cache.fileno()).f_frsize
        released = 0
        for index, entry in enumerate(entries):
            relative = PurePosixPath(entry.filename)
            if (relative.is_absolute() or not relative.parts
                    or any(part in ("", ".", "..") for part in entry.filename.rstrip("/").split("/"))
                    or "\\" in entry.filename or "\0" in entry.orig_filename):
                raise ValueError("nonlocal artifact entry")
            name = relative.as_posix()
            if name in seen:
                raise ValueError("duplicate artifact entry")
            seen.add(name)
            kind = stat.S_IFMT(entry.external_attr >> 16)
            target = destination.joinpath(*relative.parts)
            if entry.is_dir():
                if entry.file_size or kind not in (0, stat.S_IFDIR):
                    raise ValueError("unsupported artifact directory")
                target.mkdir(parents=True, exist_ok=True)
            else:
                if kind not in (0, stat.S_IFREG):
                    raise ValueError("artifact entries must be regular files")
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(entry) as decoded, target.open("xb") as output:
                    length = 0
                    while chunk := decoded.read(len(zeros)):
                        if chunk == zeros:
                            output.seek(len(chunk), os.SEEK_CUR)
                        else:
                            output.write(chunk)
                        length += len(chunk)
                    if length != entry.file_size:
                        raise ValueError("artifact entry length mismatch")
                    # Preserve zero-filled tails even for ZIP data descriptors.
                    output.truncate(entry.file_size)
                deallocate_zero_blocks(target)
            if index + 1 < len(entries):
                # Only the private input cache changes. Entries are processed
                # in file order, and the next header remains untouched.
                end = entries[index + 1].header_offset // block_size * block_size
                if end > released:
                    punch_hole(cache.fileno(), released, end - released)
                    released = end


def download(name, destination):
    destination = Path(destination)
    if destination.exists():
        raise ValueError("artifact destination already exists")
    endpoint = (
        f"repos/{os.environ['GITHUB_REPOSITORY']}/actions/runs/"
        f"{os.environ['GITHUB_RUN_ID']}/artifacts?per_page=100"
    )
    listing = json.loads(subprocess.check_output(["gh", "api", endpoint]))
    matches = [a for a in listing["artifacts"] if a["name"] == name]
    if len(matches) != 1 or matches[0]["expired"]:
        raise ValueError("expected exactly one unexpired artifact")
    artifact = matches[0]
    digest = artifact.get("digest", "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("artifact has no SHA-256 digest")
    destination.parent.mkdir(parents=True, exist_ok=True)
    print(f"Available bytes before {name}: {shutil.disk_usage(destination.parent).free}", flush=True)
    with tempfile.TemporaryDirectory(prefix=".artifact-", dir=destination.parent) as work:
        work = Path(work)
        archive_path = work / "download.zip"
        archive_endpoint = (
            f"repos/{os.environ['GITHUB_REPOSITORY']}/actions/artifacts/"
            f"{int(artifact['id'])}/zip"
        )
        checksum = hashlib.sha256()
        with archive_path.open("xb") as cache:
            with subprocess.Popen(["gh", "api", archive_endpoint], stdout=subprocess.PIPE) as source:
                try:
                    while chunk := source.stdout.read(1024 * 1024):
                        checksum.update(chunk)
                        cache.write(chunk)
                    if source.wait() != 0:
                        raise ValueError("artifact download failed")
                except BaseException:
                    source.terminate()
                    raise
        if "sha256:" + checksum.hexdigest() != digest:
            raise ValueError("artifact SHA-256 mismatch")
        extracted = work / "extracted"
        extracted.mkdir()
        extract_sparse(archive_path, extracted)
        os.rename(extracted, destination)
    files = [p.stat() for p in destination.rglob("*") if p.is_file()]
    logical = sum(info.st_size for info in files)
    allocated = sum(info.st_blocks * 512 for info in files)
    print(f"Verified and sparsely extracted {name}: {digest}")
    print(f"Extracted {logical} logical bytes using {allocated} allocated bytes")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: download-sparse-artifact.py ARTIFACT DESTINATION")
    download(sys.argv[1], sys.argv[2])
