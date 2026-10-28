#!/usr/bin/env python3
"""Download an immutable Actions artifact without allocating its zero-filled blocks.

Native macOS runners use bsdtar's sparse ZIP extraction. Verify the entire
archive digest before publishing the directory; the existing output-storage
step still verifies every original image against its manifest before sharing.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


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
        archive_endpoint = (
            f"repos/{os.environ['GITHUB_REPOSITORY']}/actions/artifacts/"
            f"{int(artifact['id'])}/zip"
        )
        # No archive is stored alongside the extracted files. Keep temporary
        # files private until download, ZIP extraction and SHA-256 all succeed.
        with subprocess.Popen(["gh", "api", archive_endpoint], stdout=subprocess.PIPE) as source:
            try:
                with subprocess.Popen(
                    ["/usr/bin/tar", "-xSf", "-", "-C", work], stdin=subprocess.PIPE
                ) as extractor:
                    try:
                        checksum = hashlib.sha256()
                        extracting = True
                        while chunk := source.stdout.read(1024 * 1024):
                            checksum.update(chunk)
                            if extracting:
                                try:
                                    extractor.stdin.write(chunk)
                                except BrokenPipeError:
                                    if extractor.wait() != 0:
                                        raise ValueError("artifact ZIP extraction failed") from None
                                    # Streaming ZIP extraction can finish at the
                                    # central directory. Still hash the entire
                                    # archive, including its directory/comment.
                                    extracting = False
                        try:
                            extractor.stdin.close()
                        except BrokenPipeError:
                            pass
                    except BaseException:
                        extractor.terminate()
                        raise
                    if extractor.wait() != 0:
                        raise ValueError("artifact ZIP extraction failed")
                if source.wait() != 0:
                    raise ValueError("artifact download failed")
                if "sha256:" + checksum.hexdigest() != digest:
                    raise ValueError("artifact SHA-256 mismatch")
                os.rename(work, destination)
            except BaseException:
                source.terminate()
                raise
    files = [p.stat() for p in destination.rglob("*") if p.is_file()]
    logical = sum(info.st_size for info in files)
    allocated = sum(info.st_blocks * 512 for info in files)
    print(f"Verified and sparsely extracted {name}: {digest}")
    print(f"Extracted {logical} logical bytes using {allocated} allocated bytes")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: download-sparse-artifact.py ARTIFACT DESTINATION")
    download(sys.argv[1], sys.argv[2])
