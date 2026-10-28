"""Exercise the native artifact download boundary with ordinary file bytes."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location(
    "sparse_download", Path(__file__).with_name("download-sparse-artifact.py")
)
downloader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(downloader)


@unittest.skipUnless(sys.platform == "darwin", "native runner uses macOS bsdtar")
class SparseArtifactDownload(unittest.TestCase):
    def test_zero_blocks_are_sparse_and_corrupt_archives_are_not_published(self):
        data = b"begin" + bytes(8 * 1024 * 1024) + b"end"
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as writer:
            writer.writestr("nested/payload.bin", data)
            # A real cohort has more than 1,300 entries. Its central directory
            # is larger than a pipe buffer and must be included in the digest.
            for i in range(1400):
                writer.writestr(f"sidecars/{i:04d}-" + "x" * 180, b"sidecar")
            writer.writestr("tail.bin", bytes(512 * 1024), zipfile.ZIP_STORED)
            writer.comment = b"original comment" * 4000
        original = archive.getvalue()
        self.assertGreater(len(original), 1024 * 1024)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload = root / "download.zip"
            payload.write_bytes(original)
            mock_gh = root / "gh"
            mock_gh.write_text(
                '#!/bin/sh\ncase "$2" in\n'
                '  */zip) cat "$TEST_ARCHIVE"; exit "${TEST_DOWNLOAD_EXIT:-0}" ;;\n'
                '  *) printf "%s" "$TEST_LISTING" ;;\nesac\n'
            )
            mock_gh.chmod(0o700)
            listing = {"artifacts": [{
                "name": "outputs-host", "id": 42, "expired": False,
                "digest": "sha256:" + hashlib.sha256(original).hexdigest(),
            }]}
            env = {
                "PATH": str(root) + os.pathsep + os.environ["PATH"],
                "GITHUB_REPOSITORY": "example/project", "GITHUB_RUN_ID": "123",
                "TEST_ARCHIVE": str(payload), "TEST_LISTING": json.dumps(listing),
            }
            with patch.dict(os.environ, env):
                target = root / "verified"
                downloader.download("outputs-host", target)
                extracted = target / "nested/payload.bin"
                self.assertEqual(extracted.read_bytes(), data)
                self.assertLess(extracted.stat().st_blocks * 512, len(data) // 4)
                # The ZIP is still structurally valid; only full-archive digest
                # validation detects an altered comment outside the file data.
                with zipfile.ZipFile(payload, "a") as writer:
                    writer.comment = b"changed in transit"
                with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                    downloader.download("outputs-host", root / "corrupt")
                self.assertFalse((root / "corrupt").exists())
                payload.write_bytes(original)
                with patch.dict(os.environ, {"TEST_DOWNLOAD_EXIT": "1"}):
                    with self.assertRaisesRegex(ValueError, "download failed"):
                        downloader.download("outputs-host", root / "interrupted")
                self.assertFalse((root / "interrupted").exists())
                self.assertEqual(list(root.glob(".artifact-*")), [])
                with self.assertRaisesRegex(ValueError, "already exists"):
                    downloader.download("outputs-host", target)


if __name__ == "__main__":
    unittest.main()
