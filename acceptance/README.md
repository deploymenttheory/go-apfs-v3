# Acceptance tests

Acceptance establishes interoperability with independent macOS observations.
Reading an image with the same code that wrote it cannot establish this. No v2
tests or harness helpers are reused.

## Volume inspection

Purpose: identify filesystem and volume accurately before a forensic, packaging,
or codesigning consumer selects what to operate on.

| Cases | Native expectation | Portable operation | What passes prove |
| --- | --- | --- | --- |
| APFS, case-sensitive APFS, HFS+, HFSX | `diskutil info -plist` on Apple-created images | `diskimage.Open` and `inspect.Image` | Name, case policy, geometry, APFS UUID match; source bytes unchanged |

The recipe creates ordinary files, directories and a symlink but this scenario
asserts volume properties. The separate file-reading family asserts their semantics.

```sh
# All hosts: small retained fixtures, no native tools.
go test -v ./acceptance

# macOS only; the output directory must not exist.
python3 acceptance/native/capture.py --expected-major 27 --output artifacts/native/macos-27

# Replay a single corpus or a directory containing several producers.
APFS_NATIVE_CORPUS=../artifacts/native go test -v ./acceptance
```

The collector uses only Python's standard library and Apple tools. It never
invokes v3. Images are detached before completion is published. Commands have
two-minute deadlines and diagnostics are retained beside the intended corpus
even on failure. An interrupted or partial capture cannot pass as complete.

`manifest.json` binds image, raw observation, and recipe hashes to the actual
OS version/build/architecture. Replay requires all four cases and rejects
missing files, unsafe filenames, duplicates, unexpected profiles, and mismatched
digests. A fresh capture never automatically replaces a retained baseline.

## File reading

Purpose: give packaging and forensic consumers the same names, file bytes, forks
and logical metadata that macOS reports, without mounting on the consumer host.

| Cases in each of APFS, case-sensitive APFS, HFS+, HFSX | Independent native expectation | Portable assertions |
| --- | --- | --- |
| Directory with 96 children, nested paths and Unicode | Final read-only mount enumeration and `lstat` | Exact child sets, names and object IDs; traversal across B-tree nodes |
| Empty, binary and sparse files | Native reads and SHA-256 | Logical size and complete byte hash |
| Relative and dangling symlinks | `readlink` and `lstat` | Exact target and logical size, without following links |
| Permissions, ownership, hidden flag and timestamps | `lstat` | Native mode/UID/GID/flags, birth seconds, access/modify/change nanoseconds |
| Empty/binary/32 KiB attributes and resource fork | Native `listxattr`/`getxattr` | Every native-visible value's presence, size and complete hash |

The native helper calls Darwin's public xattr APIs through Python `ctypes` because
macOS Python does not expose `os.getxattr`. It remains independent of the Go reader.
Filesystem-owned attributes may be additionally exposed by the Go API. Directory
synthetic sizes/link counts are not compared. These fixtures do not qualify hard
links, compression, encryption or name collation.

```sh
python3 acceptance/native/capture.py --expected-major 27 --scenario file-reading --output artifacts/files/macos-27
APFS_NATIVE_FILES=../artifacts/files go test -v -run TestNativeFileReading ./acceptance
```

Environment paths above are relative to the acceptance package's working directory.
Use absolute paths for a corpus elsewhere. Default `go test ./...` replays both
small retained families without native tools. A missing family fails the suite.

## CI tiers

- PR: all unit checks, lint, six cross-builds, retained-corpus replay on Linux,
  Windows, and macOS, and relevant native qualification for reader changes.
- Nightly/manual: fresh macOS 15/26/27 producers and Linux/Windows replay of
  all three profiles. Future crash, mount, scale, and extended fuzz families
  belong here as their implementations arrive.
- Release: qualify the exact candidate revision before publishing. Current
  workflows do not claim unimplemented features are qualified.

Unit tests isolate bounds, checksums, short reads, concurrency, and corruption.
Fuzz targets exercise parser entry points. Coverage is diagnostic. Every new
scenario must explain its value and independent expected result as plainly as
the table above.
