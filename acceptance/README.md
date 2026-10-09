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
Use absolute paths for a corpus elsewhere. Default `go test ./...` replays all
four retained families without native tools. A missing family fails the suite.

## File semantics

Purpose: resolve the same application paths and file relationships as macOS,
including files whose content is fragmented beyond HFS+'s eight inline extents.

| Cases in each filesystem variant | Independent native expectation | Portable assertions |
| --- | --- | --- |
| 15 named comparison cases: case, canonical decomposition, combining order, Hangul, ligatures, ignorables and Unicode 11/14/16 boundaries | `lstat` of original and alternate spellings on the final read-only mount | Matching inode or `fs.ErrNotExist` for every query; enumeration retains original spelling |
| Three aliases, a removed fourth link, modification through an alias | `lstat`, native reads, xattrs and resource fork | Shared inode ID and link count, all data/fork bytes and metadata agree |
| HFS+/HFSX data and resource forks in deliberately fragmented free space | Darwin `F_LOG2PHYS_EXT`, full native reads and boundary samples | More than eight native extents required; full hash and reverse-order reads crossing every boundary match |

The fragmentation recipe fills only its temporary 64 MiB fixture volume and
releases alternating allocations. Capture fails unless Darwin proves the
resulting forks require overflow records. The retained macOS 27 forks have
20 and 21 extents. Neither a guessed allocation layout nor Go's own interpretation
is accepted as proof. A fresh capture never replaces the retained observations.

The same file comparison used by file-reading checks content, identity, metadata,
forks and attributes. Additional assertions are confined to this scenario, so
the purpose and native preconditions remain visible. The family does not qualify
directory hard links, historical APFS comparison profiles, fragmented metadata,
attribute continuations, compression or encryption.

```sh
python3 acceptance/native/capture.py --expected-major 27 --scenario file-semantics --output artifacts/semantics/macos-27
APFS_NATIVE_SEMANTICS=../artifacts/semantics go test -v -run TestNativeFileSemantics ./acceptance
```

CI captures all four families on macOS 15/26/27. Each Linux, Windows and macOS
consumer must replay every producer; `APFS_REQUIRED_NATIVE_MAJORS` prevents a
missing corpus from passing as a skipped profile.

## File compression

Purpose: read compressed application contents identically on portable hosts,
while preserving the original storage and metadata for forensic consumers.

| Cases in each filesystem variant | Independent native expectation | Portable assertions |
| --- | --- | --- |
| decmpfs types 1, 3, 4, 7–16 | `ditto` for native LZVN; Apple buffer codecs for other payloads; final read-only kernel reads | Logical sizes, full hashes and compression type; same metadata/attribute comparisons as file-reading |
| Attribute and resource-fork storage, mixed stored/compressed blocks, partial final block | Apple codec readback of final stored bytes, plus kernel readback | Full contents and reverse-order samples crossing 64 KiB boundaries |
| Stored markers, empty type 1, zlib with/without Adler-32, resource descriptor gaps | Native mounted reads | Correct marker, checksum and explicit block-length interpretation |
| Hard-link aliases, independent resource fork beside inline compression, ordinary xattr and mode | Native inode/link count, xattrs and `lstat` | Identity and metadata preserved; raw stored data fork remains separately accessible |
| Inactive valid/malformed decmpfs attributes | Ordinary native file reads | Compression flag selects the source; stale storage never overrides data |
| Malformed active LZFSE marker | Native logical size with premature EOF, EIO or EINVAL; raw attribute retained | Explicit corruption instead of invented or empty successful contents |

The focused `native/file_compression.py` helper installs format storage using
Apple-produced payloads and then decodes the final stored bytes again using the
public Apple codecs. Native kernel readback is compared independently. macOS
15/26 can lack filesystem registration for LZ4 types 15/16 while exposing the
public LZ4 codec. Those cases record the kernel's EIO and compare Go with the
native codec result; they are never labeled successful kernel reads or skipped.
macOS 27 requires kernel readback for all admitted types. Both producer sources
are hashed in the manifest. The retained corpus contains 27 ordinary observed
objects and one separate malformed control per filesystem.

```sh
python3 acceptance/native/capture.py --expected-major 27 --scenario file-compression --output artifacts/compression/macos-27
APFS_NATIVE_COMPRESSION=../artifacts/compression go test -v -run TestNativeFileCompression ./acceptance
```

This family qualifies reading. Compression writing, generation-store/dataless
content and arbitrary damaged-file recovery remain outside it. Focused unit
checks exercise malformed lengths/indexes, codec errors, close/cancellation,
concurrent boundary reads and a large logical file whose index must stay on disk.

## Encrypted APFS reading

| Scenario | Independent macOS evidence | What the comparison proves |
| --- | --- | --- |
| Ordinary, Unicode, long and changed passwords | `newfs_apfs` via `hdiutil`, `diskutil` unlock/change results | Correct credentials unlock the final image; wrong and replaced credentials fail |
| Locked inspection and read-only unlocking | Locked/unlocked `diskutil` plists, unchanged image hashes | Inspection needs no credentials; reading does; neither changes source bytes |
| 108 objects per image, including modified clones | Native final mount with ownership enabled | Encrypted metadata, extent-specific tweaks, data, sparse ranges, links, attributes and resource forks agree |
| Native `ditto` compression inside encrypted storage | Native logical reads and metadata | Decryption feeds the same compression reader correctly |
| PBKDF2, AES key unwrap, AES-128/256-XTS | Apple CommonCrypto output and damaged-key rejection | Primitive bytes agree independently of filesystem roundtrips |

`native/file_encryption.py` uses only disposable attached image devices. Its
passwords and cryptographic vector keys are public fixture values. Native
`diskutil` refuses empty credentials; these are rejection controls, not proof
about volumes formatted with an empty password. Unicode passwords are established
through `diskutil changePassphrase`. Native mounts explicitly enable ownership
so the kernel does not replace stored UID/GID values with the mounting user's IDs.

The native volume profile uses AES-256 key wrapping and AES-128-XTS sectors.
CommonCrypto AES-256-XTS vectors qualify the primitive, not a native volume
profile. Hardware/per-file keys, legacy key records, encrypted DMG envelopes,
encryption creation/modification by Go and recovery keys remain unqualified.
Unit tests additionally check damaged authenticated metadata, key-record HMAC,
DER bounds, iteration limits, cancellation, unaligned/concurrent reads, and key
lifetime across independent unlocks, inline attributes and decoded caches.

```sh
python3 acceptance/native/capture.py --expected-major 27 --scenario file-encryption --output artifacts/encryption/macos-27
APFS_NATIVE_ENCRYPTION=../artifacts/encryption go test -v -run TestNativeEncryptedReading ./acceptance
```

## CI tiers

The **macOS filesystem compatibility** workflow has two visible stages:

1. **Record Apple filesystem reference data (macOS 15/26/27)** creates disk
   images with Apple tools and records how macOS reads them. Separate steps show
   volume identity; file contents, metadata and forks; names, links and
   fragmentation; compression; and encrypted APFS files and passwords. Its artifacts contain the images, observations
   and provenance needed to repeat a comparison.
2. **Compare Go with macOS reference data (Linux/Windows/macOS)** reads every
   reference image through Go and checks the results against all three macOS
   versions. Missing evidence or mismatched results fail the workflow.

This proves the covered Go operations agree with Apple's observed behavior on
portable hosts. Each job's summary explains its evidence and the comparison's
limits; compilation alone does not establish filesystem compatibility.

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
