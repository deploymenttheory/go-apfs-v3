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
DiskImages can transiently report `EBUSY` when detaching a disposable image.
Only that cleanup command retries, at most six attempts one second apart;
every result stays in the transcript. Other errors fail immediately.

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
retained families without native tools. A missing family fails the suite.

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

CI captures all eleven families on macOS 15/26/27. Each Linux, Windows and macOS
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
profile. Hardware/per-file keys, legacy APFS key records, encryption creation
and modification by Go, and recovery keys remain unqualified. Encrypted DMG
reading has its own family below.
Unit tests additionally check damaged authenticated metadata, key-record HMAC,
DER bounds, iteration limits, cancellation, unaligned/concurrent reads, and key
lifetime across independent unlocks, inline attributes and decoded caches.

```sh
python3 acceptance/native/capture.py --expected-major 27 --scenario file-encryption --output artifacts/encryption/macos-27
APFS_NATIVE_ENCRYPTION=../artifacts/encryption go test -v -run TestNativeEncryptedReading ./acceptance
```

## Encrypted DMG reading

| Scenario | Independent macOS evidence | What the comparison proves |
| --- | --- | --- |
| AES-128/256 envelopes around APFS and HFS+/HFSX | `hdiutil` creates encrypted images and reports the cipher | Both cipher sizes feed the existing filesystem readers correctly |
| UDZO and raw UDRW images | Native image format and read-only mount | Decryption composes with UDIF decoding and also exposes raw logical disks |
| Unicode, wrong, empty and changed passwords | Native `imageinfo` credential acceptance/rejection | The current password unlocks; rejected and old credentials do not |
| Independently encrypted APFS inside a DMG | APFS stays locked after image unlock and rejects the image password | Image and volume credentials and lifetimes remain separate |
| 107 objects per image | Final native reads, xattrs, resource forks, compression, links and metadata | Complete logical results match across hosts; source hashes remain unchanged |

`native/disk_image_encryption.py` records native imageinfo and diskutil plists,
file observations and the command transcript. The raw HFS+ case is an 8 MiB
image to keep retained evidence bounded; the other cases are compressed DMGs.
Opening and closing a borrowed Go view is also checked to preserve its source
and invalidate cached partition reads. Structural units cover header/record
bounds, overlapping credentials, aggregate derivation limits and block/EOF
behavior. A separate fuzz target exercises envelope admission without spending
unbounded time trying passwords.

This family qualifies version 2 password-based reading. Image creation by Go,
version 1, certificate/keybag-only unlocking and arbitrary damaged-image recovery
remain outside it. The native format's CBC and key-cookie checks are not data
authentication; source preservation and observed contents are separate assertions.

```sh
python3 acceptance/native/capture.py --expected-major 27 --scenario disk-image-encryption --output artifacts/encrypted-dmg/macos-27
APFS_NATIVE_ENCRYPTED_DMG=../artifacts/encrypted-dmg go test -v -run TestNativeEncryptedDiskImages ./acceptance
```

## CI tiers

The **macOS filesystem compatibility** workflow has three visible stages:

1. **Record Apple filesystem reference data (macOS 15/26/27)** creates disk
   images with Apple tools and records how macOS reads them. Separate steps show
   volume identity; file contents, metadata and forks; names, links and
   fragmentation; compression; encrypted APFS files and passwords; and encrypted
   DMG files. Its artifacts contain the images, observations
   and provenance needed to repeat a comparison.
2. **Compare Go with macOS reference data (Linux/Windows/macOS)** reads every
   reference image through Go and checks the results against all three macOS
   versions. Missing evidence or mismatched results fail the workflow.
3. **Verify Linux, Windows and macOS outputs with Apple tools (macOS 15/26/27)**
   independently compares returned workspaces against native observations and
   exercises AppleDouble unpacking. This stage invokes no Go verifier.

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

## APFS snapshots

Purpose: let forensic and packaging consumers read a selected historical state
without mixing its files with the live filesystem.

| Cases | Independent native expectation | Portable assertions |
| --- | --- | --- |
| APFS, case-sensitive APFS, encrypted APFS inside AES-256 DMG | Two retained snapshots and the later live state, observed from final read-only mounts | Exact snapshot names/XIDs/UUIDs/timestamps and the common file/metadata/fork comparison for all three states |
| Modified hard link, clone, sparse ranges, attributes, resource fork, permissions; renamed/deleted/recreated files | Native reads, `lstat`, xattrs and positive/negative lookups in each historical mount | Historical bytes, identities, metadata and lookup results match; interleaved values do not mix states |
| Empty inventory and a created then deleted snapshot | Native inventory before creation and after deletion | Missing/deleted selections fail without live fallback |
| Borrowed encryption keys and damaged historical metadata | Independently unlocked native source; corruption only in test overlays | Closing an unlock invalidates its snapshot values/caches; independent unlocks survive; corruption returns no reader |

`native/snapshot_reading.py` retains snapshots created by Apple's `asr` during
replication to a disposable target. It observes the child's snapshot through
`fs_snapshot_list`, pauses only that child, mounts the snapshot, then resumes
and requires the copy to finish successfully. Mounting pins the snapshot against
ASR cleanup; capture verifies it still exists after unmounting. The temporary
target is discarded. A 16 MiB allocated, compressible file outside `Fixture`
gives the observer time to mount; it supplies no expected filesystem results.
All subprocesses have deadlines and a missed snapshot fails capture.

This workflow needs no custom entitlement or host security changes. It uses
Apple's actual snapshot names rather than invented recipe names. Snapshot UUIDs
come from `diskutil`; timestamps come from native attribute enumeration. Unicode
snapshot names and non-leaf snapshot metadata trees are not yet natively qualified.
The filesystem trees within the snapshots do span multiple nodes.

macOS may reuse an unlock when reattaching after ASR. Capture explicitly locks
such a volume, records that locked state, requires rejection of the DMG password
as an APFS password, then unlocks with the separate APFS credential. Portable
replay also requires that opening the DMG alone leaves APFS inaccessible.
`diskutil verifyVolume` and `hdiutil verify` must pass; image hashes must remain
unchanged by the final native and portable reads.

```sh
python3 acceptance/native/capture.py --expected-major 27 --scenario snapshot-reading --output artifacts/snapshots/macos-27
APFS_NATIVE_SNAPSHOTS=../artifacts/snapshots go test -v -run TestNativeSnapshotReading ./acceptance
```

Retained macOS 27 snapshot replay takes under one second locally; the complete
retained acceptance suite takes approximately four seconds. The CI gate
requires fresh macOS 15/26/27 reference captures and each Linux/Windows/macOS
consumer to replay all three. Snapshot creation/deletion/revert by Go, sealed
system verification, dataless snapshots and arbitrary checkpoint recovery remain
outside this family.

The snapshot collector retries `ENOENT` only while polling for ASR's new
snapshot, under its existing 30-second deadline. Its result records the retry
count. Busy creation of an ASR target gets at most three attempts, each at a new
disposable path, with every command retained in diagnostics. Final snapshot
inventories, successful native copy completion and retained-content checks stay
strict. These bounds address transient native failures observed during PR #18.

## Preservation-aware extraction

Purpose: retain a macOS tree on Linux or Windows without making host filenames,
permissions, symlinks or extended-attribute support a source of silent loss.

| Scenario | Independent native reference | Portable and native return checks |
| --- | --- | --- |
| 125–126 entries in APFS, case-sensitive APFS, HFS+, HFSX | Final read-only enumeration, `lstat`, reads and raw `XATTR_SHOWCOMPRESSION` values | Reopened workspace matches names, identities, metadata, logical bytes and raw attributes |
| Windows device names, colon/backslash, newline, long/Unicode names and case pairs | Original names and distinct file hashes | Portable mapping has no collisions; original spelling survives reopening |
| Ordinary `._` content, relative/absolute/dangling links, two hard-link aliases | Native file bytes, link targets, inode and link counts | Ordinary data stays ordinary; target records cannot redirect extraction; aliases retain logical identity |
| Native `ditto --hfsCompression --noclone` storage | Native logical reads and compression-owned xattrs | Logical and raw forks remain separate; compressed metadata is retained |
| AppleDouble ordinary attributes, empty/binary/large values, FinderInfo and resource fork | Apple's `COPYFILE_PACK`, plus native `COPYFILE_UNPACK` control results | Every host decodes/encodes; Apple unpacks the resulting files and compares all resulting attributes |

The collector never invokes Go. It hashes its own sources and all observations.
Default portable tests replay retained macOS 27 evidence. CI captures all three
macOS versions and extracts each corpus on Linux, Windows and macOS. Each Mac
then verifies all 36 actual workspace outputs using Python against native
observations, and performs 108 native AppleDouble unpack comparisons. The return
verifier never calls Go. Hidden ordinary files must be included in artifacts.
Host links/permissions can be lost in archive transport: the checked manifest
preserves logical relationships and metadata independently.

A small composition check also extracts a historical generation file from each
snapshot profile, including nested encryption, and verifies its native metadata,
content and view. This avoids multiplying the large extraction fixture by every
reader profile. Focused unit tests cover source traversal/errors, incomplete
publication, limits/cancellation, damaged blobs, external edits and symlink
substitution. AppleDouble parser tests and fuzzing check malformed ranges,
overlap, empty/duplicate records, output limits and I/O failures.

```sh
python3 acceptance/native/capture.py --expected-major 27 --scenario preservation --output artifacts/native/preservation/macos-27
APFS_NATIVE_PRESERVATION=../artifacts/native/preservation APFS_WORKSPACE_OUTPUT=../artifacts/outputs/preservation-macOS go test -v -run TestNativePreservation ./acceptance
python3 acceptance/native/verify_preservation.py --expected-major 27 --corpus artifacts/native/preservation --outputs artifacts/outputs --producers 27 --consumers macOS
```

Outputs require a new directory; use a fresh output path for another run. The
retained local extraction comparison takes about nine seconds; native readback
of its four workspaces and 12 AppleDouble controls takes less than one second.
This qualifies capture/readback and serialized metadata, not host metadata
application, app-bundle execution, workspace editing or filesystem rebuilding.

## Content replacement

Purpose: replace an existing macOS file's data on a portable host while retaining
its other information and all hard-link aliases. Native capture creates 14 entries
per filesystem profile, saves a before image, performs seven real truncate/write
operations on the original inodes, then captures a final read-only after image.

| Operation | Native evidence | Portable assertion |
| --- | --- | --- |
| Write through an ordinary hard-link alias | Same inode/link count and new contents at all three paths | Every alias receives identical bytes; metadata and independent resource fork remain intact |
| Replace inline zlib contents with an independent resource fork | Native data and raw xattrs before/after | Compression flag/attribute removed; independent resource bytes retained |
| Truncate resource-backed zlib through a linked inode to empty; replace native ditto LZVN | Native flags, fork/attribute absence, empty/short data | Compression-owned storage disappears; logical/raw data both contain the replacement |
| Grow an empty file and replace `CON` using its original name | Native final file hashes | Empty values and mapped host names work without changing source names |
| Replace a file with inactive malformed decmpfs metadata | Native ordinary writes and unchanged opaque xattrs | Inactive bytes never become compression authority |
| Leave other entries untouched | Native before/after observations | Original objects, attributes, raw data and symlinks remain unchanged |

The portable preservation operation retains source timestamps. Native after-write
times are captured but the timestamp assertion uses the original native values;
the remaining replacement outcomes use the actual after observation. This is an
explicit logical metadata policy, not a claim to emulate a kernel write clock.
The changed nodes are marked and their source manifest hash is retained. Native
before/after capture never invokes Go. The shared compression fixture helpers are
included and hashed alongside the scenario's own source.

Each consumer uploads its actual before/after workspaces. On each required Mac,
`verify_replacement.py` independently verifies 36 pairs, 504 final entries and
252 content replacements against native observations. Missing cases, extra/lost
entries, changed original values, surviving compression storage or missing
provenance fail the gate. The existing AppleDouble native-unpack gate also remains
required. No synthetic Go roundtrip supplies the expected replacement semantics.

```sh
python3 acceptance/native/capture.py --expected-major 27 --scenario content-replacement --output artifacts/native/replacement/macos-27
APFS_NATIVE_REPLACEMENT=../artifacts/native/replacement APFS_REPLACEMENT_OUTPUT=../artifacts/outputs/replacement-macOS go test -v -run TestNativeContentReplacement ./acceptance
python3 acceptance/native/verify_replacement.py --expected-major 27 --corpus artifacts/native/replacement --outputs artifacts/outputs --producers 27 --consumers macOS
```

Use a fresh destination for each run. Retained local comparison takes about two
seconds. Focused failure controls cover borrowed source ownership, short reads,
source errors, mid-copy cancellation, inconsistent data between reads, limits,
duplicate identities, unknown compression profiles and destinations inside the
baseline, including symlink aliases. General external import,
native authorization and crash-durable transactions retain separate scope.


## Ordered tree edits

Purpose: make application structure changes on a portable host while preserving
untouched source objects. The native family starts with 18 entries per filesystem
and records 18 successful operations, eight rejected operations and six name
boundary probes. Final read-only mounts contain 21 entries. Creation metadata and
attributes, including any native process provenance, are explicit supplied values.
The Go implementation must never manufacture those values from its host.

| Native case | Value of the comparison |
| --- | --- |
| Create a signature directory, files, Unicode resource and symlink | Exact stored names, supplied metadata/attributes and target bytes; created objects have distinct provenance |
| Link both source and newly created files | Same native object relationships and final counts at every alias |
| Case-only rename; move a populated directory | Correct native comparison and preserved object identity/contents/forks |
| Replace an existing file that has another alias | The displaced object survives under its other name with its original bytes and reduced link count |
| Rename between two aliases of one inode | Both names survive the native no-op |
| Replace an empty directory; remove entries | Correct final namespace, with nonempty removal and descendant moves rejected |
| Move and then replace a compressed file | Content replacement composes with tree changes and retains compression cleanup rules |
| ASCII, accented BMP and supplementary-plane name lengths | Native 255 UTF-16-unit limits, applied after HFS+ decomposition |

Existing timestamps are compared with the original native observation. Created
objects retain the metadata supplied immediately after native creation; subsequent
native clock changes remain evidence, not portable timestamp defaults. New-object
IDs are compared by path and a bijection of native hard-link groups, never by
expecting independent object allocators to choose the same inode numbers.

```sh
python3 acceptance/native/capture.py --expected-major 27 --scenario tree-edits --output artifacts/native/tree-edits/macos-27
APFS_NATIVE_TREE_EDITS=../artifacts/native/tree-edits APFS_TREE_EDIT_OUTPUT=../artifacts/outputs/tree-edits-macOS go test -v -run TestNativeTreeEdits ./acceptance
python3 acceptance/native/verify_tree_edits.py --expected-major 27 --corpus artifacts/native/tree-edits --outputs artifacts/outputs --producers 27 --consumers macOS
```

Use fresh output directories. Local retained comparison takes about three seconds.
Each required native verifier checks 36 actual before/after workspace pairs, 756
final entries and 648 successful native operations across every producer/consumer
pair. It invokes no Go code. Existing native-output verification remains required.
Focused tests cover failure before publication, borrowed sources, creation identity
across subsequent edits, aliases outside extracted subtrees and deterministic output.

Workspace outputs are transported as tar archives inside CI artifacts. Directory
uploads alone omit empty directories, which would lose part of the captured tree.
Each Mac unpacks the complete original/edited trees before independent verification;
missing empty directories fail exactly like missing nonempty directories. This
transport applies to preservation, replacement, tree-edit and metadata-edit outputs alike.

On macOS, archive creation disables native metadata packing with
`--no-mac-metadata --no-xattrs --no-acls`. Extraction also passes
`--options '!mac-ext'`: libarchive otherwise interprets genuine `._` files as
AppleDouble companions even when metadata application is disabled. Their bytes
remain ordinary content; metadata stays in the workspace manifest and blobs.

## Metadata, attributes and resource-fork edits

Purpose: prepare application metadata on Linux/Windows while retaining source
provenance and all unspecified values. One family checks 29 native operations and
seven rejection controls per filesystem, from 16 initial to 17 final entries.

| Native case | What the comparison proves |
| --- | --- |
| File, directory and symlink mode changes; root metadata | Correct native values and no symlink traversal |
| UID/GID reassignment on CI | Supplied ownership is recorded independently of the portable host account |
| Explicit birth/modification/access timestamps | Exact APFS nanoseconds and HFS+ seconds; precise native birth observation uses `getattrlist` |
| Create-only, replace-only, empty, binary and 127-byte-name attributes | Correct presence, bytes and conditions; absent replace/remove and oversized names reject |
| FinderInfo on files, directories and symlinks; zeroing and removal | Format-specific masking, disappearance and hidden-flag relationships |
| Large fork replaced by shorter data, then empty/remove controls | Complete replacement cannot leave an old tail; empty public forks are absent |
| Metadata through aliases and after rename | Object identity is shared and changes compose in order |
| Replace compressed contents, then supply a fork; metadata on another compressed file | Compression-owned storage remains protected while unrelated edits retain raw bytes |

Inputs, native operation identities/effects and before/after observations are
retained separately. The final read-only native mount supplies expected values.
Unspecified timestamps use the native before observation under the workspace
preservation policy. Actual native ctimes remain recorded and are never treated
as a portable host-clock default. Writable resource-fork observations can update
HFS+ atime, so explicit timestamps are assigned after those observations.

```sh
python3 acceptance/native/capture.py --expected-major 27 --scenario metadata-edits --output artifacts/native/metadata-edits/macos-27
APFS_NATIVE_METADATA_EDITS=../artifacts/native/metadata-edits APFS_METADATA_EDIT_OUTPUT=../artifacts/outputs/metadata-edits-macOS go test -v -run TestNativeMetadataEdits ./acceptance
python3 acceptance/native/verify_metadata_edits.py --expected-major 27 --corpus artifacts/native/metadata-edits --outputs artifacts/outputs --producers 27 --consumers macOS
```

Use new output directories. Capture uses passwordless sudo when available to set
UID/GID 60001/60002 on one disposable image file per profile. Without it, the
collector explicitly records `same-owner-local`. The retained macOS 27 corpus
uses that narrower local case. For its independent local verification, append
`--allow-same-owner`. The required CI matrix rejects same-owner evidence and
requires actual reassignment on every macOS version; this option is never passed
there. The portable API records values without emulating native authorization.

The focused retained replay takes approximately two seconds. Each native verifier
checks 36 returned workspace pairs, 612 final entries and 1044 successful native
operations, complete attribute inventories including removals, raw/logical hashes,
link identities, all unchanged metadata, source identity and changed-field records.
It invokes no Go code. Outputs use the same complete-tree archive transport as the
other editing families. Parser, cancellation, failed source, unsupported ownership,
source-preservation and provenance controls remain focused unit tests.

## File-command sessions

`file-commands` qualifies the ordinary command interface over persistent scratch.
Each APFS, case-sensitive APFS, HFS+ and HFSX case captures 17 original entries,
23 Apple operations, five rejection controls and 31 final entries. The journey
copies an application bundle, imports host payloads, applies symbolic/recursive
permissions, links, ownership, BSD flags, timestamps, attributes and resource
forks, and removes a directory tree. Apple libc supplies 390 independent
`setmode/getmode` vectors per profile.

```sh
python3 acceptance/native/capture.py --expected-major 27 --scenario file-commands --output artifacts/native/file-commands/macos-27
APFS_NATIVE_COMMANDS=../artifacts/native/file-commands APFS_COMMAND_OUTPUT=../artifacts/file-commands go test -v ./acceptance -run '^TestNativeFileCommands$'
```

The replay starts a session from the before image and invokes each operation in a
separate CLI process. Rejected commands must leave its revision byte-identical.
Exports before/after return to all three Macs; `verify_file_commands.py` checks
names, metadata, data, raw attributes/forks, hard-link groups, logical identities
and portable projections independently of Go. The existing workflow requires all
three native producers and all Linux/Windows/macOS consumers.

Native command mounts explicitly use `noatime`; observation uses lstat against a
fixed path inventory, avoiding observer-created access-time effects. Recorded
runtime clock intervals map to the fixed session clock at the target filesystem's
precision. Historical explicit assignments remain exact. Native compression
storage on a new copy may differ from the session's logical uncompressed copy.
Runner-injected `com.apple.provenance` on newly created objects remains in native
evidence and is excluded only where no copied source supplied it. Copied security
metadata is still checked byte-for-byte. See [the contract](../docs/sessions.md).

Required captures change UID/GID to 60001/60002 with sudo on disposable volumes.
The retained macOS 15 CI corpus supplies actual ownership changes, including
physical symlinks during recursive chown. The retained local macOS 27 reference
records same-owner assignment because this
account lacks passwordless sudo. Independent local readback accepts
`--allow-same-owner` only with one local producer and macOS consumer; that option
cannot bypass the required release matrix. Process-interruption, hash corruption,
lock conflicts, bounds, symlink traversal and metadata-only content reuse have
separate focused unit controls.

## Image building

Purpose: prove Linux/Windows can produce DMGs that macOS accepts without losing
application contents, metadata, forks, aliases or existing signatures.

| Native inputs | Portable operation | Independent native verdict |
| --- | --- | --- |
| APFS, case-sensitive APFS, HFS+/HFSX, deep trees, ordinary/compressed data, attributes/forks, hard links, signed universal app | Capture session; build UDRO and UDZO twice with fixed clock | `hdiutil verify`, `fsck_apfs -n` or `fsck_hfs -fn`, exact mounted readback, link bijection and `codesign --verify --deep --strict` |
| APFS exact nanosecond times, tracked documents and native name equivalences/distinctions | Preserve metadata and construct hashed directory records | Native `getattrlist`, 53 positive/negative lookups per profile |
| Independently observed empty APFS directory | Build an empty 64 MiB container twice | Native empty root, attributes, timestamps and filesystem checks |
| Three APFS volumes with mixed case policy, reserve, quota and empty root | Build a shared container in both encodings | Exact native inventory/files, bounded quota/reserve pressure, protected allocation and reuse |
| Native System/Data group | Preserve group UUID, roles, membership and System inode namespace | Native group inventory, exact files/signatures, independent writes to both members, fsck and remount |
| Every constructed APFS output | Return unchanged image to every Mac | Native writes on a shadow: growth, links, rename, deletion, tree growth and reuse; fsck without repair, remount/readback and source hash unchanged |

`go test -run 'TestNative(ImageBuilding|ContainerBuilding)$' -v ./acceptance` replays the retained macOS
27 corpus. Capture with `--scenario image-building`; `APFS_NATIVE_IMAGE_BUILDING`
selects another corpus and `APFS_IMAGE_BUILDING_OUTPUT` retains constructed DMGs.
`verify_image_building.py` accepts the corpus/output roots and expected verifier
macOS major, following the other independent verification scripts. CI requires
all four filesystem profiles and both encodings from every producer/consumer combination,
compares output hashes across hosts and retains failure diagnostics. Native source
images and observations are immutable; a writer mismatch is fixed in Go. Each Mac
requires all 117 built DMGs to agree in triples across portable hosts, then checks
the 39 distinct byte sequences, including 27 native APFS allocation journeys.
Hash comparison precedes native verification, so identical output is mounted once
per verifier OS. The two container cases add approximately five seconds to local
Go replay. Their separately manifested references live in `macos-27/containers`;
older single-volume observations and source provenance remain unchanged.
The original HFS-only capture is retained under `testdata/image-building/history`;
its files and expectations were not rewritten for APFS construction.

Native image-building capture and verification require GitHub-hosted VMs, or
`APFS_NATIVE_DISPOSABLE_VM=1` explicitly set inside another isolated disposable VM.
Normal local invocation is refused. The [kernel-panic incident](../docs/native-testing-incident.md)
shows why a shadow is insufficient isolation and why both native allocation and
independent namespace assertions belong in this gate. Go replay remains portable
and never invokes native image tools.

## Sector-preserving image repacking

Purpose: prove an image conversion retains **every decoded disk sector**, including
partition tables, unused bytes, APFS snapshots and encrypted volume data. This is
separate from logical tree rebuilding in `image-building`.

`native/image_repacking.py` reuses the signed HFS+ and APFS snapshot references
already captured in the same workflow. Apple tools additionally create a bare
HFS+ volume, an HFSX APM disk with an explicit free partition and seeded unused
sector, and a 1100 MiB APFS container with an encrypted and an ordinary volume.
The larger container admits two native volumes; its retained encoded file is
small. Raw, UDRO, UDZO and UDBZ input profiles remain distinct. Apple-attached raw
devices supply complete disk SHA-256 values. Native filesystem APIs record files,
raw attributes/forks, identities and snapshot history; Apple verifies signatures.
Native signed DMGs and encrypted DMGs without credentials supply refusal controls.

`TestNativeImageRepacking` checks provenance, required producers/profiles and
refusal outcomes. It builds UDRO and UDZO twice, compares native whole-disk hashes,
checks deterministic output and leaves source hashes unchanged. Raw input is
retained gzip-compressed solely to keep the repository small and is expanded to
a test temporary directory before invoking the production API. Production
repacking does not need raw scratch.

`native/verify_image_repacking.py` independently verifies every host output on
macOS 15, 26 and 27: `hdiutil verify`, whole raw-device hashes, native partition and
volume inventories, filesystem checks, exact mounted files/raw attributes,
snapshot historical contents, native APFS unlocking and signed-app verification.
All 90 plaintext outputs must agree in triples before each Mac checks the 30
distinct images. It
never invokes Go. Source references and diagnostics are retained with hashes.

```sh
python3 acceptance/native/image_repacking.py --expected-major 27 \
  --references acceptance/testdata --output /tmp/repacking/macos-27
APFS_NATIVE_REPACKING=/tmp/repacking APFS_REPACKING_OUTPUT=/tmp/repack-output \
  go test -v -run '^TestNativeImageRepacking$' ./acceptance
```

CI sets `APFS_REQUIRED_NATIVE_MAJORS=15,26,27`. Missing cases, negative controls,
producers or returned output images fail; unsupported input never counts as a
successful positive case. Corrupt CRCs, missing/overlapping runs, unknown resources,
publication refusal, streaming failure and cancellation also have focused unit
controls. Filesystem repair, damaged-image salvage and signing implementations
remain outside this family.

### Encrypted image output in the existing build/repack families

These are output checks, using the same capture/replay/readback workflow above.
They establish that Go-produced encrypted images are usable by Apple tools and
that changing or removing a DMG password preserves the complete disk.

| Case | Independent verdict | Value |
| --- | --- | --- |
| APFS, case-sensitive APFS, HFS+, HFSX and System/Data builds; AES-128/256 and UDRO/UDZO | Apple unlock, cipher report, wrong-password rejection, UDIF verification and complete device hash against the already qualified plaintext build | Every builder can publish a native-readable encrypted image |
| All five repacking disk profiles inside fresh encryption | Exact native decrypted device hash, including unused sectors, retained snapshots and opaque encrypted APFS sectors | Envelope encryption does not rebuild or lose filesystem state |
| Apple-encrypted signed-app image with a new password | New password unlocks, old password fails, full native disk hash stays equal | Password replacement preserves data and application signatures |
| Explicit decryption of the same source | Apple reports no image encryption; same complete native disk bytes | Removing encryption is an intentional output policy |
| Existing AES-256 UDRW source, decrypted and re-encrypted as AES-128 UDZO | Compare Apple's attached source device directly with the output devices | Raw and compressed encrypted sources use the same preservation contract |

There are 108 distinct randomized encrypted outputs and 18 additional decrypted
outputs across the three source versions and three portable hosts. Every Mac
checks every encrypted output; their hashes must differ across hosts while their
decrypted device hashes match. Decrypted outputs must agree across hosts. This
is a bounded selection of cipher/format/profile combinations, not a repeated
Cartesian product of all file cases. The native verifier never uses Go to derive
the final expected bytes. `native/encrypted_output.py` shares only encryption
readback between the existing two families, and `native/image_outputs.py` checks
host equality before running native verification once on identical bytes.

The same pure-Go acceptance tests run locally against retained Apple fixtures;
only hosted disposable VMs run the native output verifiers. Unit tests isolate
streaming boundaries, randomness, malformed headers, encrypted inner checksums
and signatures, credential policies, publication cleanup and interrupted output.

The portable acceptance families read immutable references and own separate
scratch/output paths. They can run concurrently; CI uses `-parallel 2` to bound
active families and memory. Race CI also uses `-p 1`, giving each package the
runner CPU budget instead of competing with other instrumented packages.
Each family retains its sequential scenario checks,
required inventories and before/after hashes. This scheduling applies only to
Go replay; native attachment and filesystem mutations remain sequential within
each disposable macOS job. The race timeout stays at five minutes.

For a native-verifier-only correction, dispatch the existing compatibility
workflow with `readback_run` set to a prior run whose three captures and three
portable replays succeeded. Each Mac validates that evidence and compares source
commits before downloading the archived references and outputs. Changes outside
native helpers, documentation and the two CI workflows require fresh capture and
replay. Missing artifacts or changed Go code/tests, fixtures or dependencies fail
this admission. Every native readback still runs on all three macOS versions.
Ordinary PR runs continue to capture and replay fresh data.


Transparent file-compression writing extends the existing `file-compression` and
`image-building` families. Native source inputs include empty/tiny files, attribute
capacity controls, exact 64 KiB boundaries, a multi-megabyte file, incompressible
and mixed blocks, inactive metadata, independent resource forks and hard links.
Older retained references remain immutable; fresh required CI captures must include
the complete new input inventory. Local codec/CLI/failure tests supplement those
references without invoking native tools.

Image-building replay emits `file-compression/zlib` and `file-compression/none`
outputs and diagnostic reports inside its existing output archives. Each policy
is built twice from each of the four filesystem profiles from each source Mac.
The 72 host outputs must agree in triples, then each verifier checks the 24 distinct
images with Apple's image/fsck tools, kernel reads, public compression codec,
metadata and signature checks. Compression-owned storage may change; independent
forks, inactive attributes and all ordinary metadata must remain exact. Required
controls independently prove actual attribute/resource compression, native stored
blocks and explicit refusal to replace unrelated fork/attribute storage.

Each policy output also receives native shadow-file writes, hard-link replacement,
independent-fork preservation and allocation/reuse, followed by unmounted fsck and
read-only remount verification. Source hashes must remain unchanged. This proves
continued native use without claiming Go existing-filesystem mutation or power-loss
durability. All native operations run on disposable hosted VMs.
