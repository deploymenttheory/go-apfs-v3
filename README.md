# go-apfs-v3

Portable macOS filesystem operations in Go for forensics, application packaging,
and codesigning on Linux and Windows. APFS and HFS+/HFSX share preservation
contracts while retaining separate filesystem engines.

**Status: readers, preservation, file-command sessions, APFS/HFS+/HFSX image building and disk-image repacking.** The executable inspects images,
lists directories, reads ordinary and transparently compressed files, and unlocks
software-encrypted APFS volumes and AES-128/256 DMG images for reading. It also
opens retained APFS snapshots, extracts portable workspaces, and replaces their
file contents while preserving metadata. Ordered workspace edits create, move,
remove and link entries, and edit metadata, extended attributes and resource forks. Fresh APFS/HFS+/HFSX DMGs can be built from sessions or directories. Existing APFS/HFS+ disk images can be repacked with every decoded sector preserved. Existing-filesystem
writes, recovery and mounting remain pending. Fresh APFS containers also support multiple volumes, shared reserves/quotas and System/Data groups. See [implementation status](docs/implementation.md)
for the complete agreed scope and qualification gates. This is a clean API break
from v2.

## Build and use

Go 1.27 or later. No cgo is required. Session locks and host metadata use the
pinned `golang.org/x/sys` dependency.

```sh
go build -o ./bin/apfs ./cmd/apfs
./bin/apfs inspect image.dmg
./bin/apfs inspect --json image.dmg
./bin/apfs list image.dmg /Applications
./bin/apfs snapshot list --json image.dmg
./bin/apfs cat --snapshot-name com.apple.asr.123 image.dmg /Fixture/generation.txt
./bin/apfs cat image.dmg /Applications/Example.app/Contents/Info.plist
./bin/apfs cat --password-file ./volume-password.bin apfs-encrypted.dmg /Fixture/example.txt
./bin/apfs cat --image-password-file ./image-password.bin encrypted.dmg /Fixture/example.txt
./bin/apfs extract --json image.dmg /Applications/Example.app ./example-workspace
./bin/apfs workspace verify --json ./example-workspace
./bin/apfs session open --image image.dmg --path /Applications build
./bin/apfs cp --session build --from-host -a ./Example.app /
./bin/apfs chmod --session build 0755 /Example.app/Contents/MacOS/Example
./bin/apfs session export build ./edited-workspace
./bin/apfs pack --filesystem apfs --volume-name Example ./source Example.dmg
./bin/apfs pack --volume Apps --directory ./apps --volume Resources --directory ./resources Bundle.dmg
./bin/apfs pack --format UDZO original.dmg repacked.dmg
./bin/apfs session remove build
```

`info` is an alias for structural inspection. Flags precede the image argument.
Output goes to stdout; errors go to stderr.
Image-reading paths use the selected volume's native comparison rules without
following symlinks. [Session commands](docs/sessions.md) use the same name rules
and the documented command-specific symlink options.
When several filesystems match, select `--partition INDEX` and/or `--volume ID`.

Currently implemented:

- Sized read-only block sources and bounded partition views.
- Raw images; UDIF images with raw, zero, zlib, and bzip2 chunks.
- Password-protected `encrcdsa` v2 DMGs with AES-128/256-CBC, including encrypted
  images containing separately encrypted APFS volumes.
- GPT header/table CRC validation and enumeration with 512/4096-byte sectors;
  Apple Partition Map enumeration with 512-byte map blocks.
- APFS container geometry, checkpoint selection, object-map lookup, volume names,
  UUIDs, feature flags, encryption state, roles, and groups.
- HFS+/HFSX volume geometry, flags, case policy, and catalog root-thread name.
- Directory enumeration, file identity, native metadata, symlink targets,
  uncompressed data, sparse APFS extents, resource forks and extended attributes.
- Concurrent, bounded fork readers with independent close and cancellation.
- Native filename lookup, regular-file hard-link identity, and HFS+ overflow
  extents for fragmented data and resource forks.
- Shared decmpfs reading: stored data, zlib, LZVN, LZFSE, LZBITMAP and Apple
  framed LZ4, in attributes and resource forks, with bounded random reads.
- APFS password/keybag unlocking, encrypted metadata and extent reads; immutable
  unlocked views with explicit key lifetimes.
- APFS snapshot inventories and independent historical readers selected by exact
  snapshot name or XID; live and historical reads share the same file APIs.
- Portable extraction with original names, logical/raw data, metadata, attributes,
  resource forks, symlink targets and hard-link identities; verified workspace readers.
- Ordered workspace creation, rename, removal, link and data replacement batches.
- Explicit metadata patches, extended-attribute set/remove and complete independent
  resource-fork replacement within the same ordered batches.
- Persistent named sessions with managed scratch, host directory import and
  `cp`, `chmod`, `chown`, `chflags`, `touch`, `mkdir`, `mv`, `rm`, `ln` and `xattr`.
- Fresh, deterministic APFS containers with one or more volumes, per-volume reserves/quotas and System/Data groups, and HFS+/HFSX volumes in uncompressed or zlib UDIF DMGs;
  see [packing semantics](docs/packing.md).
- Sector-preserving raw/UDIF repacking to UDRO/UDZO, including partitioned disks,
  APFS snapshots and encrypted APFS volume sectors; strict container admission.
- Streaming AppleDouble decoding/encoding using Apple copyfile layouts.
- Versioned JSON reports and typed corruption, authentication and unsupported errors.

Password files contain exact bytes: no newline or whitespace is removed. Use
`-` as either password filename to read stdin through EOF. `--image-password-file`
unlocks a DMG envelope; `--password-file` unlocks the selected APFS volume. Both
can be supplied, with at most one reading stdin. Passwords are never accepted as
literal command-line options. Inspecting an encrypted DMG needs its image
password; APFS volume inspection can report locked volumes without their password.

The qualified encryption profile uses APFS software single-key encryption with
AES-256 key wrapping and AES-128-XTS sectors. Hardware/per-file keys, legacy key
records remain unsupported. Encrypted DMG support currently covers version 2
password records; version 1, certificate-only and keybag-only envelopes remain
unsupported. AES-256-XTS primitive vectors are tested independently; a native volume profile is not yet qualified.
Invalid recognized structures fail explicitly. Inspection never replays a journal
or repairs a source.

## Library

```go
image, err := diskimage.Open("example.dmg")
if err != nil {
    return err
}
defer image.Close()
report, err := inspect.Image(ctx, image)
```

Import `github.com/deploymenttheory/go-apfs-v3/diskimage` and
`github.com/deploymenttheory/go-apfs-v3/inspect`. `diskimage.New` borrows a
`block.Source`. Image decoding exposes the complete disk; callers select
partitions explicitly. Filesystem engines borrow their source.

`diskimage.OpenWithPassword(ctx, path, imagePassword)` owns a read-only file and
its decrypted image view. `NewWithPassword` borrows a `block.Source`; closing
that image releases keys and cached image bytes without closing the caller's
source. Opening requires an encrypted envelope. An ordinary `Open`/`New` returns
`ErrAuthentication` for one. Image encryption is reported separately from APFS
volume encryption. Finish filesystem values before closing their image.

`lockedVolume.Unlock(ctx, passwordBytes)` returns a separate `*apfs.Volume`.
The original volume stays locked. Close the unlocked view after its values;
closing it invalidates those values and releases its key schedule, while other
unlocks remain usable. The password is borrowed only for the call. Raw temporary
keys are cleared; Go's AES API does not provide expanded-key zeroization.

`volume.ListSnapshots(ctx, yield)` reports retained names, XIDs, timestamps,
flags and observed UUIDs. `OpenSnapshot(ctx, xid)` and
`OpenSnapshotName(ctx, name)` return a borrowed `filesystem.Reader` fixed to that
snapshot. Keep the source and owning APFS unlock open; the historical reader
has no separate `Close`. CLI `list`, `cat` and `extract` accept either `--snapshot-name` or
`--snapshot-xid`. Missing or damaged selections fail without returning live files.
Sealed-system verification, dataless snapshots and snapshot mutation remain outside
this reader increment.

`apfs.Volume` and `hfsplus.Volume` implement `filesystem.Reader`. `ReadDir`
enumerates names and object IDs; `Stat` returns logical metadata;
`OpenData`/`OpenAttribute` return sized `ReadAt` values. Values and volume readers
must finish before closing the image. `filesystem.Lookup` uses native comparison;
`filesystem.LookupExact` preserves exact-spelling traversal for forensic callers.
`Reader.Lookup` resolves one component and returns its stored spelling.
`OpenData` returns logical decompressed bytes when `UF_COMPRESSED` is active;
`Stat` reports the logical size and native compression type. `OpenRawData`
retains the stored data fork, while `OpenAttribute` retains byte-exact decmpfs
and resource-fork storage, including compression-owned resource forks.

`workspace.Extract(ctx, reader, rootID, newDirectory, limits)` creates a portable
workspace. `files/` contains a host projection; `metadata/manifest.json` records
original byte names and native metadata, with SHA-256 blobs for logical/raw data
and attributes. Unsafe names and case collisions are mapped. Symlinks appear as
regular target-text records; hard-link identities survive hosts or archives that
copy their contents. Original ownership, modes, flags and times are recorded,
not applied. The projection is therefore not yet a runnable macOS app bundle.

`workspace.Open(ctx, directory)` verifies the complete projection and blobs, then
implements `filesystem.Reader` with the original names and filename comparison
rules. Keep it open while using values; keep the directory immutable. Missing,
modified or incomplete content fails explicitly. This increment supports capture
and readback, staged content replacement and ordered tree edits. Host import is available through the separate session command API. The CLI refuses existing destinations. Failed capture can leave an incomplete
workspace for diagnosis. Large values stream; object, entry, depth and byte
budgets are configurable up to documented defaults in `workspace.DefaultLimits`.

`w.ReplaceData(ctx, replacements, newDirectory, limits)` replaces complete data
forks in a new, self-contained workspace. Each `workspace.DataReplacement` selects
an existing object ID and borrows a sized `block.Source`. All hard-link aliases
receive the same bytes. Source ownership, modes, timestamps, unrelated flags,
attributes and independent resource forks remain recorded. Active compression
is removed coherently; the replacement's logical and raw data are uncompressed.
Inactive decmpfs attributes remain opaque. Symlinks are never followed.

The baseline stays unchanged. The output records its parent manifest's SHA-256,
and changed `filesystem.Node` values carry `DataModified`; their identity still
identifies the source object/view. The marker survives subsequent replacement
and re-extraction. Schema 1 captures remain readable; derived workspaces use
schema 2. Replacement requires a new destination outside the baseline. Duplicate
object requests, unknown compression ownership and partial I/O fail explicitly.
This operation preserves recorded timestamps, including modification/change time;
it does not synthesize native kernel write times from the consumer host clock.

`w.Edit(ctx, changes, newDirectory, limits)` applies an ordered batch of
`workspace.Change` values, then captures its final tree once. It supports file,
directory and symlink creation, regular-file hard links, rename/move (including
replacement of an existing entry), empty-directory removal, unlink and content
replacement. Paths use the source filename rules and see preceding edits.
Symlinks are not traversed. New objects require explicit metadata and optional
initial attribute/fork sources; the host's clock, umask and process metadata are
never inferred. Existing timestamps stay recorded under the preservation policy.

Created nodes carry `Created` and a `workspace:` creation digest in their identity;
these are graph object numbers, not invented native inode IDs. Link count changes
carry `LinksModified`, with counts adjusted for aliases outside the captured tree.
These markers use schema 3 and persist through subsequent captures. Schemas 1 and
2 remain readable. See [preservation batch semantics](docs/workspace-edits.md) for the library contract, native qualification, and creation metadata policy.

`SetMetadata`, `SetAttribute`, `RemoveAttribute` and `ReplaceResourceFork` also
participate in `w.Edit`. Partial metadata patches preserve unspecified fields.
Attribute create/replace conditions follow Apple names; complete fork replacement
truncates old bytes. FinderInfo follows each format's public value and hidden-flag
rules. Active compression-owned storage and security ACL edits are protected.
Schema-4 output records cumulative changed field/attribute names and keeps schemas
1–3 readable. See [metadata edit semantics](docs/workspace-edits.md#metadata-attributes-and-resource-forks)
for timestamp precision, flag admission, empty-fork behavior and library examples.

`appledouble.Decode(ctx, source)` borrows serialized metadata; `Write(ctx, out,
file)` streams it. These APIs operate on explicit inputs, never infer companion
files from `._` names, and do not apply host metadata policy. ACL/quarantine
records are opaque serialized values, distinct from raw filesystem attributes.
The codec admits Apple's two-entry FinderInfo/resource layout and ATTR extension;
unknown layouts fail explicitly. AppleDouble's 32-bit ranges limit encoded output
to 4 GiB minus one byte. Workspace storage retains larger values independently.

`session.Create` starts an empty logical filesystem and `session.Capture` imports
an existing reader once. `session.Open` resumes it under an exclusive process lock.
Commands publish one metadata revision and reuse immutable payloads. Metadata-only
commands do not reread file content. `Verify` hashes every reachable value;
`Export` produces the preservation format described above. Session commands derive
native modification/change times; the older workspace APIs retain their explicit
preservation policy. See [session usage and limits](docs/sessions.md).

## Verification

```sh
go test ./...
go test -race ./...
go vet ./...
golangci-lint run
```

Acceptance replays genuine retained macOS images against independent
`diskutil` and native filesystem observations. The file-reading family compares
105 objects in each of four filesystem variants, including contents, metadata,
Unicode names, binary/empty/large attributes and resource forks. Each corpus
records native source, observations, image hashes and the actual OS version/build.
Images are hashed before and after portable reading.
The file-semantics family adds native positive/negative filename lookups,
three aliases of one file, and independently verified fragmented HFS+ forks.
The file-compression family adds each admitted decmpfs type, native codec
readback, mixed stored/compressed blocks, raw storage, random reads, inactive
attributes and a malformed active-file control.

[Acceptance instructions](acceptance/README.md) cover capture and cross-platform
replay. Passing a macOS 27 fixture does not qualify macOS 15 or 26. Runtime
qualification is distinct from cross-compilation.

## Design

- [Architecture and preservation contracts](docs/architecture.md)
- [Implementation sequence and status](docs/implementation.md)
- [Source inventory](docs/sources.json)

Metadata, forks, links, compression, and identity belong to file operations.
Codesigning remains a consumer; signature construction is outside this library.

Original code is MIT licensed. Derived codecs, FinderInfo and comparison data retain
their upstream notices; see [third-party notices](THIRD_PARTY_NOTICES.md) and the source inventory.
