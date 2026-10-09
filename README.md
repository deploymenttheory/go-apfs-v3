# go-apfs-v3

Portable macOS filesystem operations in Go for forensics, application packaging,
and codesigning on Linux and Windows. APFS and HFS+/HFSX share preservation
contracts while retaining separate filesystem engines.

**Status: initial read-only implementation.** The executable inspects images,
lists directories, reads ordinary and transparently compressed files, and unlocks
software-encrypted APFS volumes and AES-128/256 DMG images for reading. It also
opens retained APFS snapshots as historical filesystem views. Writes,
recovery and mounting are not implemented yet. See [implementation status](docs/implementation.md)
for the complete agreed scope and qualification gates. This is a clean API break
from v2.

## Build and use

Go 1.27 or later. The current core has no external Go dependencies or cgo.

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
```

`info` is an alias for structural inspection. Flags precede the image argument.
Output goes to stdout; errors go to stderr.
File paths use the selected volume's native comparison rules. Symlinks are not followed.
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
has no separate `Close`. CLI `list` and `cat` accept either `--snapshot-name` or
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
