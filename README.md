# go-apfs-v3

Portable macOS filesystem operations in Go for forensics, application packaging,
and codesigning on Linux and Windows. APFS and HFS+/HFSX share preservation
contracts while retaining separate filesystem engines.

**Status: initial read-only implementation.** The executable inspects images,
lists directories and reads uncompressed files. Encryption unlocking, writes,
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
./bin/apfs cat image.dmg /Applications/Example.app/Contents/Info.plist
```

`info` is an alias for structural inspection. Flags precede the image argument.
Output goes to stdout; errors go to stderr.
File paths use exact names from enumeration. Symlinks are not followed.
When several filesystems match, select `--partition INDEX` and/or `--volume ID`.

Currently implemented:

- Sized read-only block sources and bounded partition views.
- Raw images; UDIF images with raw, zero, zlib, and bzip2 chunks.
- GPT header/table CRC validation and enumeration with 512/4096-byte sectors;
  Apple Partition Map enumeration with 512-byte map blocks.
- APFS container geometry, checkpoint selection, object-map lookup, volume names,
  UUIDs, feature flags, encryption state, roles, and groups.
- HFS+/HFSX volume geometry, flags, case policy, and catalog root-thread name.
- Directory enumeration, file identity, native metadata, symlink targets,
  uncompressed data, sparse APFS extents, resource forks and extended attributes.
- Concurrent, bounded fork readers with independent close and cancellation.
- Versioned JSON reports and typed corruption/unsupported errors.

Encrypted APFS state is reported but not unlocked. Invalid recognized structures
fail explicitly. Inspection never replays a journal or repairs a source.

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

`apfs.Volume` and `hfsplus.Volume` implement `filesystem.Reader`. `ReadDir`
enumerates names and object IDs; `Stat` returns logical metadata;
`OpenData`/`OpenAttribute` return sized `ReadAt` values. Values and volume readers
must finish before closing the image. `filesystem.LookupExact` is an explicit
exact-spelling traversal; native case folding is still pending.

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

[Acceptance instructions](acceptance/README.md) cover capture and cross-platform
replay. Passing a macOS 27 fixture does not qualify macOS 15 or 26. Runtime
qualification is distinct from cross-compilation.

## Design

- [Architecture and preservation contracts](docs/architecture.md)
- [Implementation sequence and status](docs/implementation.md)
- [Source inventory](docs/sources.json)

Metadata, forks, links, compression, and identity belong to file operations.
Codesigning remains a consumer; signature construction is outside this library.

Original code is MIT licensed. The Apple-derived FinderInfo adapter retains
APSL-2.0; see [third-party notices](THIRD_PARTY_NOTICES.md) and the source inventory.
