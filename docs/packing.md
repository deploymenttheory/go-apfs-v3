# Building filesystem images

`pack` creates a new, mountable HFS+ or HFSX DMG on Linux, Windows or macOS.
The filesystem builder and UDIF encoder are pure Go. Apple tools are used only
for independent acceptance verification.

```sh
# Pack the contents of a directory into the volume root.
apfs pack --filesystem hfsplus --volume-name Example ./source Example.dmg

# Build a previously edited session. Its filesystem and case policy are retained.
apfs pack --session build --volume-name Example Example.dmg

# Fix the construction clock and choose uncompressed UDIF.
apfs pack --session build --volume-name Example --format UDRO \
  --time 2025-06-07T08:09:10Z Example.dmg
```

Directory import uses the existing session engine with archive preservation and
regular-file hard-link preservation. Scratch is created and removed automatically.
The directory's contents become the volume root's children; the volume root uses
the session creation defaults. A session build retains its captured root metadata.
`--scratch-dir` and `APFS_SCRATCH_DIR` locate named sessions and select the
temporary import scratch root. Unnamed imports default to the system temporary
directory.

`--filesystem hfsplus|hfsx` is required for directory input. A named session must
already be HFS+ or HFSX. APFS creation and cross-format metadata conversion require
their own implementation and qualification.

## Output and preservation contract

The output is a single-volume UDIF without a partition map, containing a clean,
nonjournaled filesystem with 4096-byte allocation blocks. `--format UDZO` (default)
uses zlib compression; `UDRO` uses raw chunks. Both represent zero chunks without
storing their bytes and include data, block and master CRC32 checksums. Compression
of the DMG envelope is independent of compression of files inside the volume.

Names use the pinned HFS Unicode decomposition and case comparison rules. Data,
resource forks, ordinary attributes, opaque security attributes, public FinderInfo,
ownership, permissions, BSD flags and all four captured timestamps are preserved
when representable. Symlinks retain literal targets. Regular-file aliases share
one native inode through HFS's private-directory indirection. Native inode numbers
and the physical extent layout are newly assigned. Link counts describe the aliases
inside this build; references outside a captured subtree cannot exist in its output.

Unchanged decmpfs types 1, 3, 4, 7 and 8 can retain their stored representation.
Native build acceptance covers each admitted type, including native LZVN resource
storage and the type-7 stored marker. Other compression types fail explicitly. The builder does not introduce new decmpfs encoding.
Sparse input has identical logical bytes but is allocated contiguously.

Uncaptured required metadata, subsecond or out-of-range HFS timestamps, unsupported
object types, directory hard links, reserved names/attributes and unrepresentable
FinderInfo fail explicitly. Empty HFS resource forks are absent; an input claiming
an independently present empty fork is rejected. Available attributes are never
silently dropped. Host-import defaults and unavailable attributes are reported;
packing cannot recreate metadata the host did not provide.

`--uid` and `--gid` set directory-import defaults for unavailable ownership. Existing
observed ownership is preserved. Use session `chown`, `chmod`, `touch` and the other
file commands for deliberate changes before packing. Flags accept ordinary operands;
JSON is an optional output report only.

## Capacity and reproducibility

`--capacity` specifies volume bytes, optionally suffixed `KiB`, `MiB` or `GiB`.
Capacity rounds up to a 4096-byte block and must be at least 8 MiB. Automatic sizing reserves space for every
payload and metadata tree plus free space, with an 8 MiB minimum. Insufficient
capacity fails before output publication.

`--time RFC3339` fixes the whole-second construction clock; it does not normalize
captured file timestamps. Without it the command samples the current UTC clock.
The default native volume identifier derives from canonical metadata and payload
hashes; `--volume-id` accepts an explicit eight-byte identifier as 16 hex digits.
Enumeration, CNID assignment, allocation, zero filling, chunking and zlib settings
are deterministic. Identical captured inputs and options produce byte-identical
outputs across all three hosts. Different host-import observations or Go encoder
versions are not assumed to be identical. Reproducible builds should pin their
input session and tool version.

Planning bounds are 100,000 entries, depth 256, 4096 attributes per object, a 64 MiB
metadata accounting budget and fewer than 16,000 used nodes per B-tree. Volumes
are limited to 1 TiB. File data streams through a bounded 4 MiB DMG chunk buffer;
file size does not determine RAM usage. Content-derived identifiers require a
payload hash pass before the streaming output pass. No intermediate raw disk image
is materialized.

## Publication and library API

`hfsplus.Plan` borrows an immutable `filesystem.Reader` and returns a bounded
layout with `Size` and `Write`. `diskimage.Encode` independently consumes a sized
sequential raw volume. `pack.Write` connects them with bounded streaming and stops
both sides on failure. Readers and values retain their existing lifetime rules.

`pack.Create` writes a private sibling temporary file, flushes and closes it, then
publishes with a no-overwrite hard link. An existing destination, including a
symlink, is refused. The destination host filesystem must support hard links
(e.g. NTFS on Windows). A failure before publication leaves the destination absent;
normal cleanup removes staging. Abrupt process termination can leave a private
`.apfs-pack-*` sibling. The final image is complete once publication succeeds;
power-loss directory durability and edits to existing images have separate gates.
The CLI refuses destinations inside the managed session scratch directory.

## Independent qualification

One `image-building` acceptance family starts from Apple-created HFS+/HFSX images.
Its source contains deep catalog trees, large and empty attributes, resource forks,
compressed files, native filenames, aliases and an Apple-signed universal app.
Every portable host captures a session and builds UDRO and UDZO twice. Automatic
8 MiB and explicit 160 MiB capacities exercise multi-block allocation bitmaps and
checksum-covered zero chunks; long keys force a three-level catalog. Local
comparisons check the original observations and reproducibility. CI returns every
output to macOS 15, 26 and 27 for `hdiutil verify`, `fsck_hfs -fn`, read-only mounted
readback and `codesign --verify --deep --strict`. An independent Python comparison
checks exact values and a bijection of link identities; hashes must match across
portable hosts for the same captured input and options. No Go writer or reader
supplies the native expected values or the final native verdict.
