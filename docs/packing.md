# Packing filesystem and disk images

`pack` builds a new APFS or HFS+/HFSX filesystem from a directory or session, or repacks
an existing disk image while preserving all decoded sectors. Both operations
run on Linux, Windows and macOS.
The filesystem builders and UDIF encoder are pure Go. Apple tools are used only
for independent acceptance verification.

```sh
# Pack the contents of a directory into the volume root.
apfs pack --filesystem apfs --volume-name Example ./source Example.dmg

# Use case-sensitive APFS names.
apfs pack --filesystem apfs --case-sensitive ./source CaseSensitive.dmg

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

`--filesystem apfs|hfsplus|hfsx` is required for directory input. APFS additionally
accepts `--case-sensitive`. A named session retains its native filesystem and case
policy. Cross-format metadata conversion is not implicit. An empty directory or
session builds an empty filesystem using the same command.

## Repacking an existing image

```sh
apfs pack --format UDZO original.dmg compressed.dmg
apfs pack --format UDRO original.dmg uncompressed.dmg
apfs pack --json disk.raw packaged.dmg
```

A file operand selects sector-preserving repacking. The complete decoded disk is
retained: partition tables and identifiers, every partition, filesystem allocation
and metadata, recorded unused sectors, APFS volumes, encrypted volume sectors and
retained snapshots. No filesystem is unlocked, repaired, rebuilt or resized. No
session or intermediate raw disk file is needed. Construction-only flags, including
`--filesystem`, `--volume-name`, `--capacity` and `--time`, are rejected for image
input. The report supplies the preserved disk size and SHA-256.

Lossless here means identical decoded disk bytes. The output DMG envelope is newly
encoded; its compressed bytes, CRCs and segment identifier can differ from the
input. Files and application signatures inside the disk retain their exact bytes.
Bytes that an original image already omitted cannot be recovered by repacking.

The admitted inputs are flat raw GPT/APM disks with 512-byte logical sectors or recognizable bare APFS/HFS+
volumes, and flattened, single-segment version-4 UDIFs with XML metadata and raw,
zero/ignored, zlib or bzip2 runs. Block tables and runs must cover the entire disk
in order without overlap or gaps. Stored payloads must be accounted for. Every
present data, block and master CRC32 is verified before encoding. An absent native
checksum is accepted only when its complete field is zero; a computed disk hash
does not establish authenticity or filesystem health. Structural/checksum errors
fail without publishing an output; there is no repair or salvage option.

The encoder retains source block names, identifiers, ranges and the recognized
native empty `plst` placeholder. Unknown resource keys or values, nonempty/unknown
`plst` resources, extended footers, container signatures, notarization data and
unaccounted envelope bytes are refused. License resources are therefore refused
rather than removed. Signed applications inside an ordinary DMG are supported;
a signature on the DMG itself requires a separate future signing workflow.
Encrypted DMG envelopes are refused. APFS encryption inside an unencrypted image
survives unchanged and needs no password for this operation.

Identical image bytes, format and tool version produce identical output across
hosts. Repacking hashes the decoded disk before and during encoding and refuses a
detected change. Inputs must remain immutable for the call. Memory is bounded by
the existing decoder cache, a 4 MiB output chunk and bounded metadata; it does not
scale with disk capacity. The existing 1 TiB disk and 16 MiB XML limits apply,
with at most 4096 block tables and bounded XML depth/node counts.

`diskimage.Repack` borrows a `block.Source` and an output writer. `pack.Repack`
opens a source file and publishes the completed image at a new path with the same
flush, no-overwrite and cleanup contract as fresh builds below. Reader ownership
and output-on-error rules remain explicit. Raw forensic imaging of damaged or
unrecognized partition maps retains a separate qualification gate.

## Fresh-output and preservation contract

The output is a single-region UDIF without a partition map, with 4096-byte
filesystem blocks. HFS+/HFSX is clean and nonjournaled. APFS contains one
unencrypted, unsealed volume and a complete initial checkpoint, object maps,
filesystem/extent-reference trees, space manager and free queues. It is a fresh
filesystem; source snapshots, clone sharing, physical allocation and native inode
numbers are not carried into a rebuild. `--format UDZO` (default)
uses zlib compression; `UDRO` uses raw chunks. Both represent zero chunks without
storing their bytes and include data, block and master CRC32 checksums. Compression
of the DMG envelope is independent of compression of files inside the volume.

Names use the pinned native comparison rules: APFS retains spelling and compares
with normalization, while HFS uses its frozen decomposition. Case policy belongs
to the source session. Data,
resource forks, ordinary attributes, opaque security attributes, public FinderInfo,
ownership, permissions, BSD flags and all four captured timestamps are preserved
when representable. Symlinks retain literal targets. Regular-file aliases share
one native inode through APFS sibling records or HFS's private-directory indirection. Native inode numbers
and the physical extent layout are newly assigned. Link counts describe the aliases
inside this build; references outside a captured subtree cannot exist in its output.

Unchanged decmpfs types 1, 3, 4, 7 and 8 can retain their stored representation.
Native build acceptance covers each admitted type, including native LZVN resource
storage and the type-7 stored marker. Other compression types fail explicitly. The builder does not introduce new decmpfs encoding.
Sparse input has identical logical bytes but is allocated contiguously.

Uncaptured required metadata, subsecond or out-of-range HFS timestamps, unsupported
object types, directory hard links, reserved names/attributes and unrepresentable
FinderInfo fail explicitly. An input claiming an independently present empty resource fork is rejected in
this construction profile. Available attributes are never
silently dropped. Host-import defaults and unavailable attributes are reported;
packing cannot recreate metadata the host did not provide.

APFS preserves nanosecond times in the supported 1970–2262 signed-nanosecond
range, including exact epoch zero. Tracked documents receive fresh document IDs.
Active compressed inputs must have consistent decmpfs headers, sizes, flags and
decodable storage; stored compression remains unchanged. Unknown BSD flag bits,
reserved filesystem-owned attributes and unsupported object kinds are refused.
APFS symbolic-link targets are literal, with a current 1023-byte construction limit.

`--uid` and `--gid` set directory-import defaults for unavailable ownership. Existing
observed ownership is preserved. Use session `chown`, `chmod`, `touch` and the other
file commands for deliberate changes before packing. Flags accept ordinary operands;
JSON is an optional output report only.

## Capacity and reproducibility

`--capacity` specifies volume bytes, optionally suffixed `KiB`, `MiB` or `GiB`.
Capacity rounds up to a 4096-byte block and must be at least 8 MiB. Automatic sizing reserves space for every
payload and metadata tree plus free space, with an 8 MiB minimum. Insufficient
capacity fails before output publication.

`--time RFC3339` fixes the construction clock; HFS requires whole seconds while
APFS accepts nanoseconds. It does not normalize captured file timestamps. Without it the command samples the current UTC clock.
Default native identifiers derive from canonical metadata and payload hashes.
HFS `--volume-id` accepts an eight-byte identifier as 16 hex digits. APFS accepts
`--volume-uuid` and `--container-uuid` as nonzero canonical UUIDs; absent values use
distinct content-derived UUIDs. Options belonging to the other format are refused.
Enumeration, native object-ID assignment, allocation, zero filling, chunking and zlib settings
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

`apfs.Plan` and `hfsplus.Plan` borrow immutable `filesystem.Reader` values and
return bounded layouts with `Size` and `Write`. Each engine owns its format
options and validation. `pack.VolumeOptions` supplies common construction choices;
`pack.Write` selects the engine from the reader's native format.
`diskimage.EncodeVolume` independently consumes a sized sequential source with an
`Apple_APFS` or `Apple_HFS` content hint. The existing `Encode` retains its HFS default. `pack.Write` connects them with
bounded streaming and stops
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

One `image-building` acceptance family starts from Apple-created APFS,
case-sensitive APFS, HFS+ and HFSX images.
Its source contains deep catalog trees, large and empty attributes, resource forks,
compressed files, native filenames, aliases and an Apple-signed universal app.
Every portable host captures a session and builds UDRO and UDZO twice. Automatic
8 MiB and explicit 160 MiB capacities exercise multi-block allocation bitmaps and
checksum-covered zero chunks; long keys force a three-level catalog. Local
comparisons check the original observations and reproducibility. CI returns every
output to macOS 15, 26 and 27 for `hdiutil verify`, `fsck_apfs -n` or
`fsck_hfs -fn`, read-only mounted
readback and `codesign --verify --deep --strict`. An independent Python comparison
checks exact values and a bijection of link identities; hashes must match across
portable hosts for the same captured input and options. No Go writer or reader
supplies the native expected values or the final native verdict.

APFS adds exact birth nanoseconds, tracked documents, 53 native positive/negative
name lookups per profile and an independently observed empty-directory build. Each
Mac also modifies every APFS output through a disposable shadow: file growth, hard
links, rename, deletion, tree growth and allocation reuse. The new checkpoint must
pass Apple's checker without repair and retain its contents after remounting; the
original image hash must remain unchanged. Fresh builds qualify native continued
use, not Go transactions or power-loss durability.

The `image-repacking` family reuses independently captured signed-app and snapshot
images, then adds native bare HFS+, raw GPT and HFSX Apple Partition Map disks with seeded free
sectors, and two APFS volumes sharing a container, one encrypted. Inputs exercise
raw, UDRO, UDZO and UDBZ storage. Apple devices supply the complete disk hashes;
all three hosts produce UDRO/UDZO twice. Every Mac verifies all 90 outputs with
`hdiutil verify`, raw-device SHA-256, partition/volume inventories, native mounted
file and raw-attribute observations, retained snapshot mounts, encrypted-volume
unlocking, filesystem checks and application signature verification. Cross-host
image hashes must agree. The native comparison never invokes Go.
