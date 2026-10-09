# Architecture and contracts

The library supplies filesystem operations for forensics, packaging, and
codesigning on Linux, Windows, and macOS. Production interpretation of an image
on another operating system must never depend on a macOS helper.

## Dependency direction

```text
CLI / acceptance / consumer applications
                  |
               inspect
              /       \
         diskimage   apfs / hfsplus
              \       /
                 block
```

`filesystem` contains shared reader contracts, metadata values and errors. It imports neither
engine nor host metadata implementations. A partition is a bounded borrowed
source, not a preferred filesystem. Format structures are shared by each
engine's eventual reader and writer; the two engines retain distinct algorithms.

Workspaces and mounts belong above these engines. Snapshot, preservation,
replacement, and transaction algorithms must not migrate into CLI handlers.

## Ownership and errors

`block.Open` and `diskimage.Open` own read-only descriptors. `New` and engine
`Open` functions borrow sources. Owners must outlive every borrowed view.
Sources provide concurrent `ReadAt` with an immutable size. Exclude external
mutation while reading; forensic callers should supply immutable images.

Errors distinguish corruption, unsupported features, limits, authentication,
and conflicts. APFS structural errors retain offsets relative to their source.
Unknown partitions are listed; invalid known tables never fall back to raw
interpretation. Inspection checks cancellation between partitions. File operations
check it during tree traversal and every extent read. Returned fork values retain
their opening context, so cancelling an operation also cancels its remaining I/O.

## Complete files

Metadata distinguishes uncaptured, absent, and present values. Mode 0000, zero
flags, and empty forks are valid observations. Preserve native timestamp
precision. Identity belongs to a volume and historical view, not a pathname.
Forks and attributes use independently owned sized readers.
They borrow the image; closing a value never closes other values or the image.
Unrepresented extent ranges fail rather than becoming zero-filled data; APFS
sparse extents carry an explicit sparse marker. Readers reject overlapping extents.

`Lookup` applies native name comparison and `LookupExact` uses enumerated spelling.
Neither follows symlinks. Lookup currently scans only the selected directory,
with B-tree traversal pruned by parent ID. Comparison tables are generated from
pinned Apple sources; Go's or the host's evolving Unicode tables are not used.
HFS+ maps stored slash to POSIX colon and NUL to U+2400.
Filesystem-owned APFS attributes remain inspectable; HFS+ FinderInfo returns the
native public view, whose reserved catalog fields stay untouched on disk.

HFS+ resolves regular-file link records through the private metadata directory.
All aliases return the underlying file CNID, forks, attributes and metadata.
Finder type/creator and creation date together identify link records. Fork
resolution joins inline extents with records keyed by CNID, fork type and logical
start block; missing, overlapping and surplus ranges are corruption. Attribute
continuations use their separate attribute B-tree. The extents file itself must
be described completely in the volume header, as specified by TN1150.

Planned staged `ReplaceData` preserves inode identity, hard-link aliases, and
unrelated metadata while updating compression coherently. Directory-entry
replacement is a separate operation. An independent resource fork must survive
content replacement; stale compression storage must never become authoritative.

The workspace will bind original names, link groups, metadata, and immutable
blobs in an explicitly identified metadata directory. Reversible name mappings
handle host limitations. Journal API-mediated changes and publish coherent
generations; external edits require explicit import. Preserving source ACL
bytes and enforcing host ACLs are separate capabilities.

## Forensics and writes

Inspection never replays a journal or repairs its source. APFS selects the
highest checksummed superblock in the supported contiguous descriptor area.
This is not proof that every object in the checkpoint is consistent. Failure
to resolve the selected view does not trigger silent fallback. Bad block zero
and descriptor-tree layouts are currently explicit errors.

Writable engines require exclusive ownership, feature admission, allocation
accounting, and durable publication. APFS copy-on-write and HFS+ journaling need
separate implementations. HFS+ metadata journaling is not atomic file-content
replacement. Compressed images will use durable writable shadows and explicit
export; `Sync` must describe exactly what becomes durable.

Recovery records source locations and distinguishes intact, partial, and inferred
reconstructions. Unavailable/reused extents are not verified content. General
file-type carving is separate from the planned filesystem-aware recovery.

## Current limits

Decoder bounds: 16 MiB UDIF plist; 64 MiB stored/decoded compressed chunk; 1 TiB
UDIF logical disk; 4096 GPT/APM entries; 32 tree levels; 65536 checkpoint
descriptor blocks; one million visited nodes/extents per file operation. These
are not total process-memory guarantees. The UDIF cache
retains one decoded chunk under a mutex. Configurable shared budgets are pending.

Dirty-journal logical views, repair, sealed-volume file access, and encryption
unlocking are not qualified. HFS+ directory hard links and transparent compression
return unsupported errors. Overflow resolution is shared by catalog, attributes,
data and resource forks; the native fragmentation scenario directly qualifies
data/resource forks. Fragmented metadata and attribute-continuation fixtures
remain to be added. APFS readers admit the observed 0x11 attribute-stream
encoding, with its provenance and unknown write semantics recorded in
`sources.json`. Other unknown storage flags fail. Feature flags remain visible
in structural reports.

APFS lookup currently targets the Unicode 16 comparison mappings in the pinned
Apple XNU source, including original combining classes when case folding changes
a scalar. Native cases exercise Unicode 11/14/16 boundaries. Unknown scalars
retain their spelling; this is not emulation of every native filename-admission
error. Historical APFS Unicode profiles and directory-key hash acceleration
remain outside the qualified lookup contract.
