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

Workspace `ReplaceData` preserves source object identity, hard-link aliases, and
unrelated metadata while updating compression coherently. Directory-entry
replacement is a separate operation. An independent resource fork must survive
content replacement; stale compression storage must never become authoritative.

Both engines delegate active decmpfs contents to `internal/decmpfs`, which uses
the decoder-only packages under `internal/codec`. `UF_COMPRESSED` selects this
path; inactive attributes remain opaque, even when malformed. `Stat` reports
logical size and native compression type without decoding the file. Unknown
types remain inspectable but cannot be opened as logical data. Generation-store
and dataless representations do not become zero-filled files.

`OpenData` decodes logical data. `OpenRawData` reads the stored data fork;
`OpenAttribute` always reads raw stored attributes, including decmpfs and any
compression-owned resource fork. On unlocked volumes these interfaces return
plaintext storage; ciphertext remains available through the image source. Inline compression can coexist with an
independent resource fork. Values serialize access to a single decoded 64 KiB
block and check their retained context between blocks. Resource indexes are read
on demand: opening a large logical file does not allocate its index or contents.
Each requested block validates its ranges and decoded length; opening alone is
not a whole-file integrity scan. Malformed compressed data returns corruption,
including native premature EOF for a nonempty declared file.

The implemented `workspace` package binds original names, identity/view, metadata,
logical/raw data and attributes in `metadata/manifest.json` and hashed blobs.
`files` is the selected root's portable host projection. Names use one conservative
mapping on every host: unsafe/non-ASCII/long/reserved names and case collisions
become `~` followed by the original name's SHA-256; original bytes stay in the
manifest. Host paths cannot escape the rooted destination. An ordinary `._` file
remains ordinary content. Symlinks become target-text files, never traversal
paths. Regular hard links are attempted and otherwise copied, with the outcome
reported; original identities remain authoritative after archive transport.

Workspace creation requires a new directory. All streamed values must succeed
before the completion manifest is renamed into place. Failure leaves diagnostic
partial output, never a valid workspace. This is not a crash-durable transaction
or an edit API. Opening verifies schema, traversal, reference bounds, every blob
hash and the complete projection before returning `filesystem.Reader`. Source
filename rules and byte spelling survive independently of host lookup. External
mutation must be excluded during capture and use; edits detected at open are
conflicts, not imports. Preserved metadata does not enforce host ownership,
permissions, timestamps or ACLs. Content replacement below produces a separate
workspace. Ordered tree editing is described below; general external import remains later work.

Traversal defaults are 100,000 objects, 200,000 entries, depth 128, 4,096 attributes
per object, 64 MiB of manifest and 1 TiB per value and total streamed values.
Callers may lower the configurable limits. Logical/raw/attribute reads count
against the transfer budget even when storage deduplicates them. Data copies use
64 KiB buffers. A report separates retained metadata from host materialization.

`Workspace.ReplaceData` validates a nonempty batch of existing regular-file
object IDs before extraction. Each complete replacement source is borrowed and
streamed through the same bounded capture path. Duplicate IDs are conflicts,
including two requests naming different aliases of one inode. The output must
be new and outside the input workspace; actual ancestor directory identities
catch symlink and case aliases. No source file or blob is opened for writing.

A private reader overlays only the changed data, size and active compression
state. Attribute-backed compression loses its decmpfs attribute; resource-backed
compression also loses its compression-owned resource fork. Independent forks
and inactive attributes remain byte-exact. The shared decmpfs profile classifier
rejects unknown ownership. Logical and raw replacement hashes must agree before
publication. Unchanged files retain their data, raw storage and metadata.

Source timestamps are deliberately preserved, including modification/change
times. The API does not emulate native authorization or assign the host clock.
Each supplied object carries `Node.DataModified`, including byte-identical
replacement requests, so its data cannot masquerade as untouched source evidence.
Identity remains the original object/view. Derived schema-2 manifests record
`parentManifestSHA256`; `ManifestSHA256` and `ParentManifestSHA256` expose that
relationship without requiring the parent to remain present for reading.
Re-extraction retains the marker. Schema-1 captures remain readable. The report
counts distinct modified objects, not aliases or calls.

The publication boundary remains the completed manifest after successful reads,
writes and file flushes. There is no current-generation pointer, edit journal,
in-place mutation or crash-durable commit guarantee. Failed work can leave
incomplete output; the previous workspace stays usable. Independent destination
files keep later host edits from mutating the original through shared hard links.

`Workspace.Edit` holds a bounded private directory graph copied from the verified
manifest. Ordered changes resolve paths against that graph and reuse the existing
content replacement/compression rules. One final call to the capture engine
streams the resulting tree. Preflight errors create no output; streaming failures
leave an incomplete destination without a completion manifest. The baseline and
borrowed input lifetimes have the same contract as replacement.

Directory entries and objects remain distinct. Rename retains identity and permits
native replacement of compatible targets; renaming between distinct aliases of
one inode is a no-op. An empty directory can replace another empty directory.
Moves into descendants, directory hard links and intermediate symlink traversal
are rejected. Removing an entry adjusts its object's recorded link count by one,
retaining external aliases rather than counting only the extracted subtree.
Directory size and link counts remain outside native comparison as in the reader.

Creation requires all logical metadata fields explicitly present. Optional initial
attributes are borrowed sources, including independent resource forks. Active
compression is not a creation input. APFS retains supplied Unicode spelling;
HFS+ decomposes it with the existing pinned Apple tables. The 255-UTF-16-unit
limit applies to the stored spelling. Host projection mapping remains separate.

`Node.Created` distinguishes newly supplied objects. Their graph IDs are allocated
above the input's maximum; their `Identity.Volume` is `workspace:` plus a creation
digest, with View zero. The digest combines the parent manifest hash and the
captured object's metadata, ID, target and data/attribute hashes, requiring no
additional payload pass. It is stable through later edits; the containing manifest
hash identifies the complete edited state. Native objects retain source identity.
`LinksModified` distinguishes changed link counts. Schema 3 admits these fields;
older schemas remain supported. Created-object and modified-file report counts
are cumulative for reachable objects. This is recorded provenance, not a signature.

`appledouble` is a separate serialized metadata codec adapted from pinned Apple
copyfile source. It borrows values, bounds header/record parsing, and streams data.
Ordered duplicate records, empty values, flags and fixed FinderInfo/resource slots
are retained. A zero-length resource slot cannot distinguish absence from emptiness.
It does not associate sidecars with host files or turn raw security attributes
into native policy encodings. Native pack/unpack controls supply interoperability
evidence; untouched raw values remain preserved in the workspace.

## Historical APFS reads

A volume carries a private transaction bound. The live reader uses its selected
container checkpoint; a snapshot reader uses the retained snapshot XID and the
physical snapshot superblock's filesystem root. Both resolve virtual filesystem
objects through the live volume's object map, which preserves retained versions.
`Identity.View` reports the selected transaction. Opening another view never
mutates an existing reader or caches a global current snapshot.

Snapshot metadata and its name index are validated as one bounded inventory.
The filesystem and physical snapshot metadata trees share record bounds and
traversal, while their storage classes and subtypes remain explicit. Extended
snapshot metadata is resolved at the snapshot XID from the live metadata OID;
the saved snapshot superblock can predate that OID's creation. Native UUID
observations qualify this distinction.

A historical reader borrows its parent's unlocked key owner and exposes only
`filesystem.Reader`. It cannot close or transfer those keys. Closing the owning
unlock invalidates historical metadata, values and decoded compression caches;
independent unlocks remain usable. There is no live-view fallback when snapshot
selection, metadata validation or historical object resolution fails.

## Encrypted APFS reads

`Volume.Unlock` reads the selected checkpoint's container keylocker, locates the
volume keybag, verifies each key record's HMAC and bounds password-derivation
work before trying credentials. PBKDF2-HMAC-SHA256 derives the wrapping key;
RFC 3394 integrity checks distinguish a rejected credential from a damaged VEK
after successful KEK authentication. A root-tree checksum must pass before the
unlocked view is returned. Password bytes are not normalized or retained.

UUID-derived AES-XTS decodes the outer keybags; the password protects their
wrapped keys. Object-map encryption flags select metadata decryption before
checksum validation. File extents use their own `crypto_id` tweak, which must
not be replaced by the current physical address. Read-only clone access uses the
same extent machinery. The shared fork reader combines bounded sources or explicit
sparse ranges; it knows nothing about keybags, XTS or APFS identifiers.

An unlocked view owns an immutable key schedule behind a close/decryption lock.
Separate unlocks have separate lifetimes. Closing one releases the schedule and
invalidates its borrowed values, including inline attributes and decoded cache
contents. It never closes the image. Temporary raw keys are cleared, but Go's
AES and HMAC implementations do not expose erasure of their internal schedules.
XTS provides confidentiality without file-content authentication: a successful
unlock and valid metadata checksums do not prove that every data byte is intact.

Current bounds are 1 MiB per keybag, 4096 entries, and ten million aggregate
PBKDF2 iterations per unlock. Derivation checks cancellation every 1024 rounds;
sector reads retain their caller's context. Known software single-key records
with flags 0 or 0x10 are admitted. Legacy flag 2, hardware/per-file keys, extended
crypto profiles remain outside this layer. Encrypted DMG envelopes belong to
`diskimage`, independently of the volume cipher.
The native volume corpus qualifies AES-128-XTS; CommonCrypto also independently
qualifies the AES-256-XTS primitive without claiming a matching volume profile.

## Encrypted disk images

The `diskimage` pipeline reads an optional `encrcdsa` envelope, then UDIF chunk
encoding when present, then partitions. APFS or HFS+ consumes the resulting
bounded partition. Image and APFS passwords are independent; unlocking the first
never supplies a credential to the second. `OpenWithPassword` owns the input
file; `NewWithPassword` borrows its source. Their contexts bound opening and key
derivation, while image closure governs the decrypted view's lifetime.

Version 2 password records use PBKDF2-HMAC-SHA1 and either AES-192-CBC or older
3DES wrapping. CBC padding and the `CKIE` terminator must validate before keys
are admitted. Current native AES wrapping keeps an 8-byte IV-size field and
CBCPadIV8 identifier; the AES IV is zero-extended to 16 bytes. Payloads use
AES-128/256-CBC with an HMAC-SHA1-derived IV for each numbered block. The block
number is a big-endian uint32; a source too large for that space is rejected.
Partial reads decrypt complete encryption blocks and expose only declared bytes.

This format does not authenticate its data or key records. A damaged wrapped
key can be indistinguishable from a wrong password; metadata range/profile
errors remain corruption/unsupported errors. Existing partition and filesystem
checks still run after decryption. Successful opening is not whole-image
integrity verification.

Header admission bounds the table to 64 records, each at most 4096 bytes, and
ten million aggregate password iterations. Records must lie between the table
and payload without overlapping. Data blocks are powers of two from 512 bytes
to 64 KiB, and physical storage must contain the complete final padded block.
Version 1 and certificate/keybag-only images are unsupported. A password entry
may coexist with other known credential types, which are not used for unlocking.

The image owns its key schedule and UDIF cache. Closing invalidates partition
reads above that cache, clears cached bytes and raw IV-key material, releases
expanded keys and closes only owned files. Already returned file/attribute data
belongs to its caller; filesystem values must finish before image closure. Go's
cipher API does not expose expanded-key erasure. No decrypted temporary image
is written to disk.

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
are not total process-memory guarantees. Under a mutex, the UDIF cache retains
up to eight recently used chunks and at most 64 MiB of decoded bytes. This avoids
repeated decompression when historical filesystem roots and their object map
occupy different chunks. Eviction and image close clear decoded bytes.
Configurable shared budgets are pending.
decmpfs bounds are 3802 stored attribute bytes, 64 KiB logical inline contents,
64 KiB per resource block and 1 MiB encoded bytes per block. Exceeding an encoded
or logical decoding budget returns `ErrLimit`; unknown types return
`ErrUnsupported`. Codec scratch space is bounded independently of file size.

Dirty-journal logical views, repair, and sealed-volume file access are not qualified. HFS+ directory hard links return unsupported errors.
Overflow resolution is shared by catalog, attributes,
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
