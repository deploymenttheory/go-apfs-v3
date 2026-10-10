# Implementation sequence and qualification

This is the complete agreed scope. A phase is not complete because its APIs
compile. v2 production code and documentation were examined; its `_test` files
and harness were not imported.

| Phase | Deliverable | Current status |
| --- | --- | --- |
| 1 | Contracts, source inventory, native scenarios, build/CI, portable inspection | Native macOS 15/26/27 production and Linux/Windows/macOS replay passed in PR #7 |
| 2 | Full readers, names, metadata, forks, links, compression, unlocking | Ordinary/compressed reads, native name lookup, regular-file links, HFS+ overflow forks, metadata, symlinks, attributes and software-encrypted APFS and AES-128/256 encrypted-DMG reads implemented; retained APFS historical views implemented; broader key profiles remain pending |
| 3 | Preservation-aware extraction, workspaces, replacement, AppleDouble | Immutable extraction, verified workspace readers, streaming AppleDouble and staged content replacement implemented; ordered tree, metadata, attribute and resource-fork edit batches implemented; file-command sessions and host directory import implemented; native qualification enforced by the compatibility matrix |
| 4 | Deterministic creation, packing, DMG encoding/repacking, volume groups | Fresh APFS containers with multiple volumes, reserves/quotas and System/Data groups, HFS+/HFSX construction, sector-preserving raw/UDIF repacking and fresh AES-128/256 DMG encryption/password changes implemented; full native build/repack/encryption qualification required |
| 5 | Existing-filesystem edits, allocation, tree mutation, durable transactions | Pending |
| 6 | Snapshot lifecycle, clones, encrypted modification/creation | Pending |
| 7 | Read/write mounts on Linux/macOS/Windows | Pending |
| 8 | Deleted-file recovery, allocation-aware scanning, consumer qualification | Pending |

## Current evidence

The volume-inspection family compares native APFS, case-sensitive APFS, HFS+,
and HFSX images against `diskutil`: name, case policy, allocation block size,
filesystem size, and APFS UUID. Inputs are native zlib UDIFs with GPT maps.
Native read-only attachment and portable inspection must not change image hashes.

The file-reading family compares 105 objects per filesystem with the final
read-only native mount: exact directory entries and Unicode spelling, CNIDs/inode
IDs, regular-file and symlink sizes, link counts, mode, UID/GID, BSD flags,
birth seconds, all three other timestamps at native precision, symlink targets,
file hashes, and every native-visible extended attribute's size/hash. Native
directories' synthetic size/link counts are intentionally outside the comparison.
APFS filesystem-owned attributes may be enumerable in addition to native-visible
attributes. Fixtures include multi-node trees, empty files/attributes, binary data,
sparse ranges, a 32 KiB ordinary attribute and a resource fork larger than 32 KiB.

The file-semantics family adds 15 filename comparison cases with positive and
negative native lookup results, three hard-link aliases modified through a link,
and HFS+ data/resource forks whose fragmentation is independently measured by
Darwin `F_LOG2PHYS_EXT`. The retained forks have 20 and 21 extents; complete hashes
and random reads across every native extent boundary are compared. Original
spelling, link identity/count, metadata and attributes remain part of the same
file comparison. Apple C comparison tables are translated reproducibly; an older
Unicode 9 assumption failed the native Georgian case and is not used.

Retained local evidence covers macOS 27.0.1 (26A434). The previous inspection and
file-reading families passed all three native producers and all three replay
hosts in [PR #7's native run](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/37957366458).
The file-semantics family passed all required producers and replay hosts in
[PR #9's native run](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/37961351230).
The file-compression family now adds native decmpfs types 1, 3, 4 and 7–16,
logical/raw storage separation, native public-codec readback, stored blocks,
resource descriptor gaps, inactive attributes and a malformed active-file control.
The compression implementation passed fresh macOS 15/26/27 reference capture and
Linux/Windows/macOS replay in [PR #10's compatibility run](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/37974021258).
The encrypted-reading increment adds four independently created APFS images:
ordinary, Unicode, long and changed passwords, case-sensitive/insensitive names,
wrong/empty/old-password rejection and 108 observed objects per image. Native
clones, compression, links, sparse data, metadata and forks are read after a
read-only unlock. CommonCrypto supplies separate PBKDF2, key-wrap and XTS vectors.
The APFS encryption increment passed [PR #11's native compatibility matrix](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/37978358162).

The encrypted-DMG increment adds six Apple-created images covering AES-128/256,
APFS, case-sensitive APFS, HFS+ and HFSX, raw/compressed storage, Unicode and
changed passwords, and independent APFS encryption inside a DMG. Each compares
107 native objects and checks credential rejection, read-only preservation and
image-view lifetime. Fresh macOS 15/26/27 capture and all three replay hosts passed
in [PR #12's compatibility run](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/37982231632).
The macOS 15 images exercise 3DES password-key wrapping; the retained macOS 27
images exercise AES wrapping. Both carry AES-128/256 encrypted payloads.

Every reader change continues to require that full matrix. Short parser fuzz campaigns,
unit tests, race detection, vet, lint and cross-builds supplement native evidence.

Retained manifests identify the captured OS build. Fresh captures require the
expected major version and fail on a mislabeled runner. These scenarios do not
qualify write, mount or recovery capabilities.

Remaining reader work includes broader encryption profiles, sealed views,
historical name profiles and broader damaged-image handling. HFS+ directory
hard links, generation-store and dataless file contents fail explicitly. Fragmented
metadata and attribute-continuation fixtures remain unqualified. A small set of
native fixtures is evidence for these scenarios,
not a declaration of support for every image in the wild.

## APFS snapshot reader increment

Provide read-only enumeration and access to retained APFS snapshots. This is
part of phase 2; snapshot creation, deletion and revert by Go remain in phase 6.
The user operation is to select a historical filesystem state and read its
files and metadata on Linux or Windows, including files removed from the live
volume after the snapshot was taken.

Implementation scope:

- List snapshot names, transaction identifiers (XIDs), timestamps and flags;
  expose UUIDs when available, preserving the distinction from uncaptured data.
- Open a snapshot by an explicit name or XID through a fixed read-only view.
  Object-map resolution, tree validation and `Identity.View` must use that
  selected view. Opening one must not change the live volume or another view.
- Reuse the existing file, metadata, attribute, fork, compression and encryption
  readers. Keep snapshot selection in the APFS engine and expose it through
  `snapshot list` and explicit selectors on CLI `list`/`cat`.
- Bound snapshot-tree traversal and validate record lengths, references, object
  types, checksums and transaction limits. Missing or damaged snapshots must
  fail explicitly; they must never fall back to the live filesystem.

Use the snapshot metadata and object-map layouts in Apple's
[APFS reference](https://developer.apple.com/support/apple-file-system/Apple-File-System-Reference.pdf),
with pinned source provenance for any translated code. Existing tree decoding
should be shared where its format rules match; snapshot-specific interpretation
stays explicit.

The local feasibility gate passed without special runner provisioning. Apple
Software Restore (`asr`) creates temporary snapshots during replication. The
collector observes its own child's snapshot, pauses the child, mounts the
snapshot read-only, then resumes the copy to successful completion. The mount
prevents cleanup from deleting that snapshot. After unmounting, the retained
snapshot must still appear in Apple's inventory. All source/target volumes are
disposable images. The captured names are Apple's actual `com.apple.asr.*` names;
Unicode snapshot names are not part of native qualification.

Direct unentitled syscalls and `apfs_systemsnapshot` had failed with EPERM;
those failures did not establish that new runners were needed. The native
collector uses the replication workflow instead. It neither changes host security
settings nor creates snapshot structures with Go. A missed snapshot, timeout,
failed copy or failed filesystem verification fails capture.

Native snapshot capture has passed on macOS 15, 26 and 27. The retained macOS 27
corpus matches Go for 111–112 objects in each live/historical state in approximately
one second; the complete retained acceptance suite takes approximately four
seconds locally. Fresh capture and replay of every producer on Linux, Windows
and macOS are required by [PR #13's compatibility checks](https://github.com/deploymenttheory/go-apfs-v3/pull/13/checks).
Qualification results are recorded in that PR; native capture alone does not
establish portable compatibility.

Add one `snapshot-reading` acceptance family with three initial profiles:
ordinary APFS, case-sensitive APFS, and software-encrypted APFS inside an
encrypted DMG. Each retains two snapshots and a later live state. Between states,
change file contents, rename and delete entries, modify metadata, attributes and
resource forks, and exercise hard links, clones, sparse data and compression.
Read each retained snapshot through a native read-only mount of the final image;
expected results must not be inferred from the fixture-writing recipe.

The comparison must prove that older names, contents and metadata remain visible
only in the appropriate states, that objects retain the right identity within
each view, and that interleaved reads cannot mix states. Include empty inventory,
unknown/deleted snapshot selection, cancellation, corruption and borrowed-key
lifetime checks. Preserve source image hashes and record native commands,
observations, source hashes and OS builds.

Require fresh macOS 15/26/27 captures and Linux/Windows/macOS replay, plus the
existing regression matrix. Reuse the common file observation/comparison code;
report capture and replay duration and avoid a Cartesian product of every
encryption, compression and filename profile.

Sealed-system integrity verification, arbitrary checkpoint recovery, dataless
snapshots and snapshot mutation are outside this increment. HFS+ retains its
existing reader and regression coverage. Preservation-aware extraction and
workspaces start phase 3 below.

## Preservation-aware extraction increment

The first phase-3 increment adds an explicit portable extraction workspace and
a streaming AppleDouble codec. A workspace holds a usable host projection plus
immutable, hashed logical/raw data and attributes, original byte names, metadata,
symlink targets, hard-link identities and the selected source view. Opening it
through `filesystem.Reader` retains the source's filename comparison rules.
Native permissions, ACL enforcement and host timestamp changes are separate
from retained source metadata. Extraction never discovers metadata by matching
`._` neighbors, follows source symlinks, or overwrites an existing destination.

Names unsafe or ambiguous on a portable host receive reversible manifest
mappings. Symlinks are recorded without creating host traversal paths; hard-link
relationships remain recorded even when the host requires independent files.
Malformed trees, missing attributes, cancellation, resource limits and partial
I/O fail explicitly. A completion manifest is published only after every value
has been stored. Existing workspace data remains immutable. The next content-replacement
increment below writes a separate workspace; ordered tree edits follow it, with
general external import remaining later work.

AppleDouble operates on serialized metadata values using the pinned Apple
`copyfile` layouts. Native `COPYFILE_PACK` output is decoded and re-encoded on
every host, then Apple's unpack operation independently checks the resulting
metadata on macOS 15, 26 and 27. The codec does not emulate process quarantine,
account lookup, ACL authorization or native omission policy. Raw workspace
attributes remain authoritative when AppleDouble cannot represent a value.

The extraction family checks native file observations against the reopened
workspace, original/raw fork hashes, byte names, mapped collisions, ordinary
`._` content, links and explicit preservation outcomes. Fresh native captures
and Linux/Windows/macOS outputs are required. Native readback verifies those
outputs independently; missing artifacts or a mismatch fail the gate. Existing
reader/snapshot/encryption families remain required.

## Staged content replacement increment

Replace complete contents of existing regular files while preserving their source
identity, hard-link aliases, unrelated metadata and independent resource forks.
The library accepts a batch of explicit object IDs and borrowed sized inputs;
The replacement library resolves explicit object identities. Both APIs create a
new self-contained workspace and leave the baseline untouched. Existing, nested
or symlink-aliased destinations cannot replace or modify the source workspace.

Active compression becomes ordinary data, removing only its owned storage.
Inactive decmpfs attributes remain opaque. Source timestamps stay recorded by
explicit policy; native kernel write times are not invented. `Node.DataModified`
marks supplied contents and persists through subsequent captures. Schema-2
manifests bind the result to its input manifest hash; old captures remain readable.
There is no generation database, concurrent commit API or general host-file import.

The content-replacement family captures native before/after images on all four
filesystem profiles. Seven native O_TRUNC writes per image exercise ordinary and
compressed hard links, growth, shrinking, empty data, original mapped names,
inline compression with an independent fork, resource compression and inactive
attributes. Go replacement is compared against the independent native after
observation. Timestamps are checked against the native before observation because
preserving those recorded values is the stated API policy. Both observations
remain unmodified evidence. Current native qualification covers decmpfs types
3, 4 and 8; the storage classifier shares the reader's admitted profiles.

Each Linux, Windows and macOS consumer returns before/after workspaces to every
Mac. Python verifies all 36 pairs and 252 replacement operations against native
reference data, including removed compression attributes, alias identity,
unchanged objects and source provenance. The focused retained family takes about
two seconds locally. Existing preservation and reader gates remain required.
Unit controls cover partial/failed reads, cancellation, changing input, duplicate
identities, limits, unknown ownership and output containment. Durable transactions,
compression encoding and filesystem writes retain their later phase gates.
Namespace edits are qualified by the following increment.

## Ordered workspace tree editing increment

A batch can create directories/files/symlinks, create regular-file hard links,
rename or move entries, remove files/empty directories and replace contents.
Later operations resolve against earlier edits; the final workspace is captured
once. Native filename spelling/comparison, rename replacement, same-inode rename,
cycle rejection, external aliases and source metadata retention are explicit.
New objects require supplied metadata and initial attribute/fork values. Native
process-added provenance is captured as an explicit input, never synthesized by Go.

The `tree-edits` acceptance family uses 18 initial entries and 21 final entries
per filesystem. Eighteen native operations cover an application-style update,
linked source and created files, overwritten targets with surviving aliases,
case-only renames, moving a populated directory, empty-directory replacement,
symlink creation and compressed-file replacement after a move. Eight native
rejections and six ASCII/BMP/supplementary-character name probes establish error
and filename boundary behavior. HFS+ spelling is observed after decomposition.

Native before/after images and supplied creation metadata/attributes are recorded
on macOS 15/26/27. Each portable host returns actual baseline/edited workspaces.
Independent Python verification on each required Mac compares 36 workspace pairs,
756 final entries and 648 native operations, preserving source and supplied
creation timestamps by documented policy. Existing preservation/AppleDouble and
all other native families remain required. The retained comparison takes about
three seconds locally; cases share the existing capture and verification paths.

Focused controls cover later-batch failure, short reads, failed attributes,
cancellation, closed owners, duplicate replacement aliases, symlink traversal,
subtree link counts and byte-identical output for identical inputs. New identities
are workspace creation digests, visibly separate from captured native identities.
Schema 3 retains creation/link-change markers through subsequent editing and
subtree extraction. General host import and filesystem-image creation remain
separate work. This completes the scoped logical tree-editing increment.

## Workspace metadata editing increment

Partial metadata patches and individual extended-attribute changes now compose
with tree and content edits. A complete resource-fork replacement operation
truncates old bytes and treats empty forks as absent, following native named-fork
writes. FinderInfo has explicit length, public-value and hidden-flag behavior.
The shared pinned Apple HFS helper supplies reserved-field masking. Unsupported
compression/security changes fail before publication. Source timestamps remain
recorded except where the caller explicitly supplies an admitted timestamp.
Schema 4 records cumulative changed fields and attributes with source identity.

One `metadata-edits` family supplies 29 native operations and seven rejection
controls on each of four filesystem profiles. It checks mode, UID/GID, exact
birth/modification/access precision, ordinary and empty attributes, FinderInfo,
fork shrink/removal, hard-link aliases and symlinks. The batch includes a rename,
an added alias and compressed-file replacement followed by independent fork
creation. Timestamp assignments follow writable-mount attribute observations,
which can themselves update HFS+ access time.

Fresh captures on macOS 15/26/27 require actual UID/GID reassignment using sudo on
disposable image files. The retained local macOS 27 corpus records same-owner
assignment because the local account has no passwordless sudo; it does not supply
that ownership-change gate. All three portable hosts replay all native producers.
Each Mac independently checks 36 workspace pairs, 612 final entries and 1044 native
operations without invoking Go. The focused retained replay takes about two
seconds. Existing native families and independent output verification remain required.

Unit controls cover unspecified metadata, explicit zero, invalid patches, unsafe
compression/security changes, source lifetime and failures, cancellation, ordered
attribute overlays, deterministic output and provenance through later extraction.
General directory import and deterministic image construction follow this work.

## File-command sessions increment

Named sessions expose `cp`, `chmod`, `chown`, `chflags`, `touch`, `mkdir`, `mv`,
`rm`, `ln` and `xattr` with ordinary operands and flags. Scratch storage is managed;
users do not supply JSON edits or a portable metadata layout. Session create/open,
status, verify, export and remove are explicit lifecycle operations. Host import
records unavailable fields and supplied defaults. Export remains the existing
preservation format; image construction is the next separate gate.

The existing tree engine is shared with preservation batches. Sessions capture
sources once, lock across processes, stream immutable content-addressed blobs and
publish one metadata revision per successful command. Failed commands keep the
previous revision. Restart discards staging and reclaims unreachable blobs. This
qualifies process interruption, not power-loss durability or APFS transactions.

Apple libc's pinned `setmode`/`getmode` grammar is translated to Go with an explicit
logical umask. Native libc supplies 390 comparison vectors. A single `file-commands`
acceptance family runs 23 Apple commands and five rejection controls on four
filesystem profiles. Separate CLI processes replay the journey, including an app
copy, host inputs, aliases, metadata, forks and removal; independent Python checks
all exported values. Native mounts use `noatime`, matching session read behavior.
Command clocks normalize to one supplied instant, retaining each format's precision.
Copied security provenance remains exact; runner-injected provenance on newly
created objects is recorded separately from portable command semantics.

Retained macOS 27 local evidence and macOS 15 CI evidence pass local replay and
independent output readback. The latter records actual ownership reassignment,
including recursive chown of physical symlinks. Fresh macOS 15/26/27 capture,
Linux/Windows/macOS replay and independent verification remain mandatory PR gates. Usage, supported flags, default provenance
and deferred behavior are in [the session contract](sessions.md).
The command increment passed the complete native capture, portable replay and
independent output matrix in [PR #19's compatibility run](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/38040323305).

## Fresh HFS+/HFSX image-building increment

`pack` consumes named sessions or imports directory contents through managed
scratch. Apple’s pinned `makehfs` volume/header/map setup is adapted into bounded
Go construction, with catalog, attributes, private-directory file links and
contiguous extents. The single-volume profile is clean and nonjournaled. UDRO and
UDZO encoding use one independent streaming layer with fixed 4 MiB chunks and
native CRC fields. Output is published only after successful flush/close, without
replacing existing paths. The [packing contract](packing.md) specifies preservation,
capacity, reproducibility, limits, native identities and failure behavior.

One `image-building` family independently captures HFS+/HFSX source trees and a
signed universal app. Linux, Windows and macOS build both encodings twice from
every producer. Every output returns to every Mac for image checks, fsck without
repair, exact mounted metadata/fork/link readback and signature verification.
Same-input outputs must be byte-identical across hosts. Local native qualification
uses macOS 27; the full macOS 15/26/27 capture, portable build and native readback
matrix passed in [PR #20](https://github.com/deploymenttheory/go-apfs-v3/pull/20).

APFS creation, journaled/in-place writes, new decmpfs encoding, encryption writing,
snapshot mutation and volume-group construction retain separate gates.

## Sector-preserving image repacking increment

`pack IMAGE NEW_DMG` encodes the complete decoded disk as UDRO or UDZO. Source
partition maps, every volume, allocation, retained snapshots, encrypted APFS
sectors and recorded unallocated bytes survive exactly. It uses no filesystem
builder, session or raw scratch image. The same bounded UDIF encoder handles
fresh HFS builds and ordered source block ranges; the same publication helper
flushes and closes staging before refusing-overwrite publication.

Repacking admits complete raw GPT/APM or recognizable bare APFS/HFS+ disks and
the documented flattened XML UDIF profile. It verifies every present data/block/
master CRC and complete run coverage before encoding. Unknown resources, extended
footers, encrypted DMG envelopes and container signatures fail explicitly. The
native empty `plst` placeholder and source block labels/IDs/ranges are retained.
A before/during decoded-disk hash detects changed input under an immutable-source
contract. See [packing semantics](packing.md#repacking-an-existing-image).

One `image-repacking` family reuses signed-app and snapshot references from the
existing independent native families. New native cases cover bare HFS+, HFSX on
APM with an explicit free partition and a sentinel sector, and a sufficiently
large APFS container with ordinary and encrypted volumes. Raw, UDRO, UDZO and
UDBZ sources produce both output encodings twice on every portable host. Native
signed and encrypted DMG inputs are refusal controls and must leave no output.
The local macOS 27 positive replay takes approximately seven seconds.

Each macOS verifier checks all 90 portable outputs using Apple image verification,
raw-device disk hashes, partition/volume inventories, read-only mounted file and
raw-attribute observations, retained snapshot mounts, encrypted-volume unlocks,
filesystem checks and signature verification. Outputs for the same input/options
must be byte-identical across hosts. Sources and native observations remain
immutable; no Go decoder supplies the final native verdict. Fresh macOS 15/26/27
capture, Linux/Windows/macOS replay and every native readback are required.

Filesystem rebuilding, APFS construction, encrypted DMG writing, container signing,
new filesystem compression and existing-image mutation retain separate gates.
PR #21 passed the complete [native compatibility matrix](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/38067713304).

## Fresh APFS image-building increment

`pack --filesystem apfs DIRECTORY NEW_DMG` and packing an APFS session now build
one unencrypted APFS volume in a fresh container. Case-sensitive APFS, empty
inputs, explicit capacity/clock and derived or supplied container/volume UUIDs use
the same command and managed scratch policy. APFS construction owns its checkpoint,
object maps, bulk-loaded filesystem/extent-reference trees, sibling/document IDs,
space manager, allocation bitmaps and free queues. `pack.VolumeOptions` selects
neither filesystem conversion nor a second editor: the source reader selects the
engine. The shared encoder records Apple's APFS content hint in UDRO/UDZO output.

Planning bounds names, metadata, trees and capacity before hashing streamed data.
Write checks each payload hash again. Metadata, nanosecond times, symlinks, hard
links, attributes, forks and qualified existing compression survive; native IDs
and allocation are newly assigned. Snapshot histories, clone extent sharing,
multiple volumes/groups, encrypted construction and existing-filesystem edits
remain separate increments. Sparse data retains its logical bytes with fresh
contiguous allocation. The full profile is in [packing semantics](packing.md).

The existing `image-building` family expands to four native filesystem profiles,
using its original capture/replay/readback paths. APFS adds exact birth nanoseconds,
tracked documents, 53 native filename lookup results and an empty-directory root.
Every portable host builds both populated encodings twice and one empty APFS UDZO
twice. Every Mac independently checks all 81 images, compares same-input host
hashes, checks filesystem health without repair, observes exact files/metadata and
verifies application signatures. Every APFS output additionally undergoes native
growth, hard linking, rename, deletion, tree growth and allocation reuse on a
disposable shadow, then fsck and remount/readback. Original image hashes remain
unchanged. This proves native continued use, not Go mutation or crash durability.

The retained macOS 27 capture and local native output checks pass. The earlier
HFS-only capture remains immutable under `acceptance/testdata/image-building/history`.
Fresh macOS 15/26/27 capture, Linux/Windows/macOS replay and native verification
are required before merging this increment. The readback job has a 15-minute
ceiling to accommodate actual native allocation checks; no new scenario family
or workflow is introduced.

## Multiple-volume APFS construction increment

The single-volume builder now delegates to one container engine. `PlanContainer`
accepts ordered immutable readers, per-volume identity/case/role/reserve/quota
options and explicit System/Data pairs. `pack --volume NAME` opens a scoped
clause with a session, host directory or empty input. Scratch remains managed;
ordinary file commands still perform edits. No input JSON configuration is used.

One shared allocation pool accounts for all volume metadata, payloads and unused
reservations. Automatic sizing includes Apple's volume-slot rule and the space
manager's own overhead. The shared 64 MiB metadata budget, 1 TiB capacity bound,
payload verification and no-overwrite publication contract apply to the entire
container. Source volumes and existing images remain unchanged. Group identity
does not imply a bootable, sealed macOS installation or firmlink construction.

Two native cases extend `image-building`: mixed case policies/reserve/quota/empty
volume, and a System/Data pair. They carry signed applications, raw compression,
resource forks, aliases, metadata, native group inventories and space-pressure
observations. Every host builds both encodings twice. Every macOS verifier first
requires byte equality across hosts, then checks the 39 distinct images instead
of mounting all 117 identical host copies. Quota exhaustion, reserve protection,
independent volume writes, allocation reuse and remounts are required verdicts.

The initial System allocator used a v2-derived inode base that passed fsck but
panicked Apple's kernel. The corrected base matches SYSTEM_OBJ_ID_MARK and
Apple-created allocator state. Namespace comparison is now independent of the
usual inode bijection. See the [incident record](native-testing-incident.md).
Native testing on a development Mac is blocked by default. The existing macOS
15/26/27 CI labels were verified as GitHub-hosted disposable VMs; jobs assert
that environment before native operations. Qualification must pass there before
this increment can be merged. Local tests perform file-only Go replay.

## Encrypted DMG construction and repacking increment

Fresh AES-128/256 image encryption wraps the shared UDRO/UDZO encoder. Directory,
session and multi-volume builds use the same output options. Image inputs use
`--image-password-file` separately from `--output-password-file`; an explicit
`--encryption AES-128|AES-256|none` policy controls replacement or removal. The
source remains immutable and the new destination is published without overwrite.
No literal password option or JSON input configuration is introduced.

The writer uses Apple's observed password-only v2 envelope and AES-192 wrapping
profile. It streams ciphertext without a plaintext image temporary file and
uses fresh cryptographic randomness for every image. Plaintext build bytes stay
reproducible; encrypted bytes must differ. Unknown encryption credentials/header
resources and unsupported inner UDIF resources remain refusal cases. APFS
volume-key creation and mutation remain separate work.

The existing `image-building` and `image-repacking` families qualify both cipher
sizes and encodings, all four filesystem profiles, System/Data groups, retained
snapshots, opaque APFS encryption, signed apps, password replacement, explicit
decryption and Apple's encrypted raw-disk input. Each Mac decrypts every distinct
ciphertext independently and compares complete native device hashes to already
qualified plaintext disks. Old and wrong passwords must fail. Plaintext host
copies first have to agree byte-for-byte, so the native repacking verifier checks
one of each identical triple instead of repeating the same native work three
times. All native operations remain confined to disposable hosted VMs.

[PR #24](https://github.com/deploymenttheory/go-apfs-v3/pull/24) tracks this increment.
Its complete macOS 15/26/27 capture, Linux/Windows/macOS replay and native output
readback matrix must pass before it is ready to merge. Focused failure tests and
race checks supplement that independent evidence; Go roundtrips alone do not
qualify the format. PBKDF2 uses Go’s constant-time bulk XOR to reduce repeated
byte-loop overhead, with the same derivation, iteration count and cancellation
checks. A focused benchmark records the password-work cost.

## Required phase gates

1. Independent native fixtures/observations, readable portable comparisons, and
   every required macOS producer and Linux/Windows consumer in CI.
2. Native-produced images read identically on all hosts, including metadata and
   forks; malformed input and unsupported features fail explicitly.
3. Extract/edit/rebuild retains all untouched values and relationships. Host
   limits produce preservation outcomes rather than silent loss.
4. Native checkers and mounted readback accept every host's output. Controlled
   inputs produce byte-identical deterministic builds.
5. Repeated native/Go edits and fault-injected writes satisfy the documented
   durability contract, including interrupted commit, disk-full and flush errors.
6. macOS recognizes and can continue modifying snapshots, clones, and encrypted
   output. Snapshot deletion preserves retained states and allocation accounting.
7. Mounted workloads retain identity, links, attributes, forks, and durable writes
   under concurrency and remounts. Drivers remain optional dependencies.
8. Seeded deletions recover with provenance; packaging and downstream signing
   journeys pass native verification on macOS 15, 26, and 27.

## Rules

- Tie every capability to a user operation, authoritative source, and independent
  acceptance result. Pin translated files/revisions and retain their licenses.
- Use Apple names for format structures and idiomatic Go ownership and I/O.
- Keep native capture independent of Go results. Existing observations are
  immutable; code changes are not a reason to regenerate expected results.
- Grow CI by scenario family, not workflow-per-regression. Coverage is diagnostic;
  do not inherit v2's per-file percentage gates. Release checks bind the candidate.
- Unknown cases must not become empty directories, zero-filled file content,
  fallback checkpoints, or successful skips.
- Full macOS process-authorization emulation, signing algorithms, notarization,
  installer-package formats, and bootable sealed-system construction are outside
  this library. Preserve their metadata without claiming their behavior.
