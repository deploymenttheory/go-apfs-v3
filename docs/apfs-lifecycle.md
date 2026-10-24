# APFS history, sharing and software encryption

The [lifecycle tracker](https://github.com/deploymenttheory/go-apfs-v3/issues/56)
extends the qualified offline editor. The intended operations are ordinary copy
commands with explicit clone intent, snapshot create/rename/delete/revert,
authenticated encrypted edits, password changes, encrypted construction and
completed encryption/decryption conversion. Linux and Windows must be able to
read every completed result immediately.

Existing readers can open native clones, retained snapshots and admitted software
encryption. Ordinary mutation admits qualified plaintext clones and live edits
with retained snapshots, and still refuses software-encrypted volume writes.
Read-only storage accounting
understands admitted plaintext clones and retained history. Ordinary mutation
uses the same accountant, with separate admission checks for each writer profile.

Live edits retain the object-map versions selected by every historical XID and
protect historical metadata and stream extents independently of recoverable
container checkpoints. The live physical-extent tree records its reference
deltas against the newest immutable snapshot; a live unlink cannot release
blocks still owned by an older history. Repeated replacements, resource-fork
and attribute edits, and temporary allocation must leave all historical reads
and snapshot identities unchanged. The public image editor retains its immutable
source and completed, no-overwrite publication contract on failure.

## Dependencies and completion

| Work | Prerequisite | Tracking |
| --- | --- | --- |
| Independent native controls and source inventory | Qualified offline editing | [Native controls](https://github.com/deploymenttheory/go-apfs-v3/issues/57) |
| Retained-version and shared-storage accounting | Native controls | [Storage ownership](https://github.com/deploymenttheory/go-apfs-v3/issues/58) |
| Safe edits to existing clones | Storage ownership | [Clone editing](https://github.com/deploymenttheory/go-apfs-v3/issues/59) |
| `cp -c` in existing images | Clone editing | [Clone copy](https://github.com/deploymenttheory/go-apfs-v3/issues/60) |
| Session sharing and actual clones in packed images | Clone copy | [Sessions and packing](https://github.com/deploymenttheory/go-apfs-v3/issues/61) |
| Live edits preserving retained snapshots | Storage ownership and clone editing | [Historical preservation](https://github.com/deploymenttheory/go-apfs-v3/issues/62) |
| Snapshot creation and rename | Historical preservation | [Creation and names](https://github.com/deploymenttheory/go-apfs-v3/issues/63) |
| Snapshot deletion and final-reference reclamation | Snapshot creation | [Deletion](https://github.com/deploymenttheory/go-apfs-v3/issues/64) |
| Completed snapshot revert | Snapshot deletion | [Revert](https://github.com/deploymenttheory/go-apfs-v3/issues/65) |
| Existing-image edits inside encrypted DMGs | Native controls | [Encrypted envelopes](https://github.com/deploymenttheory/go-apfs-v3/issues/66) |
| Software-encrypted APFS edits and password changes | Revert and encrypted envelopes | [Authenticated mutation](https://github.com/deploymenttheory/go-apfs-v3/issues/67) |
| New software-encrypted volumes | Session sharing and authenticated mutation | [Encrypted construction](https://github.com/deploymenttheory/go-apfs-v3/issues/68) |
| Existing-volume encryption/decryption conversion | Revert, authenticated mutation and encrypted construction | [Conversion](https://github.com/deploymenttheory/go-apfs-v3/issues/69) |
| Combined lifecycle and fault qualification | All implementations | [Combined qualification](https://github.com/deploymenttheory/go-apfs-v3/issues/70) |
| Permanent source/output/verdict bindings | Combined qualification | [Evidence](https://github.com/deploymenttheory/go-apfs-v3/issues/71) |
| Documentation and completion audit | Permanent evidence | [Closure](https://github.com/deploymenttheory/go-apfs-v3/issues/72) |

Each implementation adds its own independent native capture, portable replay and
Apple checker/readback/continued-write requirements. Combined qualification adds
cross-capability scenarios; it does not postpone individual compatibility gates.
Issues remain open until their stated requirements are actually satisfied.

## Source basis

[Apple's APFS reference](https://developer.apple.com/support/apple-file-system/Apple-File-System-Reference.pdf)
describes stream references, physical extent references, retained object-map
versions, snapshot metadata/name records and encryption state. In particular,
creating a snapshot moves the current extent-reference tree into the snapshot
and starts an empty live tree. Revert fields request work during a later native
mount; a portable writer must instead publish a completely reverted state.

Pinned [Apple cp C](https://github.com/apple-oss-distributions/file_cmds/blob/659a8a301e2acf0343f8b8673a154a2ca4d07084/cp/utils.c)
calls `clonefileat` for `-c`, removes an existing destination before the clone
attempt, and falls back to copying only for `EXDEV` or `ENOTSUP`. That differs
from ordinary destination truncation. Recursive and preservation options must
compose with those decisions. The separate
[copyfile API](https://github.com/apple-oss-distributions/copyfile/blob/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile.3)
also has best-effort and forced clone flags, optional ACL copying and an explicit
cloned-state observation. Equal bytes alone cannot establish shared storage.

The installed macOS 15 `cp -c` instead rejects a cross-volume `EXDEV` with no
destination. The captured macOS 26 and 27 tools perform the fallback. Older
[Apple cp source](https://github.com/apple-oss-distributions/file_cmds/blob/35ca7d4a702664134a55f1ff6b54188ee48e1177/cp/utils.c)
falls back only for `ENOTSUP`, explaining the older outcome. Each source version
retains its actual command result and destination observation. A separate peer
file supplies preservation controls; no ordinary copy overwrites the refusal.

The pinned [XNU snapshot dispatcher](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/vfs/vfs_syscalls.c)
checks snapshot entitlements before create/rename/delete/revert syscalls, even
for root. Its rename path refuses an existing name with `EEXIST`. Public C source
establishes these API rules; it does not supply the private APFS implementation.
ASR snapshot retention, Apple inventory and native mounts remain the independently
qualified creation/reading control. The new control also invokes the supported
name-based create, rename and revert APIs using the developer snapshot entitlement.
API availability is observed independently on each required OS. A refusal leaves
the corresponding positive control blocked; ASR names alone do not qualify
arbitrary Unicode names or successful native rename.

Software volume encryption and DMG envelope encryption are separate. Current
APFS keybag admission unwraps a 32-byte combined XTS key, corresponding to
AES-128-XTS; the AES-256-XTS primitive alone does not establish a native volume
profile. Future encrypted construction uses secure randomness. Passwords travel
through the existing exact-byte file/stdin interfaces and stay out of production
logs, fingerprints and manifests. The native controls use explicitly public
fixture passwords, as the existing encryption families do.

Native conversion controls exposed a reader admission error: a completed
`diskutil apfs encryptVolume` sets `APFS_INCOMPAT_ENC_ROLLED` (0x4), which the
original reader mask rejected. Apple's reference defines this as past key changes;
`apfs_er_state_oid` separately identifies a conversion still in progress. The
reader now decodes and reports that state OID, refuses unfinished transitions,
and admits the historical flag for completed reads. Writer admission retains its
existing separate qualification requirements. Full native observation replay
must qualify the completed encrypted and decrypted states.

## Native control family

`acceptance/native/apfs_lifecycle.py` extends the existing compatibility workflow,
without adding profile jobs or another capture mode. Its current controls are:

- Both APFS name policies: native `cp -c`, independent inode identity, data and
  resource-fork physical sharing through Darwin `F_LOG2PHYS_EXT`, ordinary-copy
  nonsharing, replacement of an existing hard-link destination, cross-volume
  fallback, independent data/fork/metadata writes, truncation and owner removal.
- Settled native encryption and decryption, changed-password rejection/acceptance,
  encrypted clone writes, a plaintext peer and a newly created independently
  credentialed encrypted peer. Every completed state is detached, retained,
  reattached read-only, natively checked and observed. Migration probes must show
  an explicitly settled state before the completed reference is published.
- Both snapshot name policies: supported name-based create/rename/revert API
  observations, original ASR history, final selected-history preservation and
  subsequent native allocation. Successful APIs must produce observed Unicode
  names and completed revert. An explicit `EPERM` instead retains unchanged
  live/historical observations, a separately labelled positive native deletion
  control, and the [unresolved positive-control blocker](https://github.com/deploymenttheory/go-apfs-v3/issues/74).
  An unavailable revert never receives a `reverted` image label. Original parent
  image bytes and digests remain unchanged.

The installed utility's `-R` implementation passes its argument as the path to
`fsctl(APFSIOC_REVERT_TO_SNAPSHOT)` with XID zero. The public XNU revert fallback
applies the same request internally to a selected snapshot vnode. Supplying a
snapshot-name string as the utility manual suggests produced `ENOENT`; a
snapshot mount path with its zero-XID argument produced `EINVAL` on all three
required versions. The nonzero-XID helper also returned `EINVAL` on macOS 27.
The pinned XNU `fsctl_internal` dispatcher explicitly rejects this request before
calling APFS; changing its argument cannot fix that refusal. A kernel-internal
ioctl constant does not establish a supported userspace XID interface. The
supported name-based snapshot syscall has a separate entitlement check. These
failed attempts remain diagnostic evidence, not completed native controls.

`apfs_snapshot.c` now calls the SDK's `fs_snapshot_create`, `fs_snapshot_rename`
and `fs_snapshot_revert` interfaces. The collector signs this bounded observer
with `com.apple.developer.vfs.snapshot`, retains the entitlement source and the
signed binary's digest, and records its displayed entitlements. This does not
claim an Apple-provisioned identity or change runner security settings. The
retained macOS 15, 26 and 27 controls all killed the developer-entitled observer
with `SIGKILL` and returned `EPERM` through the baseline observer's supported APIs.
A launch probe now records that result before filesystem work. If the entitled
binary is killed, a separately retained baseline binary from the same source
must launch normally and observe the APIs without claiming that entitlement.
Both binary digests and the positive-control blocker are retained. Its output
separates successful observation from the actual syscall status/errno;
only `(0, 0)` is successful mutation. A valid observed `(-1, EPERM)` is explicit
unavailability linked to the blocker. Other errors, malformed results,
unexpected launch failures or incomplete observations fail capture. The affected mutation tickets
remain open until their positive controls are available and qualified.

The Go acceptance family checks each native state on Linux, Windows and macOS:
volume identity, name policy, locked/unlocked credentials, files, links, forks,
attributes, metadata and every retained historical view. Fresh controls come from
macOS 26 and 27. Missing supported evidence fails rather than becoming a skip.

The collector and its C storage observer require `GITHUB_ACTIONS=true` and
`RUNNER_ENVIRONMENT=github-hosted` before opening files or invoking native tools.
Local checks use ordinary-file Go replay and mocked orchestration only. A disk
image does not isolate a working Mac's kernel.

Original controls from
[native run 38699211349](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/38699211349)
are retained in `acceptance/testdata/apfs-lifecycle`: 24 states per source OS,
original source/tool identity, command observations, independent parent history
and GitHub artifact digests. Original manifests are stored verbatim in gzip;
small retention receipts expose the cases without rewriting native values.
All 72 states passed ordinary-file Go replay during that qualification. The
current required workflow replays supported producer sources on Linux, Windows
and macOS to establish portable qualification; original macOS 15 controls remain
archived outside mandatory replay. Source review and mocked tests do not supply a native verdict.
Conversion of retained encrypted history and successful arbitrary snapshot naming
have their own required controls in the corresponding implementation tickets.

## Storage ownership and reclamation

`apfs.InspectStorage(ctx, source)` reads an APFS partition without writing. For the
bounded plaintext profile it reconciles every live volume and retained snapshot,
their transaction-selected filesystem trees, all stored object-map versions,
data and attribute streams, physical extent references, volume allocation
counters, and the main-device/internal-pool allocation maps. A corrupt count,
unexplained allocation, cross-link, unsupported feature, active reaper or budget
exhaustion returns an error and no successful report. Encryption and unfinished
conversion remain explicit unsupported accounting profiles.

A shared data stream has one physical extent set even when several clone inodes
refer to it. Hard-link directory aliases do not add stream owners. Independent
resource-fork streams can instead share physical ranges. Physical extent counts
are signed: each retained snapshot contributes its chronological NEW/UPDATE tree,
and a zero current count cannot erase an older view's ownership. The original
physical `owning_obj_id` can outlive its inode, so general ownership does not
require that hint to resolve to a current inode. Plaintext clone mutation uses
these reconciled counts to split and decrement shared physical ranges, retaining
surviving references and retiring storage only when its final reference is gone.

Native sparse inodes include sparse bytes in their stream allocation field.
The explicit sparse-byte field and logical extent coverage must reconcile before
subtracting holes; no physical blocks are invented for that allocation surplus.
Single-owner attribute streams can omit `DSTREAM_ID`; shared streams require an
explicit matching count. Empty native reaper-list pages contain stale free-entry
bytes, which are not active owners. Nonempty lists and active reaping are refused.

The report separates bitmap `FreeBlocks`, main-device `PendingFreeBlocks` and
`ProtectedBlocks`. Apple's `diskutil` available capacity includes deferred frees;
it equals `(FreeBlocks + PendingFreeBlocks) * BlockSize` in all retained plaintext
controls. Deferred blocks are still allocated and are never automatically safe
to overwrite. `RetainedCheckpoints` counts structurally complete descriptor/map
sequences, not healthy historical filesystems. Their transaction bounds
conservatively protect deferred ranges, exposed as `CheckpointProtectedBlocks`.
No historical bitmap authorizes allocation in the selected transaction.

Before the ordinary writer's first allocation/write, it disables older checkpoint
descriptors in the unpublished scratch copy and then reclaims eligible deferred
ranges. Current/historical root protection is checked independently of queue age.
The selected checkpoint, its maps/data and its allocations survive until the new
checkpoint is published. No-op commands do not retire checkpoints or write bytes.
Object-map pruning can retain each historical view's predecessor mapping, including
deletion placeholders; the current ordinary writer admits no such extra views.
This is file-backed scratch-copy recovery, not a claim of in-place power-loss
atomicity or writable snapshot support. Existing plaintext clone editing uses
the same scratch-copy transaction; see [clone editing](apfs-editing.md#editing-existing-clones).

## Sessions and fresh clone construction

Sessions record explicit clone lineage for each raw data stream and attribute,
separately from inode identity, hard-link aliases and content-addressed blobs.
Only the changed stream detaches during data, fork or attribute replacement.
Metadata remains independent, and removing or renaming the original owner does
not break surviving members. Private revision schema 2 retains those groups
across reopen while continuing to read older sessions.

Fresh APFS construction translates whole-stream groups into actual stream and
physical reference records. Data clones share a stream ID; distinct attribute
stream IDs can share physical extents. Hard-link aliases add no stream owner.
All members are checked, including a member whose bytes are not separately
written to the output. Independent equal bytes never create a group. New
allocation addresses are deterministic construction choices rather than retained
native physical addresses.

Native session capture inventories exact physical mappings once per subtree.
It uses actual stream descriptors, including the distinction between an owned
data stream and a descriptor-less private-ID hint. Exact complete shared maps
become opaque source-scoped identities. Differing maps with physical overlap are
recorded as partially shared streams. APFS packing explicitly refuses those
markers before payload reads or output; its current model does not represent
shared subranges. Metadata edits preserve the marker, and replacing the complete
marked stream removes only that marker.

Packing reports actual shared storage, embedded/empty-stream copies and explicit
HFS independent-copy fallback. Compression changes derive representation
identities only from declared lineage. Snapshot preservation and software volume
encryption retain their separate admission gates; a fresh image is not a retained
history or encryption conversion. The `clone-copy` family supplies independent
Apple copy and fallback states for reopened-session packing, followed by native
checker, mounted readback and continued modification on all required kernels.

Tree/mapping traversal is bounded by 16,000 object reads and 1,048,576 records,
alongside the existing checkpoint, space-manager, 4,096-snapshot and 64 MiB
allocation-bitmap limits. Extent sweeps use interval
boundaries rather than a per-block owner map, and payload bytes are not read.
The existing lifecycle acceptance family compares all 108 retained plaintext
views and Apple's capacity observations on every portable host. Negative controls
alter native reference counts, retained mappings, sparse fields and unknown
profiles with repaired checksums. Existing ordinary-edit, allocation-pressure,
checkpoint interruption and native continued-write gates remain required through
the same capture → portable replay → Apple verification workflow.
