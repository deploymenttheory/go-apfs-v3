# Editing existing APFS filesystems

`cp`, `chmod`, `mkdir`, `mv`, `rm`, `chown`, `touch`, `chflags` and `xattr` with `--image` edit existing records
in a private decoded disk copy. A completed UDRO/UDZO image is published without overwriting a destination.
The source remains read-only; scratch is managed internally.

```sh
apfs cp --image Original.dmg --output Edited.dmg --from-host ./replacement /Payload/file
apfs chmod --image Edited.dmg --output Executable.dmg u=rwx,go=rx /Payload/file
apfs cp --image Edited.dmg --output Fork.dmg --from-host --resource-fork ./fork /Payload/file
```

For a partitioned source, specify `--partition INDEX`. `--time RFC3339` supplies
an explicit whole-second modification clock; fixing that clock makes identical
source bytes and operations produce byte-identical plaintext output across hosts.
`--format UDRO|UDZO` controls the output DMG encoding.

Several ordinary commands can share one managed copy and publish once:

```sh
apfs edit --image Original.dmg --output Edited.dmg --time 2025-06-07T08:09:10Z -- \
  mkdir -p /Payload/Resources \
  --next cp --from-host ./asset /Payload/Resources \
  --next chmod 0755 /Payload/Resources/asset
```

`--next` separates commands; each keeps its normal arguments and flags. Image,
volume, partition, output format and operation time belong to the enclosing
`edit` command. Later commands see earlier changes. A failed command discards the
whole unpublished copy. The library equivalent is `imageedit.Edit` with an
`Editor` callback; a failed editor cannot publish even if its caller ignores the
command's error. This edits existing structures rather than rebuilding a logical
session into a new filesystem.

## Admitted profile

The admitted write profile handles an unencrypted, unsealed, ordinary APFS volume in a
single-device container. It supports case-sensitive and case-insensitive native
names, ordinary regular-file hard links, attributes, data and resource forks,
and active decmpfs replacement. Select `--volume UUID` when a container has several
volumes; all ordinary volumes are accounted and untouched volumes retain their
original structures. Native reserves and quotas remain in force. Geometry uses
4096-byte blocks with a bounded allocation bitmap (64 MiB),
contiguous checkpoint regions, inline CIB addresses and one internal-pool bitmap.
Every current and pending-free block must have validated ownership.

Plaintext clone-bearing volumes are admitted when their stream and physical
reference counts reconcile. Shared data, resource forks and attribute streams
use copy-on-write; hard-link aliases retain their shared inode. Qualified retained
snapshots remain immutable while ordinary commands edit the live volume.
System/Data roles, Fusion, software-encrypted APFS volumes, active or nonempty
reapers and unrecognized write profiles are refused before disk staging. Tracked directories
retain their statistics and inheritance; protected filesystem-owned directories
remain outside user mutation.
Immutable, append-only and protected target objects are refused. Symlinks can be
moved or removed as entries; path traversal through symlinks is refused.
These limits apply to existing-image editing, not to the broader readers or fresh
construction capabilities.

Encrypted DMG envelopes are supported independently of APFS volume encryption.
Supply `--image-password-file FILE`; output retains the source AES strength and
password by default, using fresh random keys and salt. See
[encrypted image editing](encrypted-image-editing.md) for password replacement,
removal, stdin and the separate APFS volume credential boundary.

The larger and multiple-volume controls were independently qualified at
[run 38337086450](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/38337086450):
1.5 GiB ordinary containers and 768 MiB two-volume containers, both native name
policies, all three portable hosts, and Apple readback/continued writes on
macOS 15/26/27. The bitmap budget is a resource limit, not qualification of every
larger container shape. Subsequent editor/cache changes require the same gate.

Data replacement retains the existing inode and every hard-link alias. Independent
resource forks and unrelated attributes remain intact. Replacing active compressed
data removes its decmpfs storage and writes ordinary logical bytes; a compression
format that owns resource storage releases that storage. A separate independent
fork is retained for attribute-only compression. Explicit resource-fork replacement
on an actively compressed file is refused. Untouched applications retain their
signature bytes; changing signed application contents requires subsequent signing.
Birth/access times, ownership and unrelated metadata are preserved. Changed data
and forks receive the requested mtime/ctime; chmod changes ctime only. Numeric
chmod preserves ACLs. Set-ID writes require the explicit logical UID described
below; these metadata effects do not emulate process authorization.

## Creating and editing clones

Whole-file replacement and truncation detach only the edited clone's data stream.
Resource-fork and attribute changes preserve unaffected shared streams; metadata
changes retain existing sharing. Removing a hard-link alias retains its inode and
streams until its final name is removed. Removing a clone decrements stream and
physical references independently, and only the last physical reference retires
storage for later reuse. Original physical owner hints can outlive their inode;
validated reference counts determine reclamation. A compressed or empty inode
can retain a private stream ID without a data-stream descriptor. That ID alone
does not own storage: replacement creates a new stream, and unlink cannot
release a different inode's data through the retained ID.

`cp -c`, `imageedit.CopyOptions{Clone: true}` and the ordered editor create new
clone inodes in an admitted APFS image. A data stream retains its descriptor and
increments its inode-reference count. Fork and attribute streams receive
independent stream identities sharing the same physical ranges; physical
reference counts remain separate from data-stream descriptor counts. Clone
flags and a matching private stream ID never establish ownership by themselves.
An occupied destination entry is replaced, while its other hard-link aliases
retain the old inode. See [copy policy and fallback reports](image-copy.md).

Snapshot lifecycle operations and encrypted-volume mutation retain separate
admission limits.
Independent qualification requires the plaintext `apfs-clones` and `clone-copy`
controls, physical-sharing observations, Apple checks and subsequent native
clone writes on macOS 15/26/27. New native controls and generated outputs must
pass the required gates before the new copy path is considered qualified.

## File and directory operations

```sh
apfs mkdir --image Original.dmg --output Directories.dmg -p -m 0750 /Payload/Resources
apfs cp --image Directories.dmg --output Added.dmg --from-host ./asset /Payload/Resources
apfs chmod --image Added.dmg --output Mode.dmg u=rwx,g=rx,o= /Payload/Resources
apfs mv --image Mode.dmg --output Moved.dmg /Payload/Resources /Payload/Assets
apfs rm --image Moved.dmg --output Removed.dmg -r /Payload/obsolete
```

`cp` creates a missing ordinary regular file or replaces existing logical contents.
A directory destination uses the host basename. Resource-fork replacement requires
an existing regular file. `cp -n` and `mv -n` refuse existing destinations without
publishing output. Numeric and Apple symbolic modes use the shared mode parser.

New files default to 0644 and directories to 0755; intermediate `mkdir -p`
directories use 0755. Parent UID/GID and the supplied image clock determine new
metadata independently of host credentials and umask. `--uid N` supplies an
explicit logical creator/writer UID; new objects then use that UID and their
parent's GID, following Darwin creation behavior. Without `--uid`, the existing
parent-UID creation policy remains the compatibility default. All four new
timestamps use the supplied clock. Ordinary ACL inheritance follows Apple's
`kauth_acl_inherit`; parent set-ID mode bits do not propagate. Set-ID creation
and writes require an explicit logical UID. Root writes retain the bits;
other data writes and ordinary chown clear them. APFS truncation to empty contents
without a subsequent write retains set-ID bits. Ordinary cp restores the mode
captured after truncation, while `-p` applies source metadata. Numeric chmod preserves ACL bytes.
These effects model offline metadata, without authorizing a host process or
mapping stored GUIDs to host accounts. The retired offline editing regression (git history, superseded by
[#98](https://github.com/deploymenttheory/go-apfs-v3/issues/98)) recorded successful native qualification of this profile.
Existing `mkdir -p` paths are a no-op and keep their metadata.

`mv` preserves the inode, forks and attributes. An existing directory receives
the source basename. A replacement must match file/directory kind; a replaced
directory must be empty. Moving between equal hard-link inodes is a no-op.
Case-only changes preserve identity and use the volume's native comparison rules.
Moves update the named entry's date-added clock and the inode's ctime. Parent
child counts and parent mtime/ctime change coherently. Root and self-descendant
moves are refused. `rm -r`/`-R` is required for directories; `-f` ignores absent
entries. Moving/removing a symlink addresses the entry and never follows it.

Unlink updates the shared inode's link count and primary name/parent, removes the
named sibling-link/map pair, and retains the surviving sibling records even at
one link, matching Apple. Only final unlink retires the inode and every owned
stream/attribute. Filesystem-owned private and service directories are protected.

`apfs/mutate_entries.go` validates the complete directory parent graph, name hashes,
child counts, primary inode links and matching sibling entry/link/map inventory.
Its mutable index makes later operations see earlier edits in a batch. Both
construction and mutation use `apfs/build_records.go` for inode, directory and
sibling encoding. Physical extent references also share one encoder: attribute
streams retain the owning attribute record ID, independently of their stream ID.
A build/move/remove regression keeps Go-constructed resource forks editable.
Mutation paths use the existing APFS name bounds (255 UTF-16
units), at most 256 components, at most 2^20 indexed records and 4,096 operations.
The existing tree, checkpoint and free-queue capacity limits continue to apply.

## Transaction machinery

`apfs/mutate_tree.go` loads bounded, validated trees and copies changed paths.
Physical node identifiers follow new addresses; virtual identifiers remain stable.
Construction and editing share the node encoder in `apfs/build_tree.go`.

Ordinary opens, explicit checkpoint inspection/recovery and mutation admission
share mapping and stored-object validation in `apfs/checkpoint.go`. Recovery can
choose an earlier complete checkpoint only through an explicit operation that
reports the discarded newer candidates and validates the entire selected
filesystem. See [checkpoint recovery](apfs-checkpoint-recovery.md).

`apfs/mutate_space.go` validates device/chunk and internal-pool bitmaps, CIBs and
transaction-tagged free queues. New data and metadata are allocated from admitted
free space. Retired extents remain pending until they are older than the retained
selected checkpoint. Snapshot-free object maps discard superseded versions in the
new copy; the previous checkpoint keeps its own object-map tree.

`apfs/mutate_commit.go` writes copied objects, updates extent references and object
maps, versions the space manager and ephemeral free queues, and publishes a new
checkpoint followed by the block-zero copy. Older superseded descriptors are
retired in scratch. The previous selected checkpoint remains readable before new
checkpoint publication. This is an offline completed-output transaction: discard
scratch after any error. It does not qualify mounted in-place writes or physical
power-loss durability of a storage device.

## Independent evidence

The retained macOS 15/26/27 sources and native before/peak/final states were captured
in [run 38171484746](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/38171484746).
They remain immutable under `acceptance/testdata/apfs-editing`, with image hashes,
OS/tool provenance, exact capture sources and command diagnostics. Capture mounts
use `owners`; `noowners` can store UID 99 while mounted reads report a calling user.

Portable acceptance checks contents, all existing identities, hard links, modes,
timestamps, native-visible attributes, raw compression/fork storage, source hashes
and repeated-output hashes. Six source images replay locally using file reads only.
Fresh independent captures remain required in CI. Linux, Windows and macOS produce
actual edited images; each macOS version qualifies all output triples with Apple
fsck, exact raw-copy native readback, codesign, continued native allocation and a
further Go/native cycle. All native commands are restricted to disposable VMs.

Directory creation/move/unlink and removal/reuse references were captured in
[run 38177430983](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/38177430983)
and are retained separately under `acceptance/testdata/apfs-directory-editing`.
The exact capture sources and native command/tool/OS evidence accompany them.
Native captures retain siblings when the link count reaches one and qualify
primary-name/parent repair. The same required APFS pipeline refreshes both file
and directory controls; each native version checks all host output triples and
continued Go/native directory edits.

Record layouts and primary-link selection follow the
[Apple File System Reference](https://developer.apple.com/support/apple-file-system/Apple-File-System-Reference.pdf).
Apple's private APFS writer is not publicly available to port. These Go write
rules interpret the published format and are qualified by independent native
observations, rather than presented as a translation of private kernel C.

Ownership, clocks, flags and attributes use the same transaction engine; see
[existing-image metadata semantics](image-metadata.md) and native qualification.

`ln` adds original-inode aliases and literal symlinks through that same directory
index and transaction. See [link creation and lifecycle semantics](image-links.md).

## Directory statistics

Tracked directories retain exact primary-inode descendant counts, allocated
uncompressed data-fork bytes, group identities and chained origins. Resource
forks do not contribute to these byte totals, but writes to them invalidate the
containing group's generation. Moving an inherited directory across groups
promotes it to an origin; existing origins retain their identity through moves.
Hard links contribute through the primary inode, and final unlink retires storage.

Generation counters preserve the original native value and advance monotonically
when statistics change. They are invalidation tokens, rather than command or
extent counts: Apple kernels use different strides for the same truncation or
deletion. Unchanged generations remain unchanged, and overflow is refused.
Counts and byte totals are compared exactly with retained macOS 15/26/27 controls.
See Apple's [format reference](https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf)
and the independently captured [transition controls](sources.json).
