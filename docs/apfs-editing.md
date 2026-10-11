# Editing existing APFS files

`cp --image` and `chmod --image` edit existing records in a private decoded disk
copy. A completed UDRO/UDZO image is published without overwriting a destination.
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

## Admitted profile

The first increment handles one unencrypted, unsealed, ordinary APFS volume in a
single-device container. It supports case-sensitive and case-insensitive native
names, ordinary regular-file hard links, attributes, data and resource forks,
and active decmpfs replacement. Containers are bounded to 1 GiB, 4096-byte blocks,
contiguous checkpoint regions, inline CIB addresses and one internal-pool bitmap.
Every current and pending-free block must have validated ownership.

Snapshot-bearing volumes, clone history/shared streams, System/Data roles,
reserves/quotas, Fusion, encrypted image envelopes/volumes, pending reapers and
unrecognized write profiles are refused before disk staging. New-file creation,
`mkdir`, `mv`, `rm`, directory permission changes and symlink traversal belong to
later increments. Immutable, append-only and protected target objects are refused.
These limits apply to existing-image editing, not to the broader readers or fresh
construction capabilities.

Data replacement retains the existing inode and every hard-link alias. Independent
resource forks and unrelated attributes remain intact. Replacing active compressed
data removes its decmpfs storage and writes ordinary logical bytes; a compression
format that owns resource storage releases that storage. A separate independent
fork is retained for attribute-only compression. Explicit resource-fork replacement
on an actively compressed file is refused. Untouched applications retain their
signature bytes; changing signed application contents requires subsequent signing.
Birth/access times, ownership and unrelated metadata are preserved. Changed data
and forks receive the requested mtime/ctime; chmod changes ctime only.

## Transaction machinery

`apfs/mutate_tree.go` loads bounded, validated trees and copies changed paths.
Physical node identifiers follow new addresses; virtual identifiers remain stable.
Construction and editing share the node encoder in `apfs/build_tree.go`.

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
