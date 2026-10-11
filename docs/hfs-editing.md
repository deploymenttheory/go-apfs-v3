# Editing existing HFS+/HFSX filesystems

This capability changes the original filesystem records in a new output image.
It retains volume identity, catalog file IDs, hard-link relationships, geometry,
unrelated metadata and unrelated disk sectors. It does not reformat the volume.

```sh
apfs cp --image Original.dmg --output Edited.dmg --from-host ./replacement.bin /Payload/file
apfs chmod --image Edited.dmg --output Executable.dmg 0755 /Payload/file
apfs cp --image Executable.dmg --output Forked.dmg --from-host --resource-fork ./fork.bin /Payload/file
```

`cp` replaces one existing regular file, including replacement with an empty
host file. A hard-link alias changes its shared inode. `chmod` accepts numeric
and Apple symbolic modes and several existing regular-file paths. Filename
lookup follows the volume's HFS+/HFSX rules on every host; symlinks are refused.
The source is always read-only and an existing output path is refused.
`--partition INDEX` selects one filesystem in a partitioned image; every other
partition and unused sector is retained. `--format UDRO|UDZO` chooses DMG
encoding independently of file storage. `--time RFC3339` sets an explicit
whole-second modification clock; the default is the current UTC second.
The CLI has no edit-recipe configuration file.

## Admitted profile and metadata

The first engine admits clean, nonjournaled, unlocked HFS+/HFSX volumes with
complete allocation-block geometry. It verifies both structural headers, all
allocation ownership, catalog/extent/attribute keys, node allocation maps and tree
reachability before writing. Unsupported or inconsistent state is refused.
Journaled/dirty volumes, expanded timestamps, content protection, directory hard
links, unaccounted allocations and unsupported storage are outside this profile.
Mutation is bounded to 2^27 allocation blocks, 2^18 tree nodes and 4,096 requested
operations. Metadata-file growth must stay within eight inline extents and the
existing node-map capacity; exceeding a bound fails without publishing output.

Replacement retains inode IDs, birth/access times, owner/group, destination
permissions, ordinary flags, FinderInfo and unrelated attributes. Data/fork
changes set modification and change times; chmod changes the mode and change
time. The volume modification time and write count advance once per transaction.
Immutable, append-only, locked and dataless targets are refused. Replacement of
set-ID files awaits a qualified credential policy. Chmod of a file
with stored ACL security is refused until the ACL interaction is qualified.
This offline policy does not emulate the executing host's macOS credentials.

Replacing actively compressed data removes its decmpfs attribute and flag and
frees compression-owned resource storage. Independent resource forks survive.
Replacing a fork used by active compression is refused; an inactive decmpfs
attribute remains opaque metadata. Empty independent forks have no allocated
storage. Untouched application signatures are retained; editing signed contents
requires the consumer's signing operation.

## Source translation

The pinned Apple HFS revision is
`d1bac2f062e6e9c0dfcce302d9aacb10173d0eea`. The source inventory gives the exact
C hashes and translated functions. Bitmap marking/accounting, extent grouping,
B-tree search, split propagation, empty-node removal, root collapse and node-map
allocation follow Apple's public write paths. Byte slices and private file
storage replace kernel buffers, locks and journal callbacks. First-fit runs and
byte-balanced splits supply deterministic offline allocation; optional kernel
allocation caches and sibling redistribution are omitted.

`hfsplus/mutate.go` coordinates admission, catalog patches, compression cleanup
and fork replacement. `mutate_allocation.go` accounts blocks and streams payloads;
`mutate_tree.go` changes original extent/attribute trees. `imageedit.Apply` owns
the complete input/scratch/output lifecycle. `block.Staging` creates regular-file
scratch; the shared completed-output publisher also serves pack/repack.

## Transaction and durability contract

The engine streams the complete decoded disk into private temporary storage,
using a 128 KiB payload buffer. Scratch is managed internally and consumes the
decoded disk size. Source CRC/resource admission precedes copying. The complete
allocation graph is checked again after mutation, scratch is flushed, and the
encoded output is flushed and closed before atomic no-overwrite publication.

Read failures, disk-full, short writes, flush failures and cancellation discard
the transaction. Abrupt process death before publication leaves the destination
absent and may leave only private scratch. A raced output entry survives.
Successful publication exposes a complete flushed image. This is a completed
output transaction, not in-place HFS journaling, journal replay, or a guarantee
that every host filesystem persists its directory entry through physical power
loss. Cleanup errors after publication can be reported with a complete output
already present. Physical power-loss qualification requires a separate gate.

## Independent acceptance

The existing-HFS-editing family is a bounded subworkflow of the required native
compatibility gate. Apple creates fragmented nonjournaled HFS+/HFSX volumes on
macOS 15, 26 and 27, with hard links, compressed files, independent forks,
attributes and a signed application. Native operations supply before/peak/final
observations and clean native checker verdicts. Complete raw disks, producer
scripts, command transcripts and hashes are retained.

Linux, Windows and macOS independently edit the same source disks in both DMG
encodings. Comparisons require original identities and geometry, native content,
metadata and fork outcomes, extent-tree growth, consistent headers and identical
output bytes. Native timestamp controls explicitly supply birth/access together with mtime;
Apple otherwise clamps HFS+ birth time when mtime is backdated. The explicit
offline ctime is distinguished from the captured native wall clock. Allocation
pressure records actual ENOSPC and the reported availability at that moment. Apple-created post-write disks are also read directly.

Every distinct portable output returns to every disposable native VM for Apple
checksums, exact raw-copy admission, fsck, mounted readback and codesign. Final
images undergo native append, catalog growth, deletion and allocation reuse;
Go reads and re-edits those disks, and a further Apple checker/remount validates
the result. The native gate never qualifies output using shadow replay.
Native testing remains confined to disposable CI VMs; local tests read files.

The native baseline has passed all three capture, portable edit and native
qualification matrices. Its immutable 10 MiB corpus is committed under
`acceptance/testdata/hfs-editing`, including native source/peak/final disks for
every version. `go test -count=1 -run '^TestNativeHFSImageEditing$' ./acceptance`
replays all six sources in about 19 seconds locally. Fresh required CI captures
remain separate from this regression corpus. Focused failure tests also prove
that admission writes nothing on corruption, interrupted transactions publish
no partial output, and partitioned-image edits preserve every outside byte.
Fresh Linux replay also runs with the race detector, split by native source
version into three jobs with four-minute deadlines. Each covers both filesystems;
their outputs combine for the same native checks. The combined five-minute race
suite avoids duplicating that full-disk work. Portable CI continues to replay
every retained case on all three hosts.
