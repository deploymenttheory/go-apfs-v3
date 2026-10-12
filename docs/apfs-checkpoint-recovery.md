# APFS checkpoint recovery

This increment qualifies explicit recovery of interrupted, file-backed APFS
transactions into a new image. Original evidence remains read-only. Native
filesystem operations run exclusively on disposable CI VMs.

## Format and selection contract

Apple's [File System Reference](https://developer.apple.com/support/apple-file-system/Apple-File-System-Reference.pdf),
pages 26–27, defines checkpoint selection: use block zero to locate the
descriptor ring; inspect container superblocks in transaction order; validate
the checkpoint mappings and their stored ephemeral objects before accepting
a checkpoint. The mapping sequence may wrap around the descriptor ring.
Malformed ephemeral objects invalidate that checkpoint. Object-map or file-tree
damage after checkpoint selection is a distinct failure, not permission to
silently present a different historical filesystem.

Checkpoint inspection, ordinary checkpoint reads, recovery and mutation admission
share `apfs/checkpoint.go`. Validation covers physical ranges, selected descriptor/data ranges,
map termination, duplicate identities and overlapping stored objects, exact
checksums, object types/subtypes and transaction identity. Unsupported features
and resource limits must not be treated as corruption that permits rollback.

`apfs/checkpoint_recovery.go` selects the newest complete checkpoint, then validates the
entire admitted filesystem's allocation, deferred frees, object maps, streams,
directory and hard-link graph. A retained older superblock alone is insufficient.
Damage in the selected filesystem is refused; recovery does not repair trees,
invent object mappings or search arbitrary free blocks.

The CLI uses ordinary flags:

```sh
apfs checkpoint inspect --image Interrupted.dmg
apfs checkpoint recover --image Interrupted.dmg --output Recovered.dmg
```

The report identifies the selected transaction and rejected newer checkpoint
candidates. Inspection reports structural completeness separately from recovered
filesystem ownership. Ordinary readers refuse malformed mappings/stored objects
in their selected checkpoint; they never silently choose a different view.

Recovery disables rejected newer descriptor superblocks and copies the selected
superblock into block zero. It creates no new transaction or file records.
Recovery stages the decoded disk internally, preserves unrelated
partitions, validates the final state, and publishes a flushed new UDRO/UDZO
image without overwrite. It does not require a recovery configuration file.

## Qualification work

The admitted recovery profile follows existing bounded single-volume plaintext
APFS mutation admission: 4096-byte blocks, at most 1 GiB, one ordinary volume,
contiguous descriptor/data regions and completely accounted allocation/deferred
frees. Broader readers remain independently qualified. Snapshot,
clone/shared-stream, encryption, Fusion and System/Data mutation retain separate
scope. Encrypted DMG envelopes are also refused. File-backed interruption and completed-output publication do not establish
physical storage-device power-loss durability or mounted in-place transactions.

Descriptor scanning is bounded to 32 MiB and 256 superblocks. A checkpoint has
at most 4,096 mapped objects, individual objects at most 64 KiB and a 32 MiB
validation budget; all inspected candidates share a 64 MiB mapping/object read
budget. Cancellation and source I/O failures propagate. These limits are refusals,
never a reason to choose an earlier view.

Explicit recovery can use a damaged block-zero checksum only as a bounded
locator hint within that same 1 GiB profile. Its block size, block count,
container UUID and both checkpoint-region geometries must match an independently
checksummed descriptor superblock. Complete ownership validation still precedes
every write. Damage to those locator fields, missing valid descriptors and
arbitrary block scanning remain refused. Ordinary `Open` continues to reject
an invalid block-zero checksum.

Apple creates the source filesystems, signatures, links, metadata, attributes
and independent forks. A guarded collector observes actual checkpoint-data,
mapping and superblock write windows, pauses only the exact runner-owned image
helper, streams its backing bytes, and resumes it with an independent watchdog.
It never manufactures checkpoint records. Original bytes are retained before
Apple's checker or read-only mount observes them.

Apple's checker supplies its selected transaction identifier. The read-only
mount supplies complete file observations and signature verification. Retained
evidence records OS builds, tool and capture-source hashes, commands, original
disk hashes and acquisition diagnostics. Fresh capture on macOS 15, 26 and 27
and portable/native comparisons are required by the compatibility gate.

The retained corpus contains 36 controls from
[native run 38298298833](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/38298298833).
Each version has both name profiles, with four genuine checkpoint-write windows
(newer data, newer mappings, a published superblock with stale block zero, and
checkpoint-data ring wrap) and two explicitly derived checksum-damage cases.
Damage changes exactly one checksum byte in the newest mapping or stored
object. A separate Apple-checked control disables that damaged descriptor and
establishes the complete earlier state. This qualifies the chosen recovery
policy; it does not claim that Apple's checker repairs the original damaged
disk or that the corruption was produced by native interruption.

Go transaction controls cover full and partial writes at data,
metadata, checkpoint-mapping, checkpoint-superblock and block-zero boundaries,
plus cancellation, disk-full and output-publication errors. Linux, Windows and
macOS emit actual recovered images; independent Apple checking/readback and
subsequent native modification qualify those outputs. Every actual Go write is
faulted with ENOSPC, short/torn prefixes and complete writes reported failed.
Separate file-backed controls retain seven-byte writes at six publication
boundaries for each native source version. Only a torn block-zero update follows
a fully published new checkpoint; earlier interruptions must expose the original
state. An actual killed CLI during observed partial scratch copying must leave
the source unchanged and destination absent.

The dedicated workflow names capture, portable comparison, process interruption
and native continuation jobs by their actual purpose. Retained replay runs
without native tools; fresh capture never updates the repository baseline.

```sh
go test -count=1 -run TestNativeAPFSCheckpointRecovery ./acceptance
```

Recovery preserves available committed data; it cannot reconstruct uncommitted
regular-file writes or detect arbitrary bit rot in APFS data lacking checksums.
Apple's private checkpoint implementation is unavailable to port. This is an
original Go interpretation of the published format, independently qualified
through Apple's tools and kernel on disposable VMs.
