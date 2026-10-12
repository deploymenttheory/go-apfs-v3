# HFS+/HFSX journal recovery

Recovery produces a new image from an interrupted journaled HFS+/HFSX volume.
The original image stays read-only. Ordinary readers and edits continue to
refuse an interrupted source; they never replay it implicitly.

```sh
apfs journal inspect --image Interrupted.dmg
apfs journal replay --image Interrupted.dmg --output Recovered.dmg
apfs journal replay --image Interrupted.dmg --partition 1 --format UDRO --output Recovered.dmg
```

`inspect` verifies the volume header, JournalInfoBlock, journal header checksum
and geometry without requiring a readable catalog. It reports the stored
cursors and pending state. It does not promise that the pending records or
unreplayed filesystem are consistent. `--json` produces a versioned report;
there is no recovery configuration file.

`replay` checks committed records before writing home blocks, uses managed
scratch, then validates the entire recovered allocation, tree, thread and link
graph. Only after those checks does it mark the primary header unmounted and
publish the flushed completed image without overwrite. Metadata clocks, file
identities, contents, forks, application signatures and unrelated disk sectors
are retained. The report records the stored and recovered boundaries, selected
transactions, extra block lists and coalesced sector count.

## Apple behavior and explicit limits

The implementation adapts the pinned Apple
[journal code](https://github.com/apple-oss-distributions/hfs/blob/d1bac2f062e6e9c0dfcce302d9aacb10173d0eea/core/hfs_journal.c).
Header checksums cover the original 44 bytes; block-list checksums cover 32
bytes. Stored byte order is respected. Payload checksums, killed buffers,
continuation headers, sequence ordering, circular reads and overlapping writes
have separate handling. Later writes replace earlier overlapping sectors.

Apple can replay complete sequence-qualified transactions beyond the recorded
end. A stale/bad tail header or sequence stops scanning; incomplete tentative
payloads drop that whole tentative transaction. Corruption inside the declared
committed range fails recovery. The offline API deliberately refuses that
corruption rather than using the kernel's best-effort committed-prefix salvage.
It never resets, disables, relocates or recreates a journal to admit a source.

The qualified profile uses current `JNLx` headers, initialized internal journals,
512-byte journal sectors and checksum-enabled block lists. The volume must
retain the journaling-aware `HFSJ` mount identifier. Journal storage is bounded
from 256 KiB through 1 GiB, block-list headers to 1 MiB, and coalesced replay to
2^18 sectors (128 MiB). Existing complete-allocation and metadata graph bounds
also apply. Unsupported geometry and bounds fail without output publication.

External/uninitialized/old journals, larger replay sectors, inconsistent or
locked volumes, unsupported recovered metadata profiles and tree repairs remain
outside this increment. Journal replay cannot reconstruct regular-file data
that Apple had not journaled or committed. This is completed-copy recovery;
live journal writing, in-place durability and physical power-loss guarantees
remain separate work. APFS checkpoint recovery is the following transaction
increment, not an HFS journal operation.

## Independent evidence

The native producer creates its own HFS+ and HFSX filesystems and signed app,
hard links, symlink, opaque attributes and independent resource fork. Apple's
ordinary `hfs_fsync` intentionally skips catalog metasync on journaled volumes;
the workload uses SDK `F_FULLFSYNC` to enter its actual journal-flush path.

The collector identifies the exact runner-owned image/helper/device relationship
from Apple's DiskImages inventory. A guarded helper pauses that image process
after a real journal-end or block-list write, streams the original backing
bytes and resumes it. A watchdog also resumes it after collector interruption.
No journal cursor, payload or filesystem record is manufactured. Nonempty
linear/wrapped controls must contain unapplied committed metadata.

Apple's `HFS_REPLAY_JOURNAL` sysctl recovers a separate copy without invoking
tree repair. Those exact replay-only bytes are retained before checking and
read-only mounting. `fsck_hfs -fn`, complete file/metadata/fork observations and
`codesign` supply independent verdicts. Eight cases per macOS version cover
both filesystems, linear/wrapped rings and complete/incomplete records beyond
the recorded end. Original evidence, native results, OS build, source revision,
tool/script hashes and command diagnostics are retained.

Portable acceptance requires byte-for-byte agreement with Apple's replay-only
disk, then the explicit validated-unmounted marking at publication. Linux,
Windows and macOS generate actual UDRO/UDZO images. All three macOS versions
check the corresponding source-version outputs from all three writer hosts,
including signatures, metadata, subsequent native journaled allocation/writes
and Go modification after recovery. A separate portable process-kill check
interrupts partial scratch copying and requires an absent output plus unchanged
original evidence. Native operations run exclusively on disposable CI VMs.

Retained replay needs no native tools:

```sh
go test -count=1 -run TestNativeHFSJournalRecovery ./acceptance
```
