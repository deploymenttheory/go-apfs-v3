# Native HFS modification checks

HFS+/HFSX outputs first pass Apple image verification, unmounted filesystem
checks, read-only kernel observations, metadata/fork comparisons and codesign.
Subsequent modification uses a private raw image streamed from the Apple-attached
device. Before any write, its native device size and complete sector SHA-256 must
match the copied source sectors. Copying must also leave the original image hash
unchanged. This admits the exact constructed filesystem for direct native writes,
including unused sectors.

The full workload remains: compression replacement through an alias, writes to
independent forks, file growth, hard linking, rename, unlink, 96 new entries,
deletion and allocation reuse. Afterwards Apple's checker must succeed without
repair, then a read-only remount must retain contents, forks and signatures.
APFS continues to use private shadows. All native operations require a disposable
VM; a private image or shadow alone does not isolate the host kernel.

## Source study and controlled experiment

Apple's [`ExtendBTreeFile`](https://github.com/apple-oss-distributions/hfs/blob/d1bac2f062e6e9c0dfcce302d9aacb10173d0eea/core/hfs_btreeio.c)
marks the grown system file modified and calls `hfs_flushvolumeheader` with
`HFS_FVH_WAIT | HFS_FVH_WRITE_ALT`. The
[`volume-header writer`](https://github.com/apple-oss-distributions/hfs/blob/d1bac2f062e6e9c0dfcce302d9aacb10173d0eea/core/hfs_vfsops.c)
copies updated metadata to the alternate header. Apple's
[`CompareVolHeaderBTreeSizes`](https://github.com/apple-oss-distributions/hfs/blob/d1bac2f062e6e9c0dfcce302d9aacb10173d0eea/lib_fsck_hfs/dfalib/SUtils.c)
prefers the larger catalog fork and invalidates the smaller header; `CheckVolume`
then rejects that state. Debug mode
identifies the precise field; plain output only reported a minor header repair.

[Experiment 38120009221](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/38120009221)
reused six successful capture/replay jobs from run 38117545019. Every VM used
the same Linux-built macOS 15 HFS+ `none` output. Three routes ran the same
native modification/fsck/remount routine:

| Route | macOS 15 | macOS 26 | macOS 27 |
| --- | --- | --- | --- |
| Original Go UDRO, private shadow | Passed once | Stale alternate header | Stale alternate header |
| Apple-rewrapped UDRO, private shadow | Stale alternate header | Stale alternate header | Stale alternate header |
| Apple-converted UDRW, direct writes | Passed | Passed | Passed |

Failing shadows grew the catalog from 92 to 100 blocks in the primary header,
while the alternate still described 92 blocks and lacked the new extent.
Direct writable copies retained matching 100-block headers and passed fsck,
remount, contents, forks and codesign. The original Go image hashes stayed
unchanged. This experiment isolates a difference in the shadow-backed native
write route; it does not establish the private DiskImages driver's internal
cause or claim that all shadow writes fail. Rewrapping alone did not resolve it.

The stronger admission check in
[run 38120590877](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/38120590877)
then rejected Apple's UDRW conversion: the device capacity stayed at 10,936,320
bytes, but sector hashes differed. A successful converted-image control therefore
does not prove that the original disk sectors support modification. Acceptance
uses a streamed raw copy instead, requiring full device equality before writing.
Failed checker results
remain failures; no repair or checker-error exception is used. The original
read-only DMG is independently qualified in its published encoding too.

`acceptance/native/diagnose_hfs_headers.py` retains the optional three-route
diagnostic. It records individual verdicts and header fields and is outside the
normal CI qualification path. Its direct writes
use only private Apple-converted copies on disposable VMs.
