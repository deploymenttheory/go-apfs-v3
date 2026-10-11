# Native HFS modification checks

HFS+/HFSX outputs first pass Apple image verification, unmounted filesystem
checks, read-only kernel observations, metadata/fork comparisons and codesign.
Subsequent modification uses a private Apple-converted UDRW image. Before any
write, Apple-attached device size and complete sector SHA-256 must match the
original Go output. The conversion must also leave the original image hash
unchanged. This admits the exact constructed filesystem for direct native writes.
It does not admit an Apple reformatted or repaired filesystem.

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
[`checker`](https://github.com/apple-oss-distributions/hfs/blob/d1bac2f062e6e9c0dfcce302d9aacb10173d0eea/lib_fsck_hfs/dfalib/SVerify1.c)
rejects disagreement between the primary and alternate headers. Debug mode
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

Acceptance therefore qualifies native continued use through the direct writable
route, adding full device equality before modification. Failed checker results
remain failures; no repair or checker-error exception is used. The original
read-only DMG is independently qualified in its published encoding too.

`acceptance/native/diagnose_hfs_headers.py` retains the optional three-route
diagnostic. It records individual verdicts and header fields rather than
qualifying product output, and is outside the normal CI path. Its direct writes
use only private Apple-converted copies on disposable VMs.
