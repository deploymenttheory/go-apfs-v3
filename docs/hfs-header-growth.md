# Retained HFS catalog growth and native shadow replay

This reference family establishes what native HFS modification actually changes,
and separates construction defects from the storage route used to verify them.
It supports forensic reads of retained states and the next existing-filesystem
mutation phase. It does not qualify Go transactions or shadow-backed mutation.

## Matched filesystem controls

On each disposable macOS 15, 26 and 27 VM, the collector compares fresh Apple
`newfs_hfs` volumes with labelled Go-built HFS+/HFSX volumes. Both use bare
volumes, 4096-byte allocation blocks and B-tree nodes, 32768-byte system-file
clumps, and the same initial allocation/extents/catalog/attributes fork sizes.
The empty catalogs have ten nodes, eight free. Both shadow sources use UDRO;
Apple's source is freshly formatted, then wrapped by Apple, rather than converted
from a Go filesystem. Exact raw copies admit the same device size and complete
sector SHA-256 before direct writes. Shadows receive the same admission check.

The workload grows a file through hard-link aliases, retains an independent
resource fork and ordinary xattr, renames and unlinks, creates a symlink and 128
long filenames, deletes half, then reuses allocation. The catalog must actually
grow; every captured control grows from ten to 34 blocks. Detach is followed by
an unmounted `fsck_hfs -dfn` with automatic repair disabled, a complete native
device snapshot, and independent read-only remount observations of 69 surviving
entries. Original source hashes must remain unchanged.

| Source and write route | 10,936,320 bytes | 16,777,216 bytes |
| --- | --- | --- |
| Fresh Apple, direct raw writes | Native checker succeeds | Native checker succeeds |
| Go, direct raw writes | Native checker succeeds | Native checker succeeds |
| Fresh Apple UDRO, shadow | Stale ten-block alternate catalog fork; primary has 34 | Native checker succeeds |
| Go UDRO, shadow | Stale ten-block alternate catalog fork; primary has 34 | Native checker succeeds |

This result holds on all three captured OS builds. Logical/physical device blocks
are 512 bytes throughout, so a differing reported sector size does not explain
the discrepancy. Apple controls reproduce the same failure as Go controls.

## Storage-only reproducer

The collector also creates blank raw bytes and wraps them using Apple's UDRO
converter. No Go construction or filesystem mount participates. It attaches a
private native shadow, writes distinct 512-byte markers near the start and end,
calls `DKIOCSYNCHRONIZECACHE`, checks immediate readback, and detaches. It retains
the actual shadow before read-only reattachment and again after read-only and
writable reattachment. Every native read and the complete reopened disk are
retained independently.

At 10,936,320 bytes, the two tail-sector markers initially read correctly and
exist in the detached shadow file. Read-only reattachment instead returns the
original sectors. The alternate HFS volume header lives at exactly this tested
`deviceSize - 1024` location. This reproduces the header observation through
native image storage alone: HFS tree growth and the Go filesystem writer are not
required to trigger it.

Writable reattachment outcomes are recorded separately. In the retained macOS
15 run, the alternate-header-position marker becomes visible again while the
last-sector marker disappears; on macOS 26/27 both tail markers remain invisible.
Markers can also disappear from the shadow's bytes after writable reopen/close.
Do not infer a universal per-version rule from this capture; prior experiments
already showed variability. The shared read-only replay discrepancy is explicit.

The size sweep includes the failing size, separately chosen 16/32/64 KiB
boundaries, a 128 KiB boundary, and MiB-aligned controls. Exact OS build, page size,
DiskImages version, tool hashes and SDK disk-header hash remain in each manifest.
All three captured arm64 VMs report 16384-byte pages. The failing size ends
8192 bytes into a page. The 16 KiB-aligned 10,960,896-byte control succeeds despite
being unaligned to 32/64 KiB; every other page-aligned control also succeeds.
Thus the observed boundary is consistent with a partial native VM page, rather
than requiring 64 KiB shadow-band alignment. This is an inference from the size
sweep, not a claim to have inspected the private driver implementation.
The private DiskImages implementation is unavailable in the pinned public HFS
sources: a particular internal arithmetic or mapping bug is not claimed.

## Source-backed formatter corrections

The matched controls also expose two independent fresh-header differences.
Apple's pinned `InitVH` sets `lastMountedVersion` to `kHFSPlusMountVersion`
(`10.0`) and initializes the allocation fork's clump size from the formatter's
rounded bitmap size. The Go builder previously wrote `HFSJ` despite constructing
a nonjournaled volume, and left the bitmap clump at zero. Both fields now follow
the pinned C implementation. A portable construction check compares these
fields and system-fork initial geometry directly with the Apple-created inputs;
it failed before the correction. These differences do not explain shadow replay:
the correctly Apple-formatted controls reproduce it too.

The relevant C sources are pinned in [the source ledger](sources.json):
`newfs_hfs/makehfs.c:InitVH`, `newfs_hfs/newfs_hfs.c:hfsplus_params`,
`core/hfs_btreeio.c:ExtendBTreeFile`, `core/hfs_vfsops.c:hfs_flushvolumeheader`,
`core/hfs.h` alternate-header address macros, and
`lib_fsck_hfs/dfalib/SUtils.c:CompareVolHeaderBTreeSizes`. The kernel requests
synchronous alternate-header flushing after catalog growth. Its nonjournaled
alternate write discards `VNOP_BWRITE`'s return value, while the primary write's
result is returned; that is a source fact, not evidence of an I/O error in this
reproducer. The storage-only probe records successful writes and immediate reads.

## Retention and replay

`acceptance/testdata/hfs-header-growth/macos-{15,26,27}` keeps all 48 filesystem
controls and 21 size-sweep sector probes. Compressed complete disks include
unused sectors, both volume headers, allocation bitmaps, B-trees and extents.
Source UDRO envelopes and actual shadows are retained too. All native checker
verdicts, remount metadata, contents, forks, identities and command transcripts
remain in `references.json.gz`. Each small `manifest.json` lists every control's
native verdict, catalog growth and omitted sector offsets, and binds the full
evidence archive by hash. Tool and capture-source hashes bind provenance.

The file-only retention tool verifies every compressed and decoded archive,
refuses existing destinations, shares only byte-identical archives, and keeps
the original native manifest compressed. Portable replay confirms that sharing
changed no native observations, hashes, verdicts or provenance, including exact
nanoseconds. Source recipes are historical evidence and are never executed by
`go test`.

```sh
# Linux, Windows or macOS: file-only verification, no mounts.
go test -count=1 -run TestNativeHFSCatalogGrowth ./acceptance

# Disposable GitHub VMs only: focused capture in the existing workflow.
gh workflow run native.yml --ref BRANCH -f hfs_reference_capture=true

# After downloading a complete capture: file-only initial retention.
python3 acceptance/native/retain_hfs_reference.py \
  --capture artifacts/hfs-header-growth/macos-27 \
  --output acceptance/testdata/hfs-header-growth/macos-27
```

Fresh capture also runs in the ordinary compatibility pipeline. Linux, Windows
and macOS replay all required fresh producers. Incomplete capture, unknown
checker failures, failed direct writes or remount mismatches fail the gate.
The known shadow failure is preserved as an explicit diagnostic outcome, not a
successful filesystem check. Ordinary published-image qualification still checks
every HFS output using its exact admitted raw copy and requires native success.
Caller-requested volume capacities remain unchanged; no guessed OS switch or
alignment padding is added to production filesystem construction.

Native operations remain confined to disposable VMs. Downloading and inspecting
these images locally never requires attaching them to the development Mac.

The retained evidence comes from
[capture 38127438693](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/38127438693),
at source commit `7c959634` (the complete revision is retained in each manifest):
macOS 15.7.9 build 24G830, 26.6.2 build 25G83 and 27.0.1 build 26A434.
