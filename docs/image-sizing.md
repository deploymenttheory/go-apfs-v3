# Automatic image sizing

Automatic capacity must cover the final stored payload, all filesystem metadata,
unused explicit APFS volume reservations, and room for subsequent native
allocation. Fitting the initial Go sector layout alone is insufficient: Apple's
incremental construction and APFS copy-on-write transactions need working space.

## Apple source and native evidence

The pinned [Apple HFS formatter](https://github.com/apple-oss-distributions/hfs/blob/d1bac2f062e6e9c0dfcce302d9aacb10173d0eea/newfs_hfs/makehfs.c)
`InitVH` includes volume headers, allocation bitmap, metadata trees and optional
journal in `blocksUsed`, then subtracts allocated blocks from `freeBlocks`.
It leaves unallocated gaps for catalog and attributes tree growth. Those gaps
change placement, not the allocated block count.

[Apple's HFS volume code](https://github.com/apple-oss-distributions/hfs/blob/d1bac2f062e6e9c0dfcce302d9aacb10173d0eea/core/hfs_vfsops.c)
sets a mount reserve and distinguishes `f_bfree` from `f_bavail`.
[`hfs_freeblks`](https://github.com/apple-oss-distributions/hfs/blob/d1bac2f062e6e9c0dfcce302d9aacb10173d0eea/core/hfs_vfsutils.c)
subtracts reserves when requested, subtracts loaned/locked blocks, and may limit
sparse-device space to its backing store. A raw bitmap count does not establish
that a caller can use all free blocks.

The installed Apple `hdiutil(1)` manual describes `create -srcfolder` automatic
sizing as source data plus filesystem overhead padding. Explicit size overrides
that calculation. Apple's DiskImages automatic sizing and APFS formatter C
implementation are not available in the pinned public sources; this project does
not claim to port their private formulas.

[Independent CI experiment 38110647183](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/38110647183)
used the same macOS 15 source trees on disposable macOS 15, 26 and 27 VMs.
It compared the old Go output, Apple `hdiutil create -srcfolder -layout NONE`
automatic output, and Apple construction at the Go output's explicit capacity.
Bounded 64 KiB native writes with `fsync` used private shadows, stopping at
`ENOSPC` or 8 MiB. The original images' hashes remained unchanged.

All three native versions produced these results:

| Filesystem | Old Go automatic capacity | Apple automatic capacity | Native writes accepted by Go image | Native writes accepted by Apple automatic image | Apple construction at Go capacity |
| --- | ---: | ---: | ---: | ---: | --- |
| APFS | 9,052,160 bytes | 18,337,792 bytes | 196,608 bytes | At least 8,388,608 bytes | Fails with `ENOSPC` while copying files |
| HFS+ | 8,802,304 bytes | 10,661,888 bytes | 1,048,576 bytes | 2,752,512 bytes | Succeeds |

Case-sensitive profiles with explicit 160 MiB capacity accepted the entire 8 MiB
probe for both Apple and Go. The old APFS image reported 314 free and available
4096-byte blocks before writing, but stopped after only 48 additional data
blocks. Even `statvfs.f_bavail` alone did not predict successful APFS allocation.
These measurements establish underprovisioning, not a universal native reserve
constant or an exact Apple automatic-sizing formula.

## Construction policy

`internal/buildsize` applies the same accounting rule to both builders, with
format-specific padding: 8 MiB for APFS and 2 MiB for HFS+, plus 12.5% of all
allocated blocks, rounded up. This is original Go packaging policy informed by
the source study and native measurements. It does not promise byte-identical
capacity to Apple's formatter or unlimited future growth.

The padding is computed after placing all metadata. Automatic sizing iterates
until capacity-dependent APFS space-manager geometry or the HFS allocation
bitmap also fits with the full padding intact. Unused explicit APFS volume
reservations are accounted separately and do not inflate the proportional
allowance. Explicit `--capacity` is respected, rounded up to 4096 bytes, without
adding automatic padding. The minimum capacity remains 8 MiB and the maximum
remains 1 TiB.

Portable regression tests read final on-disk free counts for populated 8 MiB and
64 MiB payloads and verify explicit capacities remain exact. Existing large APFS
reservation controls exercise capacity-dependent metadata growth. Native
acceptance requires Apple to construct the same source at the Go capacity and
retains the full growth, hard-link, rename, unlink, metadata growth, reuse,
compression replacement, filesystem-check and remount workloads. All native
operations run on disposable CI VMs.
