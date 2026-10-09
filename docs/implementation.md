# Implementation sequence and qualification

This is the complete agreed scope. A phase is not complete because its APIs
compile. v2 production code and documentation were examined; its `_test` files
and harness were not imported.

| Phase | Deliverable | Current status |
| --- | --- | --- |
| 1 | Contracts, source inventory, native scenarios, build/CI, portable inspection | Native macOS 15/26/27 production and Linux/Windows/macOS replay passed in PR #7 |
| 2 | Full readers, names, metadata, forks, links, compression, unlocking | Ordinary/compressed reads, native name lookup, regular-file links, HFS+ overflow forks, metadata, symlinks and attributes implemented; unlocking and historical views pending |
| 3 | Preservation-aware extraction, workspaces, replacement, AppleDouble | Pending |
| 4 | Deterministic creation, packing, DMG encoding/repacking, volume groups | Pending |
| 5 | Existing-filesystem edits, allocation, tree mutation, durable transactions | Pending |
| 6 | Snapshot lifecycle, clones, encrypted modification/creation | Pending |
| 7 | Read/write mounts on Linux/macOS/Windows | Pending |
| 8 | Deleted-file recovery, allocation-aware scanning, consumer qualification | Pending |

## Current evidence

The volume-inspection family compares native APFS, case-sensitive APFS, HFS+,
and HFSX images against `diskutil`: name, case policy, allocation block size,
filesystem size, and APFS UUID. Inputs are native zlib UDIFs with GPT maps.
Native read-only attachment and portable inspection must not change image hashes.

The file-reading family compares 105 objects per filesystem with the final
read-only native mount: exact directory entries and Unicode spelling, CNIDs/inode
IDs, regular-file and symlink sizes, link counts, mode, UID/GID, BSD flags,
birth seconds, all three other timestamps at native precision, symlink targets,
file hashes, and every native-visible extended attribute's size/hash. Native
directories' synthetic size/link counts are intentionally outside the comparison.
APFS filesystem-owned attributes may be enumerable in addition to native-visible
attributes. Fixtures include multi-node trees, empty files/attributes, binary data,
sparse ranges, a 32 KiB ordinary attribute and a resource fork larger than 32 KiB.

The file-semantics family adds 15 filename comparison cases with positive and
negative native lookup results, three hard-link aliases modified through a link,
and HFS+ data/resource forks whose fragmentation is independently measured by
Darwin `F_LOG2PHYS_EXT`. The retained forks have 20 and 21 extents; complete hashes
and random reads across every native extent boundary are compared. Original
spelling, link identity/count, metadata and attributes remain part of the same
file comparison. Apple C comparison tables are translated reproducibly; an older
Unicode 9 assumption failed the native Georgian case and is not used.

Retained local evidence covers macOS 27.0.1 (26A434). The previous inspection and
file-reading families passed all three native producers and all three replay
hosts in [PR #7's native run](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/37957366458).
The file-semantics family passed all required producers and replay hosts in
[PR #9's native run](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/37961351230).
The file-compression family now adds native decmpfs types 1, 3, 4 and 7–16,
logical/raw storage separation, native public-codec readback, stored blocks,
resource descriptor gaps, inactive attributes and a malformed active-file control.
The compression implementation passed fresh macOS 15/26/27 reference capture and
Linux/Windows/macOS replay in [PR #10's compatibility run](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/37974021258).
Every reader change continues to require that full matrix. Short parser fuzz campaigns,
unit tests, race detection, vet, lint and cross-builds supplement native evidence.

Retained manifests identify the captured OS build. Fresh captures require the
expected major version and fail on a mislabeled runner. This scenario does not
qualify write, mount, unlock, or recovery capabilities.

Remaining reader work includes encryption, snapshots/sealed views,
historical name profiles and broader damaged-image handling. HFS+ directory
hard links, generation-store and dataless file contents fail explicitly. Fragmented
metadata and attribute-continuation fixtures remain unqualified. A small set of
native fixtures is evidence for these scenarios,
not a declaration of support for every image in the wild.

## Required phase gates

1. Independent native fixtures/observations, readable portable comparisons, and
   every required macOS producer and Linux/Windows consumer in CI.
2. Native-produced images read identically on all hosts, including metadata and
   forks; malformed input and unsupported features fail explicitly.
3. Extract/edit/rebuild retains all untouched values and relationships. Host
   limits produce preservation outcomes rather than silent loss.
4. Native checkers and mounted readback accept every host's output. Controlled
   inputs produce byte-identical deterministic builds.
5. Repeated native/Go edits and fault-injected writes satisfy the documented
   durability contract, including interrupted commit, disk-full and flush errors.
6. macOS recognizes and can continue modifying snapshots, clones, and encrypted
   output. Snapshot deletion preserves retained states and allocation accounting.
7. Mounted workloads retain identity, links, attributes, forks, and durable writes
   under concurrency and remounts. Drivers remain optional dependencies.
8. Seeded deletions recover with provenance; packaging and downstream signing
   journeys pass native verification on macOS 15, 26, and 27.

## Rules

- Tie every capability to a user operation, authoritative source, and independent
  acceptance result. Pin translated files/revisions and retain their licenses.
- Use Apple names for format structures and idiomatic Go ownership and I/O.
- Keep native capture independent of Go results. Existing observations are
  immutable; code changes are not a reason to regenerate expected results.
- Grow CI by scenario family, not workflow-per-regression. Coverage is diagnostic;
  do not inherit v2's per-file percentage gates. Release checks bind the candidate.
- Unknown cases must not become empty directories, zero-filled file content,
  fallback checkpoints, or successful skips.
- Full macOS process-authorization emulation, signing algorithms, notarization,
  installer-package formats, and bootable sealed-system construction are outside
  this library. Preserve their metadata without claiming their behavior.
