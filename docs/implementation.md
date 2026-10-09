# Implementation sequence and qualification

This is the complete agreed scope. A phase is not complete because its APIs
compile. v2 production code and documentation were examined; its `_test` files
and harness were not imported.

| Phase | Deliverable | Current status |
| --- | --- | --- |
| 1 | Contracts, source inventory, native scenarios, build/CI, portable inspection | Native macOS 15/26/27 production and Linux/Windows/macOS replay passed in PR #7 |
| 2 | Full readers, names, metadata, forks, links, compression, unlocking | Ordinary/compressed reads, native name lookup, regular-file links, HFS+ overflow forks, metadata, symlinks, attributes and software-encrypted APFS and AES-128/256 encrypted-DMG reads implemented; retained APFS historical views implemented and locally qualified, full snapshot matrix pending; broader key profiles remain pending |
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
The encrypted-reading increment adds four independently created APFS images:
ordinary, Unicode, long and changed passwords, case-sensitive/insensitive names,
wrong/empty/old-password rejection and 108 observed objects per image. Native
clones, compression, links, sparse data, metadata and forks are read after a
read-only unlock. CommonCrypto supplies separate PBKDF2, key-wrap and XTS vectors.
The APFS encryption increment passed [PR #11's native compatibility matrix](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/37978358162).

The encrypted-DMG increment adds six Apple-created images covering AES-128/256,
APFS, case-sensitive APFS, HFS+ and HFSX, raw/compressed storage, Unicode and
changed passwords, and independent APFS encryption inside a DMG. Each compares
107 native objects and checks credential rejection, read-only preservation and
image-view lifetime. Fresh macOS 15/26/27 capture and all three replay hosts passed
in [PR #12's compatibility run](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/37982231632).
The macOS 15 images exercise 3DES password-key wrapping; the retained macOS 27
images exercise AES wrapping. Both carry AES-128/256 encrypted payloads.

Every reader change continues to require that full matrix. Short parser fuzz campaigns,
unit tests, race detection, vet, lint and cross-builds supplement native evidence.

Retained manifests identify the captured OS build. Fresh captures require the
expected major version and fail on a mislabeled runner. These scenarios do not
qualify write, mount or recovery capabilities.

Remaining reader work includes broader encryption profiles, sealed views,
historical name profiles and broader damaged-image handling. HFS+ directory
hard links, generation-store and dataless file contents fail explicitly. Fragmented
metadata and attribute-continuation fixtures remain unqualified. A small set of
native fixtures is evidence for these scenarios,
not a declaration of support for every image in the wild.

## APFS snapshot reader increment

Provide read-only enumeration and access to retained APFS snapshots. This is
part of phase 2; snapshot creation, deletion and revert by Go remain in phase 6.
The user operation is to select a historical filesystem state and read its
files and metadata on Linux or Windows, including files removed from the live
volume after the snapshot was taken.

Implementation scope:

- List snapshot names, transaction identifiers (XIDs), timestamps and flags;
  expose UUIDs when available, preserving the distinction from uncaptured data.
- Open a snapshot by an explicit name or XID through a fixed read-only view.
  Object-map resolution, tree validation and `Identity.View` must use that
  selected view. Opening one must not change the live volume or another view.
- Reuse the existing file, metadata, attribute, fork, compression and encryption
  readers. Keep snapshot selection in the APFS engine and expose it through
  `snapshot list` and explicit selectors on CLI `list`/`cat`.
- Bound snapshot-tree traversal and validate record lengths, references, object
  types, checksums and transaction limits. Missing or damaged snapshots must
  fail explicitly; they must never fall back to the live filesystem.

Use the snapshot metadata and object-map layouts in Apple's
[APFS reference](https://developer.apple.com/support/apple-file-system/Apple-File-System-Reference.pdf),
with pinned source provenance for any translated code. Existing tree decoding
should be shared where its format rules match; snapshot-specific interpretation
stays explicit.

The local feasibility gate passed without special runner provisioning. Apple
Software Restore (`asr`) creates temporary snapshots during replication. The
collector observes its own child's snapshot, pauses the child, mounts the
snapshot read-only, then resumes the copy to successful completion. The mount
prevents cleanup from deleting that snapshot. After unmounting, the retained
snapshot must still appear in Apple's inventory. All source/target volumes are
disposable images. The captured names are Apple's actual `com.apple.asr.*` names;
Unicode snapshot names are not part of native qualification.

Direct unentitled syscalls and `apfs_systemsnapshot` had failed with EPERM;
those failures did not establish that new runners were needed. The native
collector uses the replication workflow instead. It neither changes host security
settings nor creates snapshot structures with Go. A missed snapshot, timeout,
failed copy or failed filesystem verification fails capture.

Local macOS 27 capture passed all three profiles, and Go replay matched the
111–112 objects in each live/historical state in approximately six seconds. Fresh
macOS 15/26/27 capture and the complete portable matrix remain the PR gate.

Add one `snapshot-reading` acceptance family with three initial profiles:
ordinary APFS, case-sensitive APFS, and software-encrypted APFS inside an
encrypted DMG. Each retains two snapshots and a later live state. Between states,
change file contents, rename and delete entries, modify metadata, attributes and
resource forks, and exercise hard links, clones, sparse data and compression.
Read each retained snapshot through a native read-only mount of the final image;
expected results must not be inferred from the fixture-writing recipe.

The comparison must prove that older names, contents and metadata remain visible
only in the appropriate states, that objects retain the right identity within
each view, and that interleaved reads cannot mix states. Include empty inventory,
unknown/deleted snapshot selection, cancellation, corruption and borrowed-key
lifetime checks. Preserve source image hashes and record native commands,
observations, source hashes and OS builds.

Require fresh macOS 15/26/27 captures and Linux/Windows/macOS replay, plus the
existing regression matrix. Reuse the common file observation/comparison code;
report capture and replay duration and avoid a Cartesian product of every
encryption, compression and filename profile.

Sealed-system integrity verification, arbitrary checkpoint recovery, dataless
snapshots and snapshot mutation are outside this increment. HFS+ retains its
existing reader and regression coverage. Preservation-aware extraction and
workspaces remain the next larger phase after the reader readiness review.

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
