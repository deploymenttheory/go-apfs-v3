# Fixture recipes

Each file is one recipe executed by the capture tool on macOS 15, 26 and 27.
A recipe names the filesystem profiles it is captured in, how the image is
created, the ordered steps that populate and mutate the volume, and what the
observer records. The schema is `acceptance/schema`; `go test ./acceptance`
validates every recipe and the lock digest.

Profiles: `apfs`, `apfsx` (case-sensitive), `hfsplus`, `hfsx`, `hfsplus-j`,
`hfsx-j` (journaled).

## Capability coverage

| Capability (docs/implementation.md) | Recipes | Portable assertions | Native verdicts |
| --- | --- | --- | --- |
| Volume and container inspection | every recipe (diskutil plist in each observation); `container-volumes`, `volume-groups`, `partitioned-disks` | name, case policy, geometry, UUIDs, roles, groups, reserves, quotas, partition maps | fsck, `diskutil apfs list`, `listVolumeGroups` |
| File reading: names, identity, metadata, links, forks, attributes, sparse data, Unicode lookup, HFS overflow extents | `file-corpus` | every entry field equals the observation; lookups match; samples across extent boundaries | mounted readback of Go-built copies |
| Transparent compression reading | `compressed-files` | logical and raw hashes, type, storage; malformed control refuses | kernel readback and public codec decode |
| Software-encrypted APFS reading, clones, re-keying | `encrypted-volumes` | unlock, rejection, clone sharing, every state | `diskutil apfs unlockVolume`, `verifyVolume` |
| Encrypted DMG reading | `encrypted-images` | AES-128/256, raw and compressed, independent credentials | `hdiutil verify -stdinpass`, device hash |
| LZFSE DMG reading | `lzfse-images` | decoded device hash, file metadata and stream bytes, sector-preserving repacks | `hdiutil verify`, fsck and mounted readback |
| Snapshot reading | `snapshot-history` | names, XIDs, UUIDs, historical views, no live fallback | `diskutil apfs listSnapshots`, snapshot mounts |
| Extraction, workspaces, AppleDouble | `file-corpus` (appleDouble export) | round trip, name mapping, raw versus logical | `ditto -x` unpack of exported `._` files |
| Workspace and session edits | `workspace-edits`, `file-command-journeys` | final trees equal the native after states; rejections match | re-run of the same journey on Go outputs |
| Permission inheritance, set-ID, cp composition | `permission-inheritance` | ACLs, ownership, modes | getattrlist extended security |
| Clone copying, independent edits and persistent sharing | `clone-copy` | copy policy, reopened session states, stream-specific detachment and sharing | native copy outcomes, mounted readback, physical extent relations and continuation |
| Fresh image construction (APFS, HFS+/HFSX, multi-volume, groups, compression, encryption) | `file-corpus`, `compressed-files`, `container-volumes`, `volume-groups` as inputs | byte-identical builds across hosts | fsck, mount, readback, codesign, continuation writes on the System member |
| Sector-preserving repacking | `partitioned-disks`, `snapshot-history`, `encrypted-volumes`, `encrypted-images` | device hash equals the recorded `diskSHA256`; refusals | `hdiutil verify`, partition inventory, snapshot mounts |
| Existing HFS+/HFSX edits, journaled admission, metadata growth | `hfs-mutation-sources`, `hfs-attributes-initialization`, `hfs-catalog-map-growth`, `hfs-fragmented-metadata` | peak/final/catalog states, headers, node maps, overflow extents | fsck, readback, continuation, Go re-edit |
| Existing APFS edits, volume selection, geometry, directory statistics | `apfs-mutation-sources`, `apfs-container-geometry`, `apfs-directory-statistics` | peak/final/catalog states, every statistics transition | fsck, readback, continuation, Go re-edit |
| HFS journal recovery | `hfs-journal-interruption` | replay byte-equal to Apple's | fsck of recovered output, continuation |
| APFS checkpoint recovery | `apfs-checkpoint-interruption` | same selected transaction as fsck_apfs | fsck of recovered output, continuation |
| Snapshot, clone and encrypted writing (pending, #56–#74) | `snapshot-history` api-probe, `encrypted-volumes` | recorded API outcomes | recorded API outcomes |

## Rules

- Names are capability-based and never carry ordering numbers.
- A recipe change changes `recipesSHA256` in `acceptance/fixtures.lock.json`;
  CI fails until a new corpus is captured and the lock is updated by review.
- Steps may call only the Apple programs the schema allows, perform POSIX
  operations through the kernel, or invoke a capture-tool procedure. Bounded
  acquisition probes read journal/checkpoint headers to recognise native write
  windows and locate explicitly declared checksum damage. They never traverse
  filesystem trees, perform recovery or generate expected file observations:
  Apple replay-only bytes, checker-selected XIDs and kernel reads are the oracle.
- Expected failures are declared (`expect`) and recorded; a recipe never
  skips.
- Differences between macOS versions are recorded by the observer and must
  match `acceptance/known-drift.json` during native verification.

## Payloads

Byte-exact inputs live under `payloads/`; its README records how each file
was produced.
