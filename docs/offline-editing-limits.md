# Offline editing admission and failure policy

The editor changes an exclusively owned scratch copy and publishes one validated
new image. It requires an ordinary admitted filesystem profile; it does not
repair unknown storage while editing. Refusal leaves the source unchanged and
publishes no destination. After publication, cleanup or persistence failures
report the already-visible output through `filesystem.PublishedOutputError`.

## Supported operations with required context

| Case | Policy | Implementation |
| --- | --- | --- |
| Several APFS volumes | Select a volume UUID; account all volume-owned blocks and preserve peers and reserves/quotas | `imageedit/selectAPFSVolume`, `apfs/mutate_ownership.go`, `apfs/mutate_limits.go` |
| Writing or creating a set-ID file | Supply a logical UID; root writes retain bits, other writes clear them; cp restores its descriptor mode snapshot, with the APFS/HFS truncation distinction; `-p` restores source mode | `internal/filesec`, `internal/copyfile`, both filesystem engines |
| Numeric chmod on an ACL-bearing object | Preserve validated ACL/GUID bytes | Both metadata writers |
| New child under an ACL-bearing parent | Apply Apple's ordered file/directory inheritance rules | `internal/filesec`, `internal/edit`, both filesystem engines |
| `cp -p`, including `-pX` | Compose source direct and destination inherited ACL entries; keep empty and absent distinct | `internal/filesec/copyfile.go`, `internal/edit/security.go` |
| Host import without captured Darwin security | Retain destination security and report the unavailable copy; do not convert uncaptured ACLs to absent ACLs | `internal/copyfile/copy.go` |
| Metadata on a literal symlink | Request no-follow behavior; source/destination resolution stays inside the logical filesystem | Shared metadata/copy policy and both engines |
| Resource fork on an actively compressed file | Refuse separate replacement while its decoding state is active | Both data/attribute writers |

Ordinary user xattr commands cannot assign filesec, compression state,
filesystem-owned symlink storage or hard-link identity. Dedicated copy and
content operations update their coupled records. Logical UIDs determine metadata
effects, without emulating process authorization or mapping GUIDs to host users.

## Protected objects

| Case | Policy |
| --- | --- |
| Volume-root metadata/removal, reserved APFS objects, HFS private link records and journal backing files | Refuse user mutation of filesystem-owned state |
| APFS `.fseventsd`, Spotlight, Trash, document revisions and temporary system trees | Refuse protected ancestors as well as direct targets |
| Immutable, append-only, locked, dataless or protected inode/catalog records | Refuse unsupported mutation; ordinary supported flag changes use the dedicated flags command |
| Protected APFS xattrs or directory records with unqualified extended fields | Preserve untouched values; refuse operations requiring their updater |
| HFS FinderInfo that would forge hard-link identity | Refuse the assignment |
| Directory hard links or hard links to nonregular files | Refuse unsupported namespace topology |

These guards are in `apfs/mutate_entries.go`, `apfs/mutate_metadata.go`,
`apfs/mutate_links.go`, `hfsplus/mutate_catalog.go`,
`hfsplus/mutate_metadata.go` and `hfsplus/mutate_links.go`.

## Storage profiles requiring separate support

| Case | Policy |
| --- | --- |
| APFS encrypted, sealed, snapshot-bearing or nonordinary-role volume | Refuse this editor profile; snapshot lifecycle, encrypted mutation and sealed-system updates require separate algorithms |
| APFS clone/shared-stream ownership, unknown extent kind or unsupported object/tree flags | Refuse allocation changes that cannot account every reference |
| APFS Fusion/tiering, unsupported checkpoint descriptor layout, active reaper, unsupported ephemeral objects or object-map snapshot state | Refuse outside the validated container profile |
| APFS space manager with unsupported geometry, multiple internal-pool bitmaps or CIB indirection | Refuse outside the admitted allocation profile |
| HFS dirty, locked, externally/uninitialized journaled or unsupported journal state | Refuse ordinary editing; the separate recovery API admits its independently qualified replay profiles |
| HFS expanded timestamps, unknown attribute storage or missing required extents tree | Refuse outside the source-backed format profile |
| Incomplete device geometry or unaccounted allocated blocks | Refuse rather than allocating over unexplained ownership |
| Unknown filesystem record, record version or opaque update semantics | Preserve readable evidence; refuse unsupported writes |

APFS admission is implemented in `apfs/mutate.go`, `apfs/mutate_validate.go`,
`apfs/mutate_space.go` and `apfs/mutate_tree.go`. HFS admission is implemented in
`hfsplus/mutate.go`, `hfsplus/mutate_tree.go` and the journal admission code.

## Resource and integrity limits

APFS allocation bookkeeping has a 64 MiB bitmap budget, independent of image
capacity, with bounded tree/object inventories. The current space-manager profile
uses one internal-pool bitmap, a sixteen-entry bitmap ring and at most 128 inline
CIB addresses. Its geometry is validated before scratch mutation. HFS catalog and
attributes files can extend into overflow extents and extend node maps; Apple's
Extents Overflow B-tree retains its resident-extents constraint.

Individual engine batches admit up to 4,096 changes. Ordered image commands share
one unpublished stage and split larger plans into bounded engine batches. Copy
payloads stream in 128 KiB chunks, with aggregate image-copy admission bounded by
the selected partition's geometry. Namespace traversal, attribute counts,
symlink expansion and object counts have separate limits. Maximum IDs, generation
counter overflow and unsupported CNID wraparound fail before publication.

Malformed keys, checksums, missing or duplicated records, overlapping physical
claims, cycles, inconsistent links/statistics, invalid filesec lengths and
inconsistent fork descriptors return corruption errors. Unsupported but valid
profiles remain distinct from corruption; resource exhaustion returns a limit or
I/O error. The editor does not fall back to another checkpoint or synthesize
missing data. The existing rejection, overflow, interruption and publication
controls supplement independent native filesystem evidence.
