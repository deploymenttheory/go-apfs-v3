# Editing a workspace tree

`Workspace.Edit` applies ordered changes and captures one new, self-contained
workspace. The input stays immutable. Paths refer to original macOS names relative
to the workspace root; later operations see earlier ones. Input paths never follow
symlinks. A new destination must be outside the input workspace.

| `workspace.Operation` / JSON `op` | Inputs | Behavior |
| --- | --- | --- |
| `CreateFile` / `create` | `path`, metadata, data, optional attributes | Create a new regular file; an existing native-equivalent name is a conflict |
| `CreateDirectory` / `mkdir` | `path`, metadata, optional attributes | Create one directory under an existing parent |
| `CreateSymlink` / `symlink` | `path`, metadata, literal `target`, optional attributes | Record a symlink without following its target |
| `CreateHardLink` / `link` | source `path`, destination `to` | Add a name for an existing regular-file object |
| `RenameEntry` / `rename` | source `path`, destination `to` | Move/rename; replace compatible existing targets, including empty directories |
| `RemoveEntry` / `remove` | `path` | Remove one entry; directories must be empty |
| `ReplaceFileData` / `replace` | `path`, data | PR16 replacement semantics for the selected object and all aliases |

Unrelated fields are rejected. The root cannot be renamed or removed. Directory
hard links and moves into descendants are invalid. Renaming between two distinct
names of the same inode is a no-op; a case-only rename updates the stored spelling
when the native comparison resolves both names to the same entry. HFS+ stores
names decomposed using the existing pinned Apple tables. Both formats enforce a
255-UTF-16-unit limit on stored spelling. Original host-unsafe names still use the
same portable projection mapping.

The library's `workspace.Change.Data` and `Attributes` values borrow immutable
`block.Source` inputs. The caller keeps them open for the call; Edit never closes
them. Creation metadata requires present mode/type, UID, GID, BSD flags, birth,
modification, change and access times. These values are recorded, not applied as
host permissions or authorization. Active compression is not a creation input;
ordinary initial attributes, empty values and independent resource forks are.

```go
changes := []workspace.Change{
    {Op: workspace.CreateDirectory, Path: "Contents/_CodeSignature", Metadata: &directoryMetadata},
    {Op: workspace.CreateFile, Path: "Contents/_CodeSignature/CodeResources", Metadata: &fileMetadata, Data: seal},
    {Op: workspace.ReplaceFileData, Path: "Contents/MacOS/Example", Data: executable},
    {Op: workspace.RemoveEntry, Path: "Contents/Resources/obsolete"},
}
report, err := baseline.Edit(ctx, changes, newDirectory, workspace.Limits{})
```

`directoryMetadata` and `fileMetadata` are explicit `filesystem.Metadata` values
supplied by the caller. All untouched source metadata and timestamps remain
recorded. Link counts change by the operation's delta, so aliases outside an
extracted subtree are retained. Uncaptured counts remain uncaptured during unrelated edits; link-count
changes require an observed value and otherwise return `ErrUnsupported`.
Newly created objects have `Created` set and a
`workspace:` creation digest as their identity's Volume, with View zero. These
object numbers are workspace graph keys, not native APFS/HFS+ inode numbers.
`LinksModified` records adjusted link counts. The creation identity remains stable
through further edits; the enclosing manifest hash identifies the edited state.

Schema-3 manifests and report counts retain these markers on re-extraction. Older
schema-1/2 workspaces remain readable. Identical input workspaces and edit inputs
produce identical manifests on the same host projection. There is no random
creation ID or host-clock default. Cross-host hard-link materialization outcomes
can still differ, as with extraction.

## CLI plan

```sh
apfs workspace edit --json ORIGINAL CHANGES.json NEW_WORKSPACE
```

The plan has schema 1 and an ordered `changes` array. Each operation uses the
fields above; file inputs use `contents` paths, resolved relative to the plan
file. Initial `attributes` are explicit `{ "name": ..., "contents": ... }`
records. Unknown fields, duplicate attribute names and trailing JSON are rejected.
The plan is limited to 16 MiB; the existing object/entry/value budgets also apply.
The CLI does not discover AppleDouble files or infer changes from the projection.

This example creates an ordinary resource file under an existing directory. The
metadata values are illustrative explicit inputs, not defaults:

```json
{
  "schema": 1,
  "changes": [
    {
      "op": "create",
      "path": "Contents/Resources/new-resource",
      "contents": "new-resource.bin",
      "metadata": {
        "mode": {"state": 2, "value": 33188},
        "uid": {"state": 2, "value": 501},
        "gid": {"state": 2, "value": 20},
        "bsdFlags": {"state": 2, "value": 0},
        "birthTime": {"state": 2, "value": "2026-10-10T00:00:00Z"},
        "modifyTime": {"state": 2, "value": "2026-10-10T00:00:00Z"},
        "changeTime": {"state": 2, "value": "2026-10-10T00:00:00Z"},
        "accessTime": {"state": 2, "value": "2026-10-10T00:00:00Z"}
      }
    },
    {"op": "rename", "path": "Contents/Resources/old-name", "to": "Contents/Resources/new-name"}
  ]
}
```

Preflight failure creates no output. Failed streaming may leave an incomplete
directory without a completion manifest, which `workspace.Open` rejects. No
baseline file or blob is written. Inputs and the destination must be protected
from external mutation for the call. General host import, native authorization,
compression encoding, filesystem-image writes and crash-durable transactions
retain their separate implementation gates.

Native qualification is described in [the acceptance guide](../acceptance/README.md#ordered-tree-edits).

## Metadata, attributes and resource forks

These operations use the same batch, original paths, alias identity and new-output
contract. `.` or `/` selects the workspace root. A final symlink is the object
being changed, never its target. Recorded permissions do not authorize or prohibit
subsequent workspace operations on the consumer host.

| Operation | Inputs | Effect |
| --- | --- | --- |
| `SetMetadata` / `metadata` | `path`, partial `metadata` | Assign the supplied fields; retain unspecified values |
| `SetAttribute` / `setxattr` | `path`, `attribute`, data, optional `attributeMode` | Set a complete ordinary attribute or 32-byte FinderInfo value |
| `RemoveAttribute` / `removexattr` | `path`, `attribute` | Remove an existing attribute or independent resource fork; absence is an error |
| `ReplaceResourceFork` / `resource-fork` | `path`, data | Replace a regular file's complete independent resource fork, including truncation |

A metadata patch reuses `filesystem.Metadata`. `Present` (JSON state `2`) supplies
a value, including zero. Omitted fields use `Uncaptured` (`0`) with a zero value;
`Absent` and contradictory omitted values are errors. Mode contains the native
POSIX type and permission bits; the type must match the existing object. UID/GID
`0xffffffff`, which native APIs reserve as a sentinel, is rejected.

The editable BSD flags are `UF_NODUMP`, `UF_IMMUTABLE`, `UF_APPEND`, `UF_OPAQUE`
and `UF_HIDDEN`. Supply the complete flags value, retaining all other bits.
Changing compression, system or unknown bits is unsupported. The workspace
records these flags; it does not emulate macOS process authorization or enforce
immutable/append-only policy on subsequent logical edits.

Birth, modification and access times accept explicit instants from the Unix epoch
through the format's supported range. APFS retains nanoseconds through signed
64-bit nanosecond range; HFS+ truncates to whole seconds and currently admits the
classic HFS+ range through 2040-02-06T06:28:15Z. Historical expanded HFS+ time
profiles are not inferred. Explicit change-time assignment is unsupported: native
`setattrlist` does not assign the requested ctime. Unspecified timestamps, including
ctime, remain recorded under the existing preservation policy. UID/GID edits retain
unspecified mode bits rather than emulating credential-dependent set-ID clearing.

`attributeMode` is omitted for create-or-replace, `create` for `XATTR_CREATE`, or
`replace` for `XATTR_REPLACE`. Names are exact UTF-8 strings, at most 127 bytes,
without NUL. Ordinary attribute edits are limited to 2 GiB minus one byte, the
HFS+ value bound, and any smaller caller budget. This admission limit also applies
to APFS workspace edits; retained source values are unaffected. Empty ordinary
values remain present. Inputs borrow sized sources
and stream through the capture engine. FinderInfo reads exactly 32 bytes for native
validation and normalization. All-zero public FinderInfo becomes absent. HFS+
masks kernel-owned fields and symlink type/creator fields, and rejects the reserved
`hlnk` file type. Setting FinderInfo mirrors its invisible bit to `UF_HIDDEN` on
both formats. Setting HFS+ flags also updates that bit in FinderInfo; APFS chflags
keeps them separate. Removing FinderInfo clears HFS+'s persisted hidden state;
APFS retains its independently stored flag.

Resource forks use `resource-fork` for complete replacement because native
`setxattr` writes a fork at an offset and leaves an old tail. `setxattr` with
`com.apple.ResourceFork` is rejected to avoid silently choosing between those
contracts. A zero-length replacement removes the public fork on both formats.
Fork edits require an ordinary regular file with known, inactive compression.
Replace compressed file contents first when removing compression is intended;
a later operation in the same batch can then supply an independent fork.
`com.apple.decmpfs`, `com.apple.system.Security` and `com.apple.fs.*` attributes are
preserved but cannot be edited through this generic interface. ACL interpretation
and changes to compression storage need their own contracts.

```json
{
  "schema": 1,
  "changes": [
    {"op": "metadata", "path": "Contents/MacOS/Example",
     "metadata": {"mode": {"state": 2, "value": 33261}}},
    {"op": "setxattr", "path": "Contents/Resources/data",
     "attribute": "org.example.build", "attributeMode": "create",
     "contents": "build-metadata.bin"},
    {"op": "resource-fork", "path": "Contents/Resources/data",
     "contents": "complete-resource-fork.bin"},
    {"op": "removexattr", "path": "Contents/Resources/legacy",
     "attribute": "com.apple.FinderInfo"}
  ]
}
```

Schema-4 output records sorted, cumulative `MetadataModified` field names and
`AttributesModified` attribute names, including removals and FinderInfo/flag side
effects. Even assigning the same value records the explicit operation. Content
replacement's compression cleanup remains represented by `DataModified`.
Creation identity and native source identity are retained. `MetadataObjects` and
`AttributeObjects` count reachable objects with these markers, independently of
aliases. Subsequent editing and extraction retain them; schemas 1–3 remain readable.
