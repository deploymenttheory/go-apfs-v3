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
extracted subtree are retained. Newly created objects have `Created` set and a
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
