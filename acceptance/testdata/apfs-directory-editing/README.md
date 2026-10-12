# Native APFS directory-edit references

Immutable Apple-created source, create/move/unlink and removal/reuse states from
macOS 15, 26 and 27, captured in
[run 38177430983](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/38177430983)
at commit `a1e5e7d` on disposable VMs. Both APFS name policies use 128 MiB raw
containers. Go did not create these images or expected observations.

Each version's manifest binds compressed and decoded image hashes, observations,
OS/build, native tool hashes, exact capture sources and command transcripts.
The reference set is about 6 MiB compressed and is replayed locally without
mounting images. CI refreshes independent captures on each required macOS version;
those captures do not automatically replace these retained references.

The scenario grows 96 long-name files under nested directories, moves files and
directories, replaces a destination, performs a case-only rename, moves symlink
entries, changes directory mode, and unlinks a primary hard link. The final state
retains one sibling record for the last hard link, removes compressed files and
symlink entries, deletes half the growth records and allocates a new subtree.
Native checker status and application signature verification accompany each state.
The Go/native/Go/native continuation separately qualifies final hard-link removal.
