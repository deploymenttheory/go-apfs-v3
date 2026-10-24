# Copying into existing filesystem images

`cp --image SOURCE --output NEW_IMAGE` copies files and directory trees within
the admitted APFS, HFS+ and HFSX filesystem profiles. `--from-host` imports host
files or directories. The original image remains read-only; managed scratch and
the existing completed-output transaction publish a new image.

```sh
apfs cp --image Original.dmg --output Apps.dmg -a /Staging/Example.app /Applications
apfs cp --image Apps.dmg --output Framework.dmg -a /Staging/Example.framework /Library/Frameworks
apfs cp --image Original.dmg --output Imported.dmg --from-host -RX ./payload /Payload
apfs cp --image Original.dmg --output Linked.dmg -a --preserve-links /Staging /Copied
apfs cp --image Original.dmg --output Replaced.dmg -p /Staging/file /Payload/existing
apfs cp --image Original.dmg --output Cloned.dmg --uid 0 -c /Payload/file /Payload/clone
```

| Option | Behavior |
| --- | --- |
| `-R` | Recurse into directories; retain literal source symlinks by default |
| `-p` | Preserve observed mode, numeric ownership, supported BSD flags and access/modification times |
| `-a` | Apple's `-RpP`; regular files copied from hard-link aliases become independent files |
| `-c` | Request distinct APFS clone inodes sharing stored streams; report ordinary-copy fallback where cloning is unavailable |
| `--preserve-links` | Preserve regular-file alias groups within one copy command, independently of the source group |
| `-n` | Refuse an existing file; the whole command publishes no output |
| `-X` | Skip source attributes/forks and retain existing independent destination attributes/forks |
| `-H`, `-L`, `-P` | Follow command-line source links, all source links, or retain recursive source links literally |

An existing directory destination receives the source basename. A directory
source ending in `/` merges its contents into the named destination. Multiple
source operands require an existing destination directory. Existing regular-file
overwrites without `-c` retain the destination inode and all its aliases. New file copies have
new identities; existing source identities and image bytes remain intact.

`cp -c` follows Apple's clone policy. For a regular file it replaces an occupied
destination entry with a new inode, leaving other aliases of the old destination
intact. It replaces a destination symlink itself and follows a command-line
source symlink. `-cR` retains recursive source symlinks and copies regular-file
aliases as separate clone inodes; `--preserve-links` explicitly retains their
alias group. `-n` refuses an occupied destination, and `-cX` is invalid.

An APFS clone retains source birth, modification and access times, flags, stored
compression, forks and ordinary attributes. Its change time is the command
clock. Set-ID bits are cleared, ownership follows the explicit logical actor,
and its ACL inherits from the destination directory. The source ACL and its
existing sharing remain unchanged. `-p` does not replace this clonefile ACL
policy. Changes to a clone's data, fork or attribute detach only that stream;
metadata and hard-link aliases retain their distinct relationships.

HFS+/HFSX destinations and host imports use ordinary copy policy when a clone
cannot be made. JSON `clones` entries and plain diagnostics report each requested
regular-file clone with source, destination, `cloned` and a fallback reason where
applicable. Equal contents never establish sharing. These results describe the
completed output; unpublished failures return no successful clone outcomes.
`Editor.Copy` inside an `imageedit.Edit` callback reports its private scratch
operation, while the enclosing result reports final publication.

Ordinary copying reads logical decompressed contents. Compression-owned storage
is removed from the copy; ordinary attributes and independent forks transfer as
Apple's public copy view exposes them. Destination attributes absent from the
source are removed, except retained quarantine and filesystem-owned values.
Recognized inactive compression metadata is copied as opaque bytes. Malformed or
unsupported inactive headers are omitted with an explicit report, following
Apple's copyfile header checks; they never substitute for ordinary file data.
Copied forks replace their complete previous value, including shrinking. APFS
resource forks remain stream-backed even when shorter than ordinary inline
attributes; write admission rejects embedded forks, as Apple's checker does. `-X`
keeps an independent existing fork; replacing compressed data still removes its
compression-owned storage.

Apple's public APFS and HFS copy views hide an independent fork on an actively
compressed source, including an inline compressed file. The shared copier follows
these independently captured rules. An image-source omission is reported with source/destination,
attribute name and reason in JSON or plain diagnostics. Raw source storage stays
intact and remains available to preservation extraction. This distinction is
qualified separately from logical data correctness.

Apple `cp -p` does not assign source creation time directly. Existing creation
times remain; setting an earlier modification time may move creation time earlier
under the filesystem's native rule. New objects use the construction clock with
that same coupling. `--time RFC3339` fixes that clock for reproducible output.
APFS retains nanoseconds; HFS uses whole seconds within the existing qualified
date range. Metadata unavailable from a host uses destination creation defaults
and appears in the report. Unavailable attribute enumeration remains distinct
from an observed empty list. Windows host streams and Linux inode flags are not
interpreted as macOS forks or BSD flags.

Archive imports capture Darwin host ACLs without following the source link and
apply the ordinary ACL copy policy below. Foreign POSIX/Windows security that
cannot be converted and unavailable observations have distinct typed
`metadataOmissions` in the completed copy report. Observed absence and empty
values remain separate from both results. Packing and reopened-session exports
retain this provenance; none of these paths reconstructs missing Apple metadata
from the host file's earlier history.

For ordered image edits, omission records are COPY-call outcomes. `command` is
the one-based Editor call index and `clockNs` is its explicit operation clock.
A later command may remove or replace that logical path. These events are
reported only when the complete image is published; session and packing reports
instead describe provenance in their current logical tree.

Image source and destination symlinks resolve inside the selected logical volume,
including absolute targets. Literal recursive links are copied without opening
their target on the host. Traversal is limited to 40 symlink expansions and 128
directory levels. Same-inode copies, copying a directory into itself, cycles,
native name collisions and incompatible destination kinds are refused. Ordinary
copies retain destination ACLs. `-p` copies direct source ACL entries followed by
inherited destination entries, independently of `-X`; source inherited entries
do not travel to the new parent. Empty ACLs remain distinct from absent ones.
Set-ID writes and preservation require an explicit logical `--uid`; root writes
retain existing bits and other writers clear them before any requested copied
mode is restored. Protected filesystem metadata retains its write restrictions. Volume-root metadata assignment is refused by these profiles;
copy into an existing directory beneath the root or create a new root entry instead.
`--resource-fork --from-host` remains the separate single-file complete fork
replacement operation; it cannot be combined with archive flags.

Sessions and images use `internal/copyfile` for copy policy and the same logical
edit tree. Image copying reuses existing allocation, tree, link and metadata
writers. Payloads stream into one owned scratch file before disk mutation, with
128 KiB buffers and an aggregate image-copy payload bound derived from the
selected partition geometry. Namespace and object bounds remain separate.
Existing image capacity, ownership and metadata limits still apply. Fixed mutation
batches remain private until a single final publication. An error or interrupted
copy publishes no partial destination; abrupt process death can leave private
scratch. This does not establish mounted journal recovery or physical power-loss
durability. See the [APFS](apfs-editing.md) and [HFS](hfs-editing.md) profile bounds.

Retained Apple-only controls cover macOS 15, 26 and 27, both name policies, and
journaled/nonjournaled HFS. They include signed applications and versioned
frameworks, independent/compressed forks, empty files/directories, Unicode names,
long-key growth, existing hard-link overwrite, archive alias splitting, explicit
alias preservation, trailing-slash merging and host directory imports. A data-only
overwrite exercises Apple's coalesced APFS data/fork physical ownership while
retaining its original fork and aliases. Producer scripts, source bindings,
command/tool evidence and compressed/decoded hashes accompany each corpus.

Linux, Windows and macOS replay every case in UDRO/UDZO with identical image
bytes. Every Mac checks Apple fsck, complete native metadata/content/fork/identity
readback and codesign. Native copying then produces Go continuation inputs;
separate Apple-only copies supply complete expected results for another native
check. All native filesystem tools run on disposable CI VMs. Local replay uses
ordinary file reads and Go writes only.

Ordinary `cp` uses Apple's descriptor-copy mode policy. `cp` opens an existing
file with `O_TRUNC`, then `fcopyfile` snapshots and restores its destination mode
after transferring data. HFS+ clears set-ID bits during truncation for a non-root
writer; native APFS copy controls retain the original bits. The shared copier
models those filesystem effects explicitly. A direct data write has its own
metadata effects; it does not restore the copy-mode snapshot.
