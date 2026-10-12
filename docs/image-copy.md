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
```

| Option | Behavior |
| --- | --- |
| `-R` | Recurse into directories; retain literal source symlinks by default |
| `-p` | Preserve observed mode, numeric ownership, supported BSD flags and access/modification times |
| `-a` | Apple's `-RpP`; regular files copied from hard-link aliases become independent files |
| `--preserve-links` | Preserve regular-file alias groups within one copy command, independently of the source group |
| `-n` | Refuse an existing file; the whole command publishes no output |
| `-X` | Skip source attributes/forks and retain existing independent destination attributes/forks |
| `-H`, `-L`, `-P` | Follow command-line source links, all source links, or retain recursive source links literally |

An existing directory destination receives the source basename. A directory
source ending in `/` merges its contents into the named destination. Multiple
source operands require an existing destination directory. Existing regular-file
overwrites retain the destination inode and all its aliases. New file copies have
new identities; existing source identities and image bytes remain intact.

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

Image source and destination symlinks resolve inside the selected logical volume,
including absolute targets. Literal recursive links are copied without opening
their target on the host. Traversal is limited to 40 symlink expansions and 128
directory levels. Same-inode copies, copying a directory into itself, cycles,
native name collisions and incompatible destination kinds are refused. ACL,
set-ID and protected filesystem metadata retain the existing write-profile
restrictions. Volume-root metadata assignment is refused by these profiles;
copy into an existing directory beneath the root or create a new root entry instead.
`--resource-fork --from-host` remains the separate single-file complete fork
replacement operation; it cannot be combined with archive flags.

Sessions and images use `internal/copyfile` for copy policy and the same logical
edit tree. Image copying reuses existing allocation, tree, link and metadata
writers. Payloads stream into one owned scratch file before disk mutation, with
128 KiB buffers and a 1 GiB aggregate payload limit across a library batch.
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
