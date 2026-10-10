# File commands and managed scratch

A session is a named, persistent logical macOS filesystem. The CLI manages its
scratch directory. File paths belong to the session, so Linux and Windows host
permissions, filename rules and symlink behavior do not define the edited result.

```sh
apfs session create --filesystem apfs build
apfs cp --session build --from-host -a ./Example.app /
apfs chmod --session build 0755 /Example.app/Contents/MacOS/Example
apfs mkdir --session build -p /Example.app/Contents/_CodeSignature
apfs cp --session build --from-host ./CodeResources /Example.app/Contents/_CodeSignature/
apfs xattr --session build -w org.example.build release /Example.app
apfs session verify build
apfs session export build ./preserved-result
apfs session remove build
```

`export` creates the existing preservation format, including a portable host
projection and metadata/blobs. Use `pack --session NAME OUTPUT_DMG` to build an APFS or HFS+/HFSX image;
export itself does not materialize a runnable host app bundle. [`pack`](packing.md) builds a new HFS+/HFSX DMG from a session.
No existing image or mounted filesystem is modified by these commands.

## Lifecycle

| Command | Purpose |
| --- | --- |
| `session create --filesystem apfs\|hfsplus\|hfsx NAME` | Start an empty logical volume; APFS also accepts `--case-sensitive` |
| `session open --image IMAGE [--path /SUBTREE] NAME` | Capture a complete tree once, then release the source image and credentials |
| `session status NAME` | Show format, scratch location, revision, counts and defaulted/unavailable metadata |
| `session verify NAME` | Check metadata, all referenced content hashes and stored sizes |
| `session export NAME NEW_DIRECTORY` | Verify and capture the logical tree as a preservation artifact |
| `session remove NAME` | Delete the recognized session under its exclusive lock |

`open` accepts the existing `--partition`, `--volume`, `--password-file`,
`--image-password-file`, `--snapshot-name` and `--snapshot-xid` selectors.
Passwords have the existing exact-byte file/stdin rules and are never retained.
Scratch captured from an unlocked image contains plaintext file content.

Scratch defaults to the host user-cache directory under `go-apfs-v3/sessions`.
`APFS_SCRATCH_DIR` or `--scratch-dir DIRECTORY` selects another storage root.
Use the same root when resuming a named session. Names contain ASCII letters,
digits, dots, underscores and hyphens, start with a letter/digit, and are at most
128 characters. Session names are case-insensitive on every host; Windows device
names and trailing dots are rejected. Cleanup is explicit: closing a command leaves the session intact.
`--json` requests reports; commands have no JSON input format.

## Supported commands

Options can follow operands. Short options combine, such as `mkdir -pm755`.
`--` ends option parsing; use it for a symbolic mode beginning with `-` or a
filename beginning with `-`. Paths are rooted at `/`; relative paths also start
at that logical root. Intermediate symlinks resolve within it, including absolute
targets and `..`. Resolution never escapes into the host filesystem.

| Command | Supported behavior |
| --- | --- |
| `cp SOURCE... DESTINATION` | Copy session contents; `--from-host` selects host source paths; `-R` recurses, `-p` preserves metadata, `-a` means `-RpP`, `-X` omits source attributes/forks, `-n` refuses existing files |
| `chmod MODE PATH...` | Octal or Apple symbolic mode, including copy bits and `X`; `-R`, `-h`, `-H/-L/-P` |
| `chown UID[:GID] PATH...` | Numeric ownership, including `:GID`; same traversal flags as chmod |
| `chflags FLAGS PATH...` | Octal user flags or comma-separated `nodump`, `uchg`, `uappnd`, `opaque`, `hidden`, their supported aliases and `no` forms; same traversal flags |
| `touch PATH...` | Current/fixed clock or `-d RFC3339`, or `-r SESSION_PATH`; `-a`, `-m`, `-c`, `-h` |
| `mkdir PATH...` | `-p` for missing parents; `-m OCTAL_OR_SYMBOLIC_MODE` for final directories |
| `mv SOURCE DESTINATION` | Move one entry; `-n` retains an existing destination |
| `rm PATH...` | Unlink, `-r/-R` recursive directories, `-f` ignores missing paths |
| `ln SOURCE DESTINATION` | Regular-file hard link; `-s` stores a literal symlink target, `-f` replaces an existing non-directory entry |
| `xattr PATH` | List names; `-p NAME PATH` reads, `-w NAME VALUE PATH...` writes, `-d NAME PATH...` removes; `-x` uses hex bytes, `-s` selects the link itself |
| `cp --from-host --resource-fork HOST_FILE DESTINATION` | Replace the complete independent resource fork, including truncation to zero |
| `stat PATH`, `list PATH`, `cat PATH` | Inspect the current logical state; `cat --resource-fork` reads the raw resource-fork attribute |

`xattr -w --value-file HOST_FILE NAME PATH...` imports binary attribute bytes.
Generic writes to compression-owned, security or `com.apple.fs.*` attributes are
rejected. FinderInfo and flags retain the qualified APFS/HFS+ coupling rules.
Ordinary copies preserve opaque attributes; ACL editing and native process
permission enforcement remain outside this phase.

Apple `cp -a` copies regular-file hard-link aliases independently.
`--preserve-links` explicitly retains those relationships within one copy command.
A trailing slash on a source directory copies its contents into the destination.
Host input also accepts the Windows trailing backslash on Windows.
`-H` follows command-line source links, `-L` follows all source links and `-P`
copies the links themselves during recursive copy. Nonrecursive copy follows its
source link. Recursive metadata commands default to physical traversal; `-h`
changes links themselves. Recursive `chown -P` also changes symlink ownership
without following their targets, as Apple chown does. `rm` unlinks a final symlink without traversing its target.

Copying onto an existing regular file retains its identity and updates all its
aliases. New copies contain logical uncompressed data; active compression-owned
storage is not copied as an independent fork. An unrelated `._name` file remains
ordinary content; AppleDouble companions are never inferred.

These are the supported subsets of the Apple command interfaces. Interactive
prompts, shell glob expansion, username/group lookup, symbolic ACL editing,
special-device creation and host export are outside this increment. Unknown
options fail. Recorded ownership and immutable/append flags do not authorize or
prevent logical session edits.

## Metadata and clocks

Session creation defaults are UID/GID 0 and umask 022, configurable using
`--uid`, `--gid` and `--umask`. With `-p`, host observations supply mode, owner,
flags, birth, modification and access time where available. Without `-p`, new
objects use the session creation context and native copy mode rules; replacing
an existing file retains its metadata except command-derived timestamps.

A host that cannot report a field supplies a documented logical default:
regular-file mode 0644, directory mode 0755, symlink mode 0777, session UID/GID,
zero BSD flags and the operation clock for missing timestamps. Defaulted fields
are listed in reports and retained in exported nodes. An explicit metadata
assignment clears that field's default marker. Windows cannot supply POSIX
owners/modes or macOS attributes. Linux inode flags and Windows streams are not
translated into BSD flags or macOS forks. Unavailable attribute enumeration is
recorded separately from an observed empty list. `-X` deliberately omits import
of those attributes. Available values are not silently discarded on read errors.

Each mutating command samples one UTC clock. `session create/open --time RFC3339`
fixes that clock for reproducible commands. APFS retains nanoseconds; HFS+ uses
whole seconds and the currently qualified range through February 2040. `touch`
with an earlier modification time also moves birth time backward, as Darwin does.
Data writes, namespace changes and metadata commands derive the native timestamp
effects qualified by acceptance. APFS empty resource-fork truncation preserves
inode times; nonempty writes and HFS+ fork changes update them.

Logical reads do not update access time. The native reference volumes are mounted
with `noatime` to match this policy and avoid macOS cache-dependent lazy updates.
`touch -a` still changes access time explicitly. Runtime clock observations in the
native reference are compared with the supplied fixed session clock; explicit
historical assignments remain exact. macOS may inject process-security provenance
on newly created native files. That observation is retained but is not fabricated
on portable hosts. Source and copied provenance attributes remain byte-exact.

## Publication, limits and library use

A session handle holds an exclusive cross-process lock. Concurrent opening fails
with a conflict. Returned values support parallel `ReadAt` calls. Session operations and mutations
are serialized by the caller. Values borrow the current revision: close them before mutating
or closing the session. Source-image readers are needed only during capture.

Every mutating command publishes all of its changes together. If any operand,
input read, limit, flush or staging operation fails before publication, the old
revision remains current. This deliberately gives multi-operand commands an
atomic failure contract; native shell tools may leave earlier operands changed.
The revision rename is the commit boundary. Recovery reclaims abandoned staging
and unreferenced blobs under the lock before another command. Process interruption
is tested. Power-loss durability, filesystem journaling and image transactions
are separate future gates.

Payloads are immutable SHA-256 blobs. Unchanged data and attributes are referenced
without reading or copying their bytes. Metadata-only commands still traverse the
bounded logical graph, but do not stream the filesystem again. Opening checks
metadata; the first payload read checks its hash, and `verify`/`export` check all
values. Scratch files are private implementation data and must not be edited by
other programs.

`session.Create`, `Capture`, `Open`, command methods, `Verify`, `Export`, `Report`
and `Close` provide the same behavior to Go callers. The old `Workspace.Edit`
and `ReplaceData` APIs remain available with their explicit preserved-timestamp
contract. Both APIs share one internal graph and metadata engine.

Existing workspace object, entry, depth and streamed-byte limits apply. Session
metadata is capped at 64 MiB, attributes at 4096 per object, and symlink expansion
at 40 links. Ordinary host xattrs are bounded to 64 MiB because host APIs require
contiguous buffers; Darwin resource forks stream. Special files, unresolved
cycles, unrepresentable names and unsupported metadata fail explicitly.
Export schema 5 records derived change-time fields, defaulted metadata and
unavailable attributes while schemas 1–4 remain readable.
