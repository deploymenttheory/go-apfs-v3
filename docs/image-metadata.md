# Metadata in existing filesystem images

The ordinary file commands use `--image SOURCE --output NEW_IMAGE` for APFS,
HFS+ and HFSX. The source is read-only, scratch is internal, and a completed
UDRO/UDZO image is published without overwriting a destination. No edit recipe
or workspace configuration is required.

```sh
apfs chown --image Original.dmg --output Owner.dmg 0:20 /Payload/file
apfs touch --image Owner.dmg --output Times.dmg -a -d 2025-06-07T08:09:10.123456789Z /Payload/file
apfs chflags --image Times.dmg --output Flags.dmg hidden,nodump /Payload/file
apfs xattr --image Flags.dmg --output Attributes.dmg -w --value-file ./value.bin org.example.metadata /Payload/file
apfs xattr --image Attributes.dmg -p -x org.example.metadata /Payload/file
apfs xattr --image Attributes.dmg --output Removed.dmg -d org.example.metadata /Payload/file
```

`chown` takes numeric `UID`, `UID:GID` or `:GID`; unspecified fields are retained.
The caller's Linux/Windows/macOS account database and permissions are not used
to invent macOS ownership. Ordinary ownership assignment clears set-ID bits,
including assignment of unchanged IDs, following Apple's `vnode_authattr` path
and retained native controls. Numeric ownership remains separate from opaque
filesec GUIDs; offline edits do not emulate process authorization.

`chflags` changes the qualified user flags: nodump, user immutable, user append,
opaque and hidden. Symbolic `no...` forms remove selected flags; octal values
replace only those user bits, preserving compressed and system flags. Explicit
`chflags` can clear user immutable/append; other mutations of such objects are
refused. Protected system objects, system flags and private directories remain
outside the admitted profile.

HFS file immutability is also stored in the catalog's locked bit. Apple
`catrec_update` synchronizes it on writes and `getbsdattr` reconstructs public
immutable flags from it on reads. `hfsplus/metadata.go` shares these rules across
readback and mutation, including legacy locked records without a BSD flag.

`touch -a` changes access time; `-m` changes modification time; the default
changes both. `-d` takes RFC3339 with optional fractional seconds and `-r` borrows
the selected timestamps of an image file. These options are mutually exclusive.
`-c` leaves absent files absent; ordinary missing files use the existing creation
policy. APFS retains nanoseconds, HFS+ stores whole seconds. Native `utimes`
creation-time clamping is applied when a new mtime predates birth time. Unselected
times and unrelated fields remain recorded. `--time` independently supplies the
whole-second transaction/change clock; fixing it makes plaintext output reproducible.

`chmod`, `chown` and `chflags` support physical `-R` traversal and `-P`.
Paths never traverse symlinks. `-h` selects a symlink itself for metadata commands;
`xattr -s` selects it for attributes. Recursive ownership includes physical links;
recursive chmod/flags skip links unless `-h` is explicit. Each shared inode is
changed once per traversal. Existing hard-link identities and contents survive.

`xattr` lists names or reads exact value bytes without an output image. `-x`
accepts/prints hexadecimal; `--value-file` streams a binary value for `-w`.
Writes create or replace an ordinary attribute and `-d` requires it to exist.
The library additionally exposes create-only and replace-only conditions.
Empty values are present attributes. Values move between inline and allocated
storage; retiring/reusing extents follows the filesystem's existing transaction
engine. FinderInfo, independent resource forks and unrelated attributes survive
ordinary attribute edits. Explicit resource-fork edits retain the existing
compression ownership restrictions. Compression, security and private filesystem
attributes cannot be overwritten through the ordinary opaque-value API.

Resource-fork `xattr -w` follows Apple's stream API: it writes at position zero,
retains a longer existing tail, and a zero-byte write leaves the fork unchanged.
Use explicit `xattr -d` to remove a fork, or `cp --resource-fork` to replace it.
Apple HFS `hfs_vnop_setxattr` calls `VNOP_WRITE` without truncation; independent
APFS controls establish the same behavior. Current-transaction records supply
retained tails, so successive writes operate on the results of earlier changes.

HFS FinderInfo is catalog storage. Its public setter masks reserved fields,
preserves document/date-added/generation values, retains private symlink type
and creator, and mirrors hidden flags. Removing it clears HFS's public hidden
state. APFS stores FinderInfo separately; removing it retains the BSD hidden bit.
These differences follow Apple C and independent macOS 15/26/27 observations.

APFS native ordinary attribute streams can carry flag `0x10`, absent from the
2020 public reference. All three native versions independently show that their
physical extent owner is the stream ID; legacy attributes and resource forks use
the owning inode ID. `apfs/build_records.go` centralizes that distinction for
validation and mutation. Updates preserve the marker while using stream storage;
embedded replacements remove it. Unknown flags and shared streams remain refused.
No private APFS C implementation is claimed as a source port.

The admitted image profiles remain those in [APFS editing](apfs-editing.md) and
[HFS editing](hfs-editing.md). HFS attribute creation can initialize an absent
attributes file using Apple's allocation, header and node-map implementation.
The shipped formatter's zero-initial-size option failed with an overlapping-
extent error; independent controls instead build the pinned Apple C formatter
and capture actual first-attribute writes on disposable macOS VMs. The
[offline editing gate](offline-editing-qualification.md) requires those controls
and Apple checks of the portable outputs.

The required existing-image edit families capture actual Apple before/after
metadata, full timestamp precision, complete raw attributes, identities and
signatures. They cover both name policies, both admitted HFS journal profiles,
new-volume/growing attribute trees, long keys, inline/stream transitions and storage
reuse. Linux, Windows and macOS replay the same operations, preserving sources
and producing identical plaintext bytes. Every Mac verifies exact raw copies
with Apple fsck, mounted readback and codesign. Subsequent kernel attribute writes
become Go inputs; separate Apple-only copies supply complete continuation
expectations, followed by another native readback. Native tools run only on
disposable CI VMs. Untouched applications retain valid signatures; edits to
signature-sensitive values still require the consumer's signing operation.
