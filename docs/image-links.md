# Links in existing filesystem images

`ln --image SOURCE --output NEW_IMAGE` creates regular-file hard links or symbolic
links in the admitted APFS, HFS+ and HFSX profiles. The source stays read-only and
scratch is managed internally by the same completed-output transaction as other
file commands.

```sh
apfs ln --image Original.dmg --output Linked.dmg /Payload/file /Payload/alias
apfs ln --image Linked.dmg --output Framework.dmg -s A /Payload/Example.framework/Versions/Current
apfs ln --image Framework.dmg --output Replaced.dmg -h -f /Payload/file /Payload/old-link
```

Hard links share the original inode, data, independent resource fork, metadata
and attributes. Linking an existing directory or symlink is outside this profile.
Adding an alias does not copy file data. A first HFS file link moves its original
catalog record into the native private inode directory and creates indirect
named records; its public inode identity stays the same. Additional links retain
the existing chain style, including admitted legacy chains. HFS enforces Apple's
32767-link limit and requires its private inode directory and usable free space.

APFS uses sibling-link/map records and retains the original inode and stream
storage. Its original directory entry acquires a sibling identifier on first
conversion. Removal and rename use the existing primary-link repair, accounting
and final-inode reclamation paths.

`-s` stores the target string literally. Relative, absolute and dangling targets
are supported without opening their destination on the host or in the image.
The current shared profile admits valid UTF-8 targets of 1–1023 bytes with no NUL.
New symlinks use 0755, parent UID/GID and the supplied image clock; HFS stores the
target in its data fork and APFS stores its filesystem-owned symlink attribute.

An existing directory destination receives the source basename. Existing entries
are refused unless `-f` is explicit. `-h` is required when replacing a destination
symlink, selecting the link itself. Image paths never traverse symlinks; implicit
destination-link traversal is unqualified and refused. Replacing a different
alias of the same inode is allowed; replacing the source entry itself is refused
before removing it. Failed batches publish no output. `--format UDRO|UDZO`,
`--partition` and the reproducible `--time` clock follow the other image commands.

HFS record rules adapt the pinned Apple `hfs_makelink`, `createindirectlink`,
`cat_createlink`, `cat_rename` and `hfs_vnop_symlink` implementations. Fresh HFS
construction and mutation share the indirect-record encoder. APFS follows the
published sibling structures and independent native observations; no private
APFS C writer is claimed as a port. See the exact [source inventory](sources.json).

The existing edit families retain Apple-created before/link/growth/removal images
on macOS 15, 26 and 27. Cases cover first-file conversion, existing aliases,
compressed files, independent forks, empty files, long-name tree growth, literal
symlink targets, forced replacement and final-link removal/reuse. A native signed
versioned framework starts with only its symlinks removed; restoring their exact
targets must restore a valid signature. The untouched signed application is
checked independently throughout.

Linux, Windows and macOS replay these controls with equal output hashes. Every
Mac runs Apple fsck, complete mounted identity/metadata/fork/target comparisons
and codesign. Subsequent Apple link creation becomes Go input; a separate
Apple-only copy supplies complete continuation expectations, followed by another
native check. New IDs use a bijection carried across the full lifecycle, preserving
all original IDs and distinguishing retired objects. Clock normalization is limited
to individually observed ctime/mtime effects. Native tools run only on disposable
CI VMs; local regression uses file reads and Go writes.

The existing [APFS](apfs-editing.md) and [HFS](hfs-editing.md) bounds still apply.
Directory hard links, snapshot/clone-bearing APFS, broader encryption and live
journal transactions retain their separate qualification gates.
