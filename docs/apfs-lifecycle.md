# APFS history, sharing and software encryption

The [lifecycle tracker](https://github.com/deploymenttheory/go-apfs-v3/issues/56)
extends the qualified offline editor. The intended operations are ordinary copy
commands with explicit clone intent, snapshot create/rename/delete/revert,
authenticated encrypted edits, password changes, encrypted construction and
completed encryption/decryption conversion. Linux and Windows must be able to
read every completed result immediately.

Existing readers can open native clones, retained snapshots and admitted software
encryption. Existing mutation deliberately refuses those profiles. Its exclusive
extent-ownership checks and removal of older object-map versions are correct for
the currently admitted profile, but cannot preserve shared or historical owners.
Enabling those inputs requires changing that accounting first.

## Dependencies and completion

| Work | Prerequisite | Tracking |
| --- | --- | --- |
| Independent native controls and source inventory | Qualified offline editing | [Native controls](https://github.com/deploymenttheory/go-apfs-v3/issues/57) |
| Retained-version and shared-storage accounting | Native controls | [Storage ownership](https://github.com/deploymenttheory/go-apfs-v3/issues/58) |
| Safe edits to existing clones | Storage ownership | [Clone editing](https://github.com/deploymenttheory/go-apfs-v3/issues/59) |
| `cp -c` in existing images | Clone editing | [Clone copy](https://github.com/deploymenttheory/go-apfs-v3/issues/60) |
| Session sharing and actual clones in packed images | Clone copy | [Sessions and packing](https://github.com/deploymenttheory/go-apfs-v3/issues/61) |
| Live edits preserving retained snapshots | Storage ownership and clone editing | [Historical preservation](https://github.com/deploymenttheory/go-apfs-v3/issues/62) |
| Snapshot creation and rename | Historical preservation | [Creation and names](https://github.com/deploymenttheory/go-apfs-v3/issues/63) |
| Snapshot deletion and final-reference reclamation | Snapshot creation | [Deletion](https://github.com/deploymenttheory/go-apfs-v3/issues/64) |
| Completed snapshot revert | Snapshot deletion | [Revert](https://github.com/deploymenttheory/go-apfs-v3/issues/65) |
| Existing-image edits inside encrypted DMGs | Native controls | [Encrypted envelopes](https://github.com/deploymenttheory/go-apfs-v3/issues/66) |
| Software-encrypted APFS edits and password changes | Revert and encrypted envelopes | [Authenticated mutation](https://github.com/deploymenttheory/go-apfs-v3/issues/67) |
| New software-encrypted volumes | Session sharing and authenticated mutation | [Encrypted construction](https://github.com/deploymenttheory/go-apfs-v3/issues/68) |
| Existing-volume encryption/decryption conversion | Revert, authenticated mutation and encrypted construction | [Conversion](https://github.com/deploymenttheory/go-apfs-v3/issues/69) |
| Combined lifecycle and fault qualification | All implementations | [Combined qualification](https://github.com/deploymenttheory/go-apfs-v3/issues/70) |
| Permanent source/output/verdict bindings | Combined qualification | [Evidence](https://github.com/deploymenttheory/go-apfs-v3/issues/71) |
| Documentation and completion audit | Permanent evidence | [Closure](https://github.com/deploymenttheory/go-apfs-v3/issues/72) |

Each implementation adds its own independent native capture, portable replay and
Apple checker/readback/continued-write requirements. Combined qualification adds
cross-capability scenarios; it does not postpone individual compatibility gates.
Issues remain open until their stated requirements are actually satisfied.

## Source basis

[Apple's APFS reference](https://developer.apple.com/support/apple-file-system/Apple-File-System-Reference.pdf)
describes stream references, physical extent references, retained object-map
versions, snapshot metadata/name records and encryption state. In particular,
creating a snapshot moves the current extent-reference tree into the snapshot
and starts an empty live tree. Revert fields request work during a later native
mount; a portable writer must instead publish a completely reverted state.

Pinned [Apple cp C](https://github.com/apple-oss-distributions/file_cmds/blob/659a8a301e2acf0343f8b8673a154a2ca4d07084/cp/utils.c)
calls `clonefileat` for `-c`, removes an existing destination before the clone
attempt, and falls back to copying only for `EXDEV` or `ENOTSUP`. That differs
from ordinary destination truncation. Recursive and preservation options must
compose with those decisions. The separate
[copyfile API](https://github.com/apple-oss-distributions/copyfile/blob/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile.3)
also has best-effort and forced clone flags, optional ACL copying and an explicit
cloned-state observation. Equal bytes alone cannot establish shared storage.

The pinned [XNU snapshot dispatcher](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/vfs/vfs_syscalls.c)
checks snapshot entitlements before create/rename/delete/revert syscalls, even
for root. Its rename path refuses an existing name with `EEXIST`. Public C source
establishes these API rules; it does not supply the private APFS implementation.
ASR snapshot retention, Apple inventory and native mounts remain the independent
creation/reading control. ASR-generated names do not qualify arbitrary Unicode
names or successful native rename. Those controls remain required before the
snapshot creation/name implementation can be completed.

Software volume encryption and DMG envelope encryption are separate. Current
APFS keybag admission unwraps a 32-byte combined XTS key, corresponding to
AES-128-XTS; the AES-256-XTS primitive alone does not establish a native volume
profile. Future encrypted construction uses secure randomness. Passwords travel
through the existing exact-byte file/stdin interfaces and stay out of production
logs, fingerprints and manifests. The native controls use explicitly public
fixture passwords, as the existing encryption families do.

## Native control family

`acceptance/native/apfs_lifecycle.py` extends the existing compatibility workflow,
without adding profile jobs or another capture mode. Its current controls are:

- Both APFS name policies: native `cp -c`, independent inode identity, data and
  resource-fork physical sharing through Darwin `F_LOG2PHYS_EXT`, ordinary-copy
  nonsharing, replacement of an existing hard-link destination, cross-volume
  fallback, independent data/fork/metadata writes, truncation and owner removal.
- Settled native encryption and decryption, changed-password rejection/acceptance,
  encrypted clone writes, a plaintext peer and a newly created independently
  credentialed encrypted peer. Every completed state is detached, retained,
  reattached read-only, natively checked and observed. Migration probes must show
  an explicitly settled state before the completed reference is published.
- Actual snapshot revert from the older of two retained ASR snapshots, using
  Apple's documented `apfs.util -R` and a subsequent writable mount. The original
  snapshot corpus and digests remain unchanged. Live and every remaining
  historical state are read from native mounts of the final image.

The Go acceptance family checks each native state on Linux, Windows and macOS:
volume identity, name policy, locked/unlocked credentials, files, links, forks,
attributes, metadata and every retained historical view. Fresh controls come from
macOS 15, 26 and 27. Missing evidence fails rather than becoming a skip.

The collector and its C storage observer require `GITHUB_ACTIONS=true` and
`RUNNER_ENVIRONMENT=github-hosted` before opening files or invoking native tools.
Local checks use ordinary-file Go replay and mocked orchestration only. A disk
image does not isolate a working Mac's kernel.

Native capture and replay are still pending for the new controls. Their results
will establish the reference profiles, including any platform differences;
source review or passing mocked tests must not be reported as native success.
Conversion of retained encrypted history and successful arbitrary snapshot naming
have their own required controls in the corresponding implementation tickets.
