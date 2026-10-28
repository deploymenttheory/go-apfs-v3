# APFS history, sharing and software encryption

The library and CLI read and modify ordinary APFS/APFSX images through portable
file I/O. Managed changes open the source read-only and publish a validated,
completed image at a new path. Linux, Windows and macOS can read that result
immediately; a later macOS mount is not needed to finish an operation.

## Available operations

| Capability | API or command | Current boundary |
| --- | --- | --- |
| Read retained snapshots | `Volume.ListSnapshots`, `OpenSnapshot`, `OpenSnapshotName`; `snapshot list`, historical `list`/`cat`/`extract` | Exact name or XID; borrowed historical reader |
| Edit the live filesystem with retained history | `apfs.ModifyVolume`, `imageedit.Edit`; ordinary image commands | Historical contents, identities and storage remain protected |
| Copy and edit clones | `cp -c`, `imageedit.CopyOptions.Clone`; ordinary writes | Copy-on-write for data/forks/attributes; hard-link aliases retain their inode |
| Keep clone intent through sessions and packing | Session commands and `pack` | Explicit whole-stream lineage; equal bytes alone do not create sharing; partially shared streams refuse fresh packing |
| Delete retained snapshots | `apfs.DeleteSnapshot`, `imageedit.DeleteSnapshot`, `Editor.DeleteSnapshot`; `snapshot delete` | Admitted plaintext, software-encrypted and completed-converted volumes; preserve every survivor and peer |
| Edit encrypted volumes and change passwords | Authenticated mutation, `imageedit.ChangeVolumePassword`; image commands and `passwd` | Admitted software ONEKEY profile; password changes rewrap the existing volume key |
| Construct new encrypted volumes | `apfs.BuildOptions.Encryption`, `VolumeSpec.Encryption`; `pack --volume-password-file` | Fresh keys and identities; independently credentialed ordinary volumes and mixed containers |
| Encrypt/decrypt an existing volume | `apfs.ConvertVolumeEncryption`, `imageedit.ConvertVolumeEncryption`; `encrypt`/`decrypt` | Completed conversion preserves volume/file identities, retained history and physical data/fork sharing |

Snapshot creation and rename are [pending](https://github.com/deploymenttheory/go-apfs-v3/issues/63).
Completed snapshot revert is also [pending](https://github.com/deploymenttheory/go-apfs-v3/issues/65).
Their required successful native create/rename/revert operations depend on
[unresolved execution authority](https://github.com/deploymenttheory/go-apfs-v3/issues/74).
Observed API refusals and readable historical views do not establish successful
creation, naming or revert. The [lifecycle tracker](https://github.com/deploymenttheory/go-apfs-v3/issues/56)
therefore remains open.

## Selecting history and deleting snapshots

Select the on-disk partition index reported by `inspect`. Select an APFS volume
UUID when a container has several volumes. Snapshot names use exact retained
spelling; an XID is a separate selector, never a number parsed from a name.

```sh
apfs snapshot list --json --partition 1 --volume VOLUME_UUID Original.dmg
apfs cat --partition 1 --volume VOLUME_UUID --snapshot-name com.apple.asr.123 \
  Original.dmg /Fixture/generation.txt
apfs snapshot delete --image Original.dmg --output Deleted.dmg \
  --partition 1 --volume VOLUME_UUID --snapshot-xid 123
```

Deletion requires exactly one name or XID and removes only that retained view.
The live filesystem, surviving snapshot names/XIDs/UUIDs, contents, metadata,
forks, shared storage and peer volumes remain intact. Deletion works before or
after admitted encrypted edits, password changes and completed conversion.
Blocks become reusable only after their final owner disappears and the existing
checkpoint-protected free mechanism permits reuse.

`Editor.DeleteSnapshot` can share one `imageedit.Edit` transaction with other
commands. Later commands see the removal. Any failed command invalidates the
whole unpublished transaction, even if its callback ignores the error. The
existing CLI `edit` batch covers ordinary file commands; use `snapshot delete`
for the standalone CLI deletion operation.

## Independent encryption layers

APFS volume encryption protects one filesystem. A DMG envelope protects the
encoded image and may contain plaintext, encrypted or mixed APFS volumes.
Their passwords, keys and policies are independent.

For existing images, `--password-file` authenticates the selected encrypted APFS
volume. Each independently encrypted peer requires
`--volume-password-file UUID=FILE`, even when it is unchanged: allocation
admission accounts for the whole container. `--image-password-file` opens an
encrypted DMG envelope.

```sh
apfs snapshot delete --image Nested.dmg --output Deleted.dmg \
  --partition 1 --volume VOLUME_UUID --snapshot-name com.apple.asr.123 \
  --password-file volume-password --volume-password-file PEER_UUID=peer-password \
  --image-password-file image-password
apfs passwd --image Encrypted.dmg --output Changed.dmg --volume VOLUME_UUID \
  --password-file old-volume-password --new-password-file new-volume-password \
  --volume-password-file PEER_UUID=peer-password
```

Existing-image edits preserve the envelope's password and AES-128/AES-256
strength by default, generating fresh envelope material. Output password
replacement and explicit envelope removal use the separate
[image encryption options](encrypted-image-editing.md).
Deleting a snapshot retains the APFS keys and credentials. A password change
rewraps the existing volume key and rejects the replaced password.

Password files contain exact bytes, including whitespace and final newlines.
`-` consumes stdin through EOF, and only one credential may use it. APFS permits
an explicitly empty password; DMG passwords retain their separate restrictions.
Passwords and keys are omitted from production reports and manifests and are
not literal CLI arguments. Capture recipes use explicitly public fixture passwords.

## Fresh construction and retained-identity conversion

Fresh construction creates a new filesystem from a directory or session. Each
encrypted volume receives independent keys; a volume without a password option
remains plaintext. `pack` can independently encrypt the outer DMG.

```sh
apfs pack --volume Private --directory ./private --volume-password-file private-password \
  --volume Public --directory ./public \
  --encryption AES-256 --output-password-file image-password Mixed.dmg
apfs encrypt --image Original.dmg --output Encrypted.dmg \
  --partition 1 --volume VOLUME_UUID --new-password-file volume-password
apfs decrypt --image Encrypted.dmg --output Plain.dmg \
  --partition 1 --volume VOLUME_UUID --password-file volume-password
```

Conversion changes an existing volume, retaining its UUID, file identities,
snapshot names/XIDs and historical contents, metadata, clone sharing and untouched
peers. Shared physical data/fork ranges retain their addresses and are converted
once; filesystem metadata is rewritten for the target crypto state. Encryption
generates fresh keys and wrapping material. Decrypting the APFS volume preserves
an encrypted outer envelope unless its removal is requested explicitly.
See [volume conversion](apfs-volume-encryption.md) and
[encrypted construction](packing.md#creating-software-encrypted-apfs-volumes).

## Admission, ownership and failure guarantees

The current writer admits bounded, unsealed ordinary volumes in a single-device
container with 4096-byte blocks. Software encryption uses AES-128-XTS ONEKEY with
one native Disk crypto user and a 32-byte combined XTS key. An AES-256 DMG does
not change that inner volume profile. Hardware-bound/per-file keys, other users
or key widths, unfinished conversion, System/Data role-bearing edits, active reaping,
unaccounted allocations and unsupported geometry are explicit refusals.
See the [full editing profile](apfs-editing.md#admitted-profile).

`apfs.InspectStorage` reconciles live and retained versions, shared streams,
physical references, metadata, allocation maps, deferred frees and peer volumes.
For encrypted input, first authenticate every encrypted volume through
`apfs.UnlockMutation` and keep its `MutationSource` open. Accounting and mutation
borrow its keys while raw source reads remain ciphertext. Close the source to
release those keys. Direct engine mutation requires an exclusively owned,
unpublished copy; discard that copy after any mutation error. The managed editor
owns this copy and its key lifetime for callers.

Hard-link aliases do not add stream owners. Removing a live file cannot free
storage retained by a snapshot, clone or peer. Deletion placeholders remain
version barriers when needed by a surviving historical XID. Deferred frees stay
allocated until checkpoint and retained-root protections permit reclamation.
These are offline scratch-copy transactions, not mounted writes or a promise of
physical power-loss atomicity or secure erasure.

Managed operations require a new destination and publish only after validation,
flush and close. Authentication, admission, selection, allocation, cancellation,
short-write, flush and publication failures cannot replace the source or publish
a partial result. An abrupt process termination can leave private temporary files;
see [completed-output publication](output-publication.md).

## Compatibility and evidence

Supported macOS releases start at 26. Current fixture producers and native
verifiers are macOS 26/27; portable conformance runs on Linux, Windows and macOS.
Filesystem structures determine reader admission, rather than an image's origin
OS. Native disk operations run only on guarded disposable VMs. Local checks use
ordinary files; a disk image does not isolate a developer Mac's kernel.

The existing [acceptance pipeline](acceptance.md) captures native states through
`cmd/apfs-fixture` and the declarative [recipes](../acceptance/recipes/README.md),
pins bundles in `acceptance/fixtures.lock.json`, checks portable outputs and
verifies them with Apple checkers, mounted live/history readback and subsequent
native/Go/native writes. The encrypted-history recipe includes successful native
snapshot deletion; arbitrary create/rename/revert authority remains a separate
unresolved prerequisite. Each feature owns its required verification.

Original macOS 15 captures and failed native API experiments remain historical
evidence with their original version identities and digests. The
[prior lifecycle guide](history/apfs-lifecycle.md.gz) is preserved byte-for-byte
inside gzip, with a [digest and source-revision receipt](history/apfs-lifecycle.json).
Its collector/testdata paths describe the historical checkout. That record includes
[native run 38699211349](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/38699211349),
its original 72 states and observed `SIGKILL`/`EPERM`/`EINVAL` outcomes; those facts
are unchanged and do not qualify pending operations or define current CI targets.
The former separate evidence-ledger and whole-programme closure sequence is not a
prerequisite for implementing or documenting an individual capability.
