# Converting existing APFS volume encryption

`apfs encrypt` and `apfs decrypt` change one existing ordinary APFS/APFSX volume
and publish a completed new image. They retain its UUID, file identities,
snapshot names/XIDs and historical contents, clone sharing, resource forks,
metadata and untouched peer volumes. Physical data/fork extents retain their
addresses and sharing; filesystem metadata is rewritten for the target crypto
state. Fresh construction through `pack` assigns new identities and is a
separate operation.

```sh
apfs encrypt --image Original.dmg --output EncryptedVolume.dmg \
  --partition 1 --volume VOLUME_UUID --new-password-file volume-password.bin
apfs decrypt --image EncryptedVolume.dmg --output PlainVolume.dmg \
  --partition 1 --volume VOLUME_UUID --password-file volume-password.bin
```

The partition index is the on-disk index reported by `inspect`. Select a volume
UUID when the APFS container has several volumes. `--format UDRO|UDZO` selects
the completed output encoding. `--time RFC3339` supplies the whole-second
operation clock; file and historical metadata retain their original clocks.
Use `--json` for a versioned report containing `volumeEncryption`: the previous
and resulting encrypted state, `completed: true`, and the Disk crypto-user UUID
when encrypting. Reports contain no passwords or wrapping material.

The result is already converted: portable readers on Linux, Windows and macOS
can read it immediately, and a later macOS mount is not required to finish the
operation. An attempt to encrypt an encrypted volume or decrypt a plaintext
volume is an explicit invalid transition.

## Independent credentials and envelopes

APFS volume encryption and DMG envelope encryption are separate layers.
`--new-password-file` supplies the new inner volume credential for `encrypt`;
`--password-file` authenticates the selected encrypted volume for `decrypt`.
Independently encrypted peers require their own repeated
`--volume-password-file UUID=FILE` arguments for container-wide ownership
validation. Their passwords and keys remain unchanged.

On macOS, explicitly lock an attached encrypted source volume before detaching
it when preparing to use a converted copy with the same UUID. macOS can retain
an unlock across detach and report the fresh-key copy as unlocked while refusing
to mount or authenticate it. The library changes ordinary image files; it does
not clear the host's cached unlocks or change its mounts.

For an encrypted DMG, supply `--image-password-file FILE`. The output preserves
its password and AES strength by default, even when decrypting the inner APFS
volume. Existing `--output-password-file` and `--encryption AES-128|AES-256|none`
options independently change the outer envelope policy. See
[encrypted image editing](encrypted-image-editing.md).

Password files contain exact bytes, including whitespace and final newlines.
`-` reads stdin through EOF; only one credential may consume stdin. APFS permits
an explicitly empty password and bounds passwords to 4096 bytes. The existing
DMG envelope restrictions apply separately. Keys and wrapping salts generated
for encryption use secure randomness, so encrypted volume bytes differ between
independent encryptions even with the same input and clock. Conversion does not
promise secure erasure of bytes belonging to previously deleted files.

## Library and transaction lifetime

`imageedit.ConvertVolumeEncryption` takes ordinary `imageedit.Options` and an
`apfs.EncryptionConversion`. Set `Encrypt: true` and supply a non-nil borrowed
`Password` to encrypt; use an empty conversion request to decrypt with
`Options.VolumePassword`. Image and peer credentials use their existing option
fields. Neither the caller's password buffers nor source image are modified.

`Editor.ConvertVolumeEncryption` can participate in `imageedit.Edit` with later
file edits and password changes. The unpublished transaction owns the resulting
keys; later commands address its current state without retaining passwords.
Any command failure invalidates the entire transaction, including when the
callback ignores that failure. An expired editor cannot use the keys.

The engine equivalent is `apfs.ConvertVolumeEncryption` on a
`*apfs.MutationSource`. Call `apfs.UnlockMutation` first, including for a
plaintext selected volume, and authenticate all encrypted peers. Close that
source to release its keys. The engine operates on an exclusively owned,
unpublished copy; any error invalidates that copy. The managed image editor
provides source immutability, flushing, validation and no-overwrite publication.

## Admission and failure behavior

Conversion uses the existing bounded 4096-byte-block ordinary-volume writer and
ownership accountant. The admitted encryption profile is software AES-128-XTS
ONEKEY with one native Disk crypto user. System/Data roles, hardware-bound or
per-file keys, unqualified users/key widths, unfinished native conversions,
active reaping, unaccounted ownership and unsupported geometry fail explicitly.
Snapshot create/rename/revert and snapshot deletion on encrypted or completed-
converted volumes have their own writer admission; conversion does not enable them.

Cancellation, allocation pressure, short writes, flush/encoding failures and
interrupted publication cannot publish a partially converted destination or
change the source. An existing destination is never overwritten. Abrupt process
termination can leave private temporary files; the existing
[completed-output contract](output-publication.md) applies.

Native conversion controls and product output checks run only on guarded
disposable hosted macOS 26/27 VMs. Portable verification checks live/historical
contents, identities, forks, credentials and peers; native verification checks
completed storage, physical clone/fork sharing and further native/Go/native
writes. Original native evidence and digests remain unchanged.
