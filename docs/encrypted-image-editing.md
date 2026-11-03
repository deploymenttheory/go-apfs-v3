# Editing encrypted disk images

Ordinary image commands and `apfs edit` can modify admitted APFS, APFSX, HFS+
and HFSX filesystems inside password-protected DMG envelopes. The source opens
read-only. The editor decrypts into managed private disk scratch, edits the
existing filesystem, validates it, and streams a completed UDRO or UDZO output
through the existing encryption writer before atomic publication at a new path.
It retains unrelated partitions and sectors. Source bytes are never modified,
and an existing destination is never overwritten.

For a partitioned source, specify `--partition INDEX` to select the filesystem.
Use `--volume UUID` as well when selecting among APFS volumes in that partition.

```sh
apfs edit --image Original.dmg --output Edited.dmg \
  --image-password-file image-password -- \
  mkdir -p /Payload/Resources \
  --next cp --from-host ./asset /Payload/Resources \
  --next chmod 0755 /Payload/Resources/asset
```

By default, encrypted input produces encrypted output with the same password
and AES-128 or AES-256 strength. New keys, salt, wrapping IV and identity are
generated for every output. Equal inputs, commands and `--time` produce equal
decoded disk bytes; encrypted file bytes intentionally differ.

`--output-password-file FILE` replaces the password while retaining source AES
strength. Add `--encryption AES-128` or `AES-256` to select strength explicitly;
explicit encryption requires an output password and also supports plaintext
input. `--encryption none` explicitly removes envelope encryption. Omitting
`--encryption` on plaintext input keeps plaintext output.

```sh
apfs chmod --image Original.dmg --output Rekeyed.dmg \
  --image-password-file old-password --output-password-file new-password \
  --encryption AES-256 0755 /Payload/tool
apfs chmod --image Rekeyed.dmg --output Plain.dmg \
  --image-password-file new-password --encryption none 0755 /Payload/tool
```

Password files contain exact bytes: spaces, Unicode and final newlines are
significant. `-` reads stdin through EOF; only one password argument can consume
stdin. Output passwords must contain 1–4096 bytes and no NUL. Passwords do not
appear in reports. `--image-password-file` unlocks the DMG envelope;
`--password-file` supplies a separate APFS volume credential. These credentials
are never substituted for one another. An admitted software-encrypted APFS
volume can be edited inside either AES envelope using both credentials. Supply
`--volume-password-file UUID=FILE` for independently encrypted peers. See
[APFS volume editing and password changes](apfs-editing.md#editing-software-encrypted-volumes)
for the admitted crypto-user profile.

Snapshot deletion and completed APFS volume conversion use these same envelope
options while retaining their separate inner-volume credentials. See
[snapshot deletion](apfs-editing.md#deleting-retained-snapshots) and
[volume conversion](apfs-volume-encryption.md).

The library equivalents include `imageedit.Apply`, `Copy`, `DeleteSnapshot` and ordered `Edit` with
`Options.ImagePassword`. `Options.Encryption` supplies a borrowed
`diskimage.EncryptionOptions`; `KeyBits: 0` keeps an encrypted source's strength
while replacing its password. `Options.Decrypt` explicitly removes encryption
and conflicts with `Options.Encryption`. `Options.VolumePassword` is independent
of the envelope credential. `Options.VolumeCredentials` supplies encrypted
peer passwords. Borrowed
password buffers are neither changed nor retained after the call.

Authentication, admission, command, encoding and cancellation failures before
publication leave the destination absent. Abrupt process termination may leave
private plaintext scratch and incomplete ciphertext beside the intended output;
it cannot publish an incomplete destination. This is the same completed-output
contract used by [plaintext image editing](output-publication.md).
