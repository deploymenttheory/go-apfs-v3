# Editing encrypted disk images

Ordinary image commands and `apfs edit` can modify admitted APFS, APFSX, HFS+
and HFSX filesystems inside password-protected DMG envelopes. The source opens
read-only. The editor decrypts into managed private disk scratch, edits the
existing filesystem, validates it, and streams a completed UDRO or UDZO output
through the existing encryption writer before atomic publication at a new path.
It retains unrelated partitions and sectors. Source bytes are never modified,
and an existing destination is never overwritten.

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
are never substituted for one another. Software-encrypted APFS volume writes
remain unsupported, including with correct credentials inside an unlocked DMG.
Wrong supplied volume credentials fail authentication before that write refusal.

The library equivalents are `imageedit.Apply`, `Copy` and ordered `Edit` with
`Options.ImagePassword`. `Options.Encryption` supplies a borrowed
`diskimage.EncryptionOptions`; `KeyBits: 0` keeps an encrypted source's strength
while replacing its password. `Options.Decrypt` explicitly removes encryption
and conflicts with `Options.Encryption`. `Options.VolumePassword` is independent
of the envelope credential and does not enable encrypted APFS writes. Borrowed
password buffers are neither changed nor retained after the call.

Authentication, admission, command, encoding and cancellation failures before
publication leave the destination absent. Abrupt process termination may leave
private plaintext scratch and incomplete ciphertext beside the intended output;
it cannot publish an incomplete destination. This is the same completed-output
contract used by [plaintext image editing](output-publication.md).
