# Native APFS history, sharing and encryption controls

These controls establish Apple-created states for the portable reader and for
subsequent storage-ownership work. `apfs_lifecycle.py` runs only on disposable
GitHub-hosted macOS 15, 26 and 27 VMs. Go never supplies native expectations.

Each producer retains both APFS name policies, native clone sharing and
divergence, hard-link aliases, resource forks, truncation, owner removal,
completed encryption/decryption, changed passwords and independently
credentialed peers. Darwin physical mappings distinguish actual sharing from
equal bytes. The `cp -c` cross-volume result is retained per source version.

Snapshot controls preserve their original ASR parent corpus. Supported API
observations distinguish a successful operation from `EPERM`; the signed
observer's actual launch policy is retained separately. Unavailable positive
operations link to [their blocker](https://github.com/deploymenttheory/go-apfs-v3/issues/74).
Refusal requires unchanged live/historical observations and is never a
successful revert. Separate native deletion and subsequent writable mounts
prove preservation of the surviving history. Captured images are checked and
observed through read-only native mounts before publication.

Disk images remain byte-identical to capture. Original manifests, observations,
command transcripts, sources and manuals are retained as gzip of their original
bytes; manifest digests describe the decompressed bytes. The root capture is
`manifest.json.gz`, and `retention.json` provides a small case/state index,
originating run/commit, original artifact identity, and both captured and retained
file digests. `artifact.json` preserves GitHub's original artifact metadata; its
archive digest is checked before extraction. This is a storage encoding, not a
projection of native names or observations. Public fixture passwords are
intentional test data.

`TestNativeAPFSLifecycleControls` verifies every readable live/historical state,
native sharing evidence, credentials and provenance on Linux, Windows and
macOS. Missing evidence fails. These controls do not qualify portable clone,
snapshot or encrypted writes; each writer needs its own Apple readback,
checker and continued-write verdicts.
