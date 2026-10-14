# Offline image editing qualification

Offline image editing has one required completion gate. Original evidence
remains read-only. Ordinary file commands edit managed scratch and publish a
validated new image. Native filesystem commands run exclusively in disposable
GitHub-hosted VMs; local replay uses ordinary files and Go tools.

Offline editing durability means completed-output publication, including precise failure
and persistence outcomes. Continuous in-place commits and live journal writing
require writable-mount support. Snapshot lifecycle, snapshot-preserving mutation,
clones and encrypted modification have separate qualification requirements
and remain pending.

## Required work

- [ ] APFS: replace the blanket 1 GiB admission ceiling with validated geometry
  and bounded allocation/tree resources; qualify native larger images.
- [ ] APFS: select an ordinary plaintext volume in a multi-volume container,
  account all volume ownership, preserve untouched volumes, and enforce native
  reserves/quotas.
- [ ] APFS: maintain directory-stat records and inheritance, and qualify
  checkpoint/free-queue capacity, repeated growth, removal and allocation reuse.
- [ ] HFS+/HFSX: initialize absent attributes files from Apple's implementation
  and independent first-attribute controls.
- [ ] HFS+/HFSX: grow fragmented metadata files, handle overflow extents and
  extend B-tree node maps; qualify splits, deletion and root collapse.
- [ ] Semantics: inventory every mutation refusal, finish ordinary ACL/set-ID
  and inheritance cases, and separate protected objects, format/resource limits,
  corruption and unsupported capabilities. Record Apple source/provenance for ports.
- [ ] Editing lifecycle: let ordered ordinary commands share managed scratch
  and publish once, preserving source geometry and native identities. Commands
  retain their existing flags; no user-authored JSON edit recipe is introduced.
- [ ] Publication: qualify source immutability, output validation, file flush,
  host persistence, publication without overwrite, post-publication errors,
  cancellation, short writes, ENOSPC, process death and cleanup.
- [ ] Evidence: retain immutable macOS 15/26/27 controls; compare Linux,
  Windows and macOS outputs independently with Apple checks, exact file/fork/
  metadata/link observations, signatures and subsequent native modification.
- [ ] Closure: pass the full regression gate, document exact supported profiles
  and remaining restrictions, and update the roadmap only after qualification.

## Completion evidence

The [evidence index](offline-editing-evidence.md) connects the retained native
controls to their original hashes, replay families and current CI campaigns.
Pending verdicts remain explicit until the complete gate passes.

Each scenario records its purpose, native source version, operation, independently
observed outcome, original hashes and commands. Fresh CI capture does not update
the retained baseline. Equivalent portable outputs may share native verification
after byte equality is established. Fault controls supplement Apple evidence;
they do not supply native expected filesystem semantics or establish physical
storage power-loss guarantees.

All checkboxes initially remain open. Research, compilation and an isolated test
are progress, not qualification or completion.

## Retained capture naming

Fixture directories and replay contracts use capability names. Each renamed
capture retains `original-manifest.json.gz` and its original SHA-256 in the
readable manifest. The readable manifest changes only its contract name,
collector filename references and temporary-directory labels, and adds the
original-manifest digest. Native expected values and disk digests are unchanged.

Historical command logs, collector sources and diagnostic text containing old
delivery labels are compressed without changing their decoded bytes. Digest
checks accept either the original filename or its `.gz` archive and verify the
decoded bytes against the original capture digest. New CI captures use the
capability names directly.

The [admission inventory](offline-editing-limits.md) groups remaining refusals by
required context, protected objects, unsupported storage, resource bounds and
corruption. The [compatibility workflow](../.github/workflows/offline-editing.yml)
requires all seven native scenario families and every portable host/source pair.

## Verifier corrections

A verifier correction can recheck archived portable images without collecting
new native controls or rebuilding identical outputs. The source Actions run must
be completed, and every capture and Linux/Windows/macOS output job for the selected
capability must have succeeded for macOS 15, 26 and 27 sources. The admission check
reads every page of job results and compares the source commit with the current
commit. Changes to Go code, Go tests, fixtures, dependencies or native construction
code require fresh outputs.

For example, recheck directory statistics on all three disposable macOS runners:

```sh
gh workflow run native.yml --ref BRANCH \
  -f offline_edits_only=true \
  -f readback_run=SOURCE_RUN_ID \
  -f offline_reference_kind=stats
```

The rerun verifies the original Linux, Windows and macOS output bytes and performs
the same Apple checks and subsequent native modifications. It qualifies the
selected capability; the full compatibility gate still requires all capabilities.
Existing directories bind their earlier statistics to native object identity,
including across moves. New directories have no before-generation, so their
independent native after-state supplies exact counts, allocated bytes and
origin/inheritance requirements.

## CI failure diagnosis and recovery

The test contract remains native Apple capture, portable Go replay on all three
hosts, and independent Apple checks and continued writes on all three macOS
versions. Failed setup or capture is missing evidence; it never changes an
expected filesystem result or counts as qualification.

Native creation through the shared command recorder is attempted once with its
existing 120-second deadline. A failed or timed-out `hdiutil create` retains its
original status, stdout and stderr. On a guarded disposable VM, the recorder
also captures `sw_vers`, `hdiutil info -plist` and `diskutil list -plist`, each with
a ten-second deadline. The existing command log retains every probe result;
`creation-failure.json` adds runner identity, the resolved hdiutil path/hash and
partial-output file metadata. The existing artifact upload includes these files.
Probes neither retry creation nor modify, detach or delete images/devices.
Probe failure cannot replace the original creation error. Successful creation
adds no probes and follows the existing native fixture recipe.

The [macOS 27 creation incident](https://github.com/deploymenttheory/go-apfs-v3/issues/42)
returned process status 1 with “Resource busy”; it did not return numeric errno
EBUSY. Apple's installed `hdiutil(1)` describes EBUSY as unavailable exclusive
access, but the failed job did not capture the resource or lock owner. The
[later successful capture](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/38429354258/job/115408067338)
used the same collector sources and creation arguments, apart from its private
path, on the same recorded OS build and runner image version. Both runs emitted
the deprecation warning. This evidence does not justify changing filesystem
expectations or adding an automatic creation retry. The underlying resource
remains unidentified; additional failure diagnostics address that evidence gap.

Runner action-download DNS failures and interrupted repository fetches occur
before the native fixture recipe. Recover a completed campaign through the
existing failed-job rerun facilities, retaining previous successful jobs and
original failed logs. Account for every dependent capture, replay and readback;
a cancelled or skipped job still needs a qualifying result. Constructor changes,
including command-recorder changes, require fresh capture/replay under the
existing archived-input admission rules.
