# Phase 5 completion: offline image editing

This is one implementation phase, with one completion gate. Original evidence
remains read-only. Ordinary file commands edit managed scratch and publish a
validated new image. Native filesystem commands run exclusively in disposable
GitHub-hosted VMs; local replay uses ordinary files and Go tools.

Phase 5 durability means completed-output publication, including precise failure
and persistence outcomes. Continuous in-place commits and live journal writing
belong to phase 7 writable mounts. Snapshot lifecycle and snapshot-preserving
mutation, clones and encrypted modification remain phase 6. This boundary is an
explicit roadmap correction, rather than a claim that those capabilities exist.

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
  corruption and later-phase features. Record Apple source/provenance for ports.
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

Each scenario records its purpose, native source version, operation, independently
observed outcome, original hashes and commands. Fresh CI capture does not update
the retained baseline. Equivalent portable outputs may share native verification
after byte equality is established. Fault controls supplement Apple evidence;
they do not supply native expected filesystem semantics or establish physical
storage power-loss guarantees.

All checkboxes initially remain open. Research, compilation and an isolated test
are progress, not qualification or phase completion.
