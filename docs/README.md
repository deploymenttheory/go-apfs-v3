# Project documentation

- [Architecture](architecture.md): preservation, ownership, errors, and boundaries.
- [Implementation](implementation.md): agreed capabilities and current qualification status.
- [Sessions](sessions.md): file commands, managed scratch and host metadata policy.
- [Sources](sources.json): authoritative references and implementation provenance.
- [Acceptance](../acceptance/README.md): why scenarios exist and how to reproduce them.
- [Qualification harness](qualification.md): coverage obligations, original CI baseline and the evidence-preserving redesign.
- [Native corpus catalog](native-corpus.md): immutable inputs, provenance, bundle resolution and candidate preparation.

Specification coverage, compilation, unit coverage, and native qualification are
different things and must not be presented interchangeably.

- [Packing](packing.md): APFS/HFS+/HFSX construction, complete-disk repacking and preservation guarantees.

- [Editing existing HFS+/HFSX filesystems](hfs-editing.md): commands, allocation/tree mutation, preservation and the completed-output transaction contract.
- [Offline editing qualification](offline-editing-qualification.md): supported profiles and completed qualification criteria.
- [Offline editing regression](offline-editing-regression.md): complete portable/native verdict, requirement mapping and incident outcomes.
- [Offline editing evidence](offline-editing-evidence.md): native controls, original digests, actual output bindings and successful Apple verdicts.
- [Copying into existing images](image-copy.md): recursive import, preservation, aliases, forks and independent native qualification.

- [Offline editing admission](offline-editing-limits.md): supported profiles, protected objects, bounds and refusal policy.
- [APFS history, sharing and encryption](apfs-lifecycle.md): dependency-linked lifecycle work, Apple source basis and independent native controls.
