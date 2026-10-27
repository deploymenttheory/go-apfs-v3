# Project documentation

- [Architecture](architecture.md): preservation, ownership, errors, and boundaries.
- [Implementation](implementation.md): agreed capabilities and current qualification status.
- [Sessions](sessions.md): file commands, managed scratch and host metadata policy.
- [Sources](sources.json): authoritative references and implementation provenance. Evidence paths under `acceptance/` refer to the retired harness in git history until the new corpus replaces them.
- [Acceptance](acceptance.md): the fixture corpus, the portable tier, the native tier and how to add a recipe.

Specification coverage, compilation, unit coverage, and native qualification are
different things and must not be presented interchangeably.

- [Packing](packing.md): APFS/HFS+/HFSX construction, complete-disk repacking and preservation guarantees.

- [Editing existing HFS+/HFSX filesystems](hfs-editing.md): commands, allocation/tree mutation, preservation and the completed-output transaction contract.
- [Copying into existing images](image-copy.md): recursive import, preservation, aliases, forks and independent native qualification.

- [APFS volume conversion](apfs-volume-encryption.md): encrypt or decrypt an existing volume while preserving identities, retained history and sharing.
- [APFS history, sharing and encryption](apfs-lifecycle.md): dependency-linked lifecycle work, Apple source basis and independent native controls.
