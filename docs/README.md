# Project documentation

- [Architecture](architecture.md): preservation, ownership, errors, and boundaries.
- [Implementation](implementation.md): agreed capabilities and current qualification status.
- [Sessions](sessions.md): file commands, managed scratch and host metadata policy.
- [Sources](sources.json): authoritative references and implementation provenance.
- [Acceptance](../acceptance/README.md): why scenarios exist and how to reproduce them.

Specification coverage, compilation, unit coverage, and native qualification are
different things and must not be presented interchangeably.

- [Packing](packing.md): APFS/HFS+/HFSX construction, complete-disk repacking and preservation guarantees.

- [Editing existing HFS+/HFSX filesystems](hfs-editing.md): commands, allocation/tree mutation, preservation and the completed-output transaction contract.
- [Offline editing qualification](offline-editing-qualification.md): supported profiles, required evidence and remaining work.
- [Copying into existing images](image-copy.md): recursive import, preservation, aliases, forks and independent native qualification.
