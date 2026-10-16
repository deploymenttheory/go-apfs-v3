# Native corpus catalog

The [approved input catalog](../acceptance/qualification/corpus.json) indexes
43 retained corpus trees: 3,308 committed files, 164 manifests and approximately
412 MiB of stored evidence. It was bootstrapped from a clean committed checkout.
Original images, observations, collector sources, manifests and historical
qualification ledgers are unchanged.

This is the immutable retained-input snapshot. Future independently captured
refreshes will have their own versioned candidate catalogs and reviewed pins;
they do not replace these original references. Corpus IDs name logical families,
and `tree_sha256` identifies a particular version. The resolver accepts either
snapshot; registry matching in this command specifically protects the original
retained set. Fresh-capture contract checks belong to the capture/promotion
workflow, rather than weakening that retained-evidence check.

The resolver is internal acceptance infrastructure. It does not run native
tools, download anything, change the product CLI or certify an implementation.
The existing replay and Apple verification gates remain required. Adoption by
the replay runner and execution receipts is tracked in
[#79](https://github.com/deploymenttheory/go-apfs-v3/issues/79).

## Identities and provenance

Each corpus records its capability bindings and dependency classification,
exact retained file names/sizes/SHA-256 values, manifest case indexes and native
source versions/builds/architectures. The complete original producer object,
including recorded collector/tool identities and any historical omissions,
remains in its original manifest. A canonical producer-object hash binds that
provenance without duplicating or inventing tool identities.

Manifest roles distinguish native captures, readable retained projections and
indexes into original capture archives. A projection remains a projection. The
original documents and their source digests remain authoritative; existing
acceptance comparisons between projections and original observations continue.

Three checks have distinct meanings:

- A bundle's SHA-256 and size identify its exact transport bytes.
- Every retained member has its own exact size and SHA-256, including existing
  `.raw.gz`, `.dmg` and compressed historical text files.
- Manifest `original_bytes` and `original_sha256` identify the manifest bytes
  before retention gzip compression. An uncompressed projection's values refer
  to that projection, not to a replacement for the original native document.

The corpus `tree_sha256` includes file and provenance contracts and capability
bindings, but excludes its transport location, workflow hashes and execution
receipts. Moving identical inputs between a committed tree and a pinned bundle
does not change their input identity. The reviewed catalog separately pins the
chosen location and archive digest. This creates no inherited execution verdict.

Matched HFS header-growth controls retain their `current-go-experiment` binding.
Archived Go-labelled controls are historical references. New Go writers still
require a fresh matched experiment against their current production revision.

## Resolution and bounds

`internal/qualification/corpus` resolves either a committed tree or a local
content-addressed tar/gzip bundle through the same interface. Bundle files are
named `sha256-<digest>.tar.gz`; network retrieval and reviewed release promotion
belong to [#80](https://github.com/deploymenttheory/go-apfs-v3/issues/80).

Admission rejects absent/corrupt/incomplete inputs, duplicate identities or JSON
keys, unexpected members, path traversal, absolute/drive/stream paths, Windows
device aliases, case collisions, links, special/sparse files and unsupported
archive metadata. It checks exact member sizes/digests and all retained manifest
documents before returning a usable tree. Trailing gzip streams, hidden tar data,
bad CRCs and excessive padding fail admission.

The catalog is bounded to 16 MiB; each original manifest to 16 MiB. Bundles stay
below 2 GiB, with at most 100,000 files, 100,000 parent directories and 16 GiB of
retained member bytes per tree. A separate allowance bounds decoded tar
headers/padding. All file copying
and hashing streams through bounded buffers. These are transport limits; nested
disk archives stay in their original compressed form. Existing acceptance tests
still verify decoded disk hashes and their filesystem-specific bounds.

Extraction uses a private managed directory and rooted file operations. It
returns no usable input after failure and cleans partial extraction. `Close`
removes owned extraction scratch, never a committed source tree. Caller-owned
catalog slices cannot mutate the resolver's admitted contracts. Replay must put
writable outputs elsewhere and call `Verify` afterwards; neither a build cache
nor source-file permissions substitute for source immutability checks.

Outer archive ownership, clocks and permissions are not native filesystem
expectations. Those values are preserved inside the disk images/observations;
host-copy fixtures reconstruct their explicit native recipe before import.
Bundle construction uses fixed transport headers and never imports host ACLs,
extended attributes or ownership into the extracted tree.

## Local checks and candidate preparation

From a clean checkout, inspect or verify inputs without native operations:

```sh
go run ./acceptance/qualification -describe-catalog
go run ./acceptance/qualification -verify-corpus all
go test -race -count=1 ./internal/qualification/corpus ./acceptance/qualification
```

The existing source-check job verifies all committed input bytes. Unknown local
files cause exact-tree verification to fail. Bootstrap additionally refuses
tracked, untracked or ignored changes under `acceptance/testdata`. Leave local
evidence untouched and use an isolated clean checkout when necessary.

Prepare a candidate at an absent path, then review it:

```sh
go run ./acceptance/qualification -bootstrap-catalog /tmp/corpus-candidate.json
```

This never overwrites the approved catalog. Bootstrap requires Git only to
check that the original evidence checkout is clean. Ordinary catalog resolution
uses files alone.

Prepare local bundles in an existing directory outside the source corpus:

```sh
go run ./acceptance/qualification -bundle-corpus all -bundle-dir /tmp/corpus-bundles
```

Bundle records identify the corpus, input tree and stored archive. Construction
verifies inputs before and after streaming, publishes each local addressed file
atomically and refuses to replace a different existing file. It neither uploads
release assets nor updates catalog locations. The selected committed/bundle
location must be explicit in a subsequently reviewed catalog; missing evidence
never falls back to a different input or successful skip.
