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

## Reference candidates and reviewed release pins

The internal qualification command prepares a complete, unapproved independent
capture candidate from an explicit input map:

```sh
go run ./acceptance/qualification -capture-contract
go run ./acceptance/qualification -prepare-references /tmp/capture-inputs.json -candidate-dir /tmp/reference-candidate
```

The input map contains `schema: 1` and an `inputs` array of `id` and absolute
`path` pairs. All 42 independent corpus IDs and all three native source versions
are required. It refuses unknown inputs, missing reviewed cases and changed
capture contracts before publishing candidate metadata. Matched HFS
header-growth controls retain their original historical catalog entry and
cannot enter independent publication. Candidate preparation is file processing;
it grants no qualification verdict and changes no approved reference.

`reference_sources.py` describes the explicit projection from complete Actions
captures to logical corpus roots. Set-ID and truncation permission inputs share
the complete copy-permissions capture; metadata lifecycle inputs share the
complete fragmented-metadata capture. Corpus IDs and capability bindings remain
distinct. Assembly preserves every original byte within each selected native
source directory, including original collector sources and observations.

The conservative capture identity excludes ordinary Go filesystem source
changes, captured input bytes and release transport pins. Collector, harness,
recipe, workflow and unclassified dependency changes invalidate the complete
capture. An unknown helper or build asset cannot silently inherit old evidence.

The release transport client streams content-addressed objects smaller than
2 GiB, pins numeric release/asset IDs, checks sizes and SHA-256 values, and
verifies that each asset belongs to the pinned release. Interrupted and corrupt
downloads publish no cache entry. Repository credentials are not sent to signed
asset redirects. Candidate releases start as drafts and become non-latest
prereleases only after their assets have been uploaded and checked.

For an already reviewed and published pin, download into an existing ordinary
cache directory and admit it explicitly:

```sh
python3 acceptance/qualification/release_assets.py --pin acceptance/qualification/references.json --directory /tmp/reference-assets
go run ./acceptance/qualification -check-references acceptance/qualification/references.json -bundle-dir /tmp/reference-assets
go run ./acceptance/qualification -replay -reference-pin acceptance/qualification/references.json -bundle-dir /tmp/reference-assets -- -count=1 -timeout 5m ./acceptance -run '^TestNativeFileReading$'
```

No approved release pin is shipped yet. Admission refuses stale capture
dependencies, corrupt catalog bytes, missing permanent qualification evidence
or invalid corpus assets. Replay checks its selected original inputs again and
executes fresh assertions; the candidate's historical verdicts do not qualify a
new implementation. Release IDs and result evidence never enter input identity.
The original `corpus.json` snapshot and its audit remain unchanged.

The normal native workflow now resolves the reviewed pin before scheduling its
independent input jobs. An absent pin or changed collector/helper/recipe contract
requires fresh capture on the original macOS 15, 26 and 27 runners. With a
compatible pin, those 39 jobs run on Linux and restore the exact original capture
artifact layouts. Asset or integrity failures after selecting reuse fail the
campaign. They cannot turn into a successful skip. Explicit reference refreshes
always capture afresh.

`reference_reuse.py` records input admission separately from native assertions.
It uses the Go resolver to verify and materialize the selected corpus trees,
then inverts the documented artifact naming projection. Aliases must have
identical original bytes. A Linux resolver never records a new Apple capture
verdict. Every existing portable replay, source version, native verifier and
subsequent native modification still runs. The matched current-Go HFS experiment
also remains fresh on every native campaign.

Restoring the 39 downloaded capture artifacts and assembling their logical roots
again reproduced all 42 independent input trees: 3,837 files and 607,864,154
original bytes matched their catalog digests. That ordinary-file check executes
no native tools and grants no hosted qualification or performance verdict.

`-reference-obligations /tmp/reference-candidate` prints the independently
required case inventory before returned receipts are examined. It preserves
source versions, host, instrumentation, controls and the existing native verifier
scope. Recovery uses its original matching-source native checks. Input
projections must contain identical complete original files and observations;
they do not stand in for omitted retained entrypoint executions.

`-check-reference-evidence /tmp/evidence -candidate-dir /tmp/reference-candidate
-reference-origin /tmp/origin.json` checks original plans, receipts, streams,
source snapshots, case observations and native output identities. The origin
document must come from the authenticated complete Actions campaign, its job
inventory and successful required gates. The command requires the exact tested
source checkout; it does not authenticate a caller-supplied origin on its own.
Individual ciphertext needs separate native scopes; copies of one scope do not
count as several checks.

The refresh controller has durable issue-backed first-observed and last-success
clocks, explicit contention deferral and one marker-addressed stale incident.
It only advances success after permanent publication from the matching completed
native campaign. Duplicate completion events do not reset this clock.

The [refresh workflow](../.github/workflows/reference-refresh.yml) retries hourly
from 01:23 through 06:23 UTC. It defers to active portable CI as well as native
implementation qualification, dispatching the complete existing native bench
when capacity is free. Deferrals remain separate retained decisions. The former
uncoordinated nightly native trigger is removed.

The [publication workflow](../.github/workflows/reference-publication.yml) listens
for both native and portable CI completion, since either may finish last. It
selects a successful default-branch refresh and successful CI for the exact same
revision. It requires the complete native gate, every source artifact and the
execution-artifact inventory from successful upload steps. It then checks out
that exact tested source and validates the original plans, streams, observations
and output identities before publishing a candidate. Failed proof retains
diagnostics and creates no release or approved pin.

Candidate releases remain drafts until all addressed objects and a final Go
catalog/corpus/evidence admission check pass. Publication opens a normal
catalog-update PR; it never merges it. Retrying an already published candidate
keeps its original objects and catalog. The first complete hosted qualification,
publication and reviewed promotion remain required before this work can be
declared operational; no pin has been approved in this checkout.

Jobs may fetch selected corpus IDs with repeated `release_assets.py --input`
options. The complete reviewed catalog and permanent proof are still checked;
unrelated disk bundles are not downloaded. To supply ordinary input directories
to native programs, use the internal resolver:

```sh
go run ./acceptance/qualification -materialize-references apfs-editing,apfs-copy -reference-pin acceptance/qualification/references.json -bundle-dir /tmp/reference-assets -input-dir /tmp/native-reference-inputs
```

Materialization verifies original and copied bytes, requires absent managed
scratch outside the source checkout, and cleans partial copies after failure.
The resulting input map names exact logical roots. It cannot substitute retained
data for a current-Go experiment and grants no filesystem verdict.

Qualification artifact uploads retain original plans, receipts, events, input
bindings and capture observations, including hidden `.qualification` copies.
Full writer outputs continue in their dedicated native-verification archives;
the qualification metadata uploads avoid transporting a second copy of them.

Every successful replay also retains `source-inputs.json` beside its original
plan, event stream and receipt. This contains the original admitted input
snapshots even for reader-only jobs that have no writer archive. Exported writer
archives continue to carry their own unchanged `.qualification/` proof layout.

Candidate obligations bind each case to all original files and capture documents
under its logical `macos-15/`, `macos-26/` or `macos-27/` source directory. This
explicit naming projection lets a one-source job and a complete three-source
capture prove the same selected source. Sibling capabilities outside that source
directory do not enter its projected digest. Original whole-tree digests remain
recorded; no disk bytes, observations, collector sources or logs are rewritten.
A changed disk or extra file inside the selected source fails coverage even if
its original manifest is unchanged. Repacking cases that consume an encrypted
auxiliary input bind that input's files and manifest, rather than the repacking
control's manifest.
