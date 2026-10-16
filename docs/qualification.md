# Filesystem qualification harness

Qualification continues to use independent Apple capture → portable Go replay →
Apple verification. The redesign makes the obligations and evidence explicit,
then removes repeated capture, replay and scheduling barriers. It uses existing
GitHub runner capacity. It changes no filesystem API or command-line interface.

The implementation is tracked in
[#76](https://github.com/deploymenttheory/go-apfs-v3/issues/76).
The [coverage registry](../acceptance/qualification/registry.json) and
[audit instructions](../acceptance/qualification/README.md) describe the existing
obligations; [the measured baseline](qualification-evidence/README.md) preserves
the original successful campaign's performance evidence.

## Evidence boundaries

Independent native inputs include original disk bytes, observations, collector
sources, native tool/OS identity and their original hashes. Existing committed
references and historical qualification ledgers remain unchanged. A versioned
catalog resolves committed inputs and content-addressed local bundles. The
[corpus contract](native-corpus.md) records the implemented resolver and bounds.
Reviewed publication will supply content-addressed GitHub release
bundles, checking both stored and original bytes with bounded safe extraction.
Actions artifacts transport evidence; they do not provide permanent retention.

Ordinary Go changes may reuse approved original Apple inputs. They still need
fresh outputs from Linux, Windows and macOS and fresh Apple verdicts on macOS
15, 26 and 27, including mounted readback and subsequent native modifications.
Changing a collector, helper, recipe or capture contract requires fresh affected
inputs. Unknown dependencies require full recapture.

Native experiments that consume current Go output stay attached to the current
revision. In particular, the HFS header-growth job builds Go images, then creates
Apple controls matched to their geometry and fork extents. Historical Go-labelled
controls cannot certify a new Go builder. Native continuations also depend on
fresh Go output and must retain the complete Apple → Go → Apple sequence.

Capture, replay and Apple verification will have separate dependency
fingerprints. Input identities exclude result receipts, avoiding circular
hashes. Receipts bind cases, variants, original inputs, outputs, production/build
identity and actual native environment. Missing, duplicate, failed, skipped or
mismatched required evidence fails completion. A job's successful status or a
static registry audit alone cannot certify a capability.

Existing verification deduplicates byte-identical plaintext host outputs only
after checking their actual hashes. Preserve that behavior. Randomized encrypted
outputs require individual native verification; matching logical plaintext does
not justify skipping them.

## Scheduling and reuse

Independent capability chains allow a family's verification to start when its
own inputs and replays are ready. Short cases will share jobs targeting 5–10
minutes. Real HFS node-map boundaries, fragmented growth/collapse/reuse and other
expensive cases retain their separate deadlines and original data sizes. Every
original source, host, encoding, refusal and race variant remains required.

Module and compilation caches may be reused; assertions run afresh with
`-count=1`. Already-compressed archives need no extra transport compression.
Profile repeated decode/I/O before changing it. Immutable decoded inputs have a
2 GiB job-local cap, separate writable scratch and verified hashes. Oversized
inputs follow the uncached path. Source preservation and corruption detection
remain required.

Obsolete runs may be cancelled within the same PR. Unrelated PRs remain
independent. Identical merge events may inherit complete compatible receipts
only when production, inputs, build/toolchain and qualification contracts match.
Any inheritance is explicit and references original receipts and digests.
Documentation/release-only classification is conservative; unknown dependencies
execute the full work. A missing-evidence skip never qualifies a merge.

Nightly native refresh will defer while an implementation campaign is active
and retry hourly during the overnight window. Deferral is recorded separately
from successful capture. After 48 hours without a successful refresh, maintain
one incident. Fully qualify candidate corpora before publishing content-addressed
assets in separate non-latest prereleases, each smaller than 2 GiB. Promotion is
a reviewed catalog-update PR. Failed candidates retain diagnostics and never
replace approved inputs automatically.

## Delivery order and cutover

| Ticket | Deliverable | Dependencies |
| --- | --- | --- |
| [#77](https://github.com/deploymenttheory/go-apfs-v3/issues/77) | Coverage registry, audit and performance baseline | None |
| [#78](https://github.com/deploymenttheory/go-apfs-v3/issues/78) | Immutable corpus catalog and resolver | #77 |
| [#79](https://github.com/deploymenttheory/go-apfs-v3/issues/79) | Unified replay and case receipts | #77, #78 |
| [#80](https://github.com/deploymenttheory/go-apfs-v3/issues/80) | Independent capture and reviewed corpus promotion | #78, #79 |
| [#81](https://github.com/deploymenttheory/go-apfs-v3/issues/81) | Independent batched capability chains and build caches | #79, #80 |
| [#82](https://github.com/deploymenttheory/go-apfs-v3/issues/82) | Safe event deduplication and evidence inheritance | #81 |
| [#83](https://github.com/deploymenttheory/go-apfs-v3/issues/83) | Profiled, bounded decoded-input reuse | #79, #81, #82 |
| [#84](https://github.com/deploymenttheory/go-apfs-v3/issues/84) | Equivalence campaign, required-check cutover and retirement | All above |

The old required gates remain until an old/new campaign qualifies the same
production revision on identical pinned inputs. Compare complete obligations,
semantics, deterministic plaintext digests and all native continuations; verify
randomized outputs individually. Then migrate required checks and remove
superseded matrices, duplicate replay and rerun-only paths. Do not retain two
competing harnesses or introduce partial/profile qualification modes.

The final ledger must show at least 50% fewer job starts and 25% fewer macOS
runner-minutes against the recorded baseline over three comparable warm-cache
campaigns. Report scheduling delay separately. If measurements miss the target,
retain coverage and explain the remaining bottleneck. Do not remove obligations
to obtain a faster result.

Native image creation, attachment, filesystem checking, snapshots and mutation
run exclusively on guarded disposable CI VMs. Local work uses ordinary files
and mocked native commands. The portable qualification CLI and corpus resolver
have no native filesystem execution path; Apple programs retain their disposable
host guards.
