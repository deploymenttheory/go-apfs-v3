# Qualification scheduling

The complete Apple capture → portable Go replay → Apple verification sequence
remains required. Scheduling changes share setup and compilation; they do not
inherit a test verdict or remove a source, host, encoding, race or continuation
obligation. Original captured files and historical performance ledgers are
unchanged.

`offline-editing.yml` invokes one `offline-family.yml` chain per capability. Each
chain has its own capture, replay, Apple readback and completion dependencies.
For example, permissions readback can start while HFS node-map replay is still
running. The original outer completion gate still requires every capability.
The source/host Cartesian product and native verifier versions remain intact.

Retained tests share the following jobs on Linux, Windows and macOS, for each
macOS 15, 26 and 27 source:

| Shared job | Original comparisons | Test-process deadlines |
| --- | --- | --- |
| APFS geometry and permissions | Geometry, directory-stat transitions, ACL inheritance, preserved copying | A separate 12-minute invocation for each original group |
| HFS attributes and overflow | First attributes; fragmented growth, collapse and reuse | Separate 12-minute invocations |
| HFS+ node-map boundary | Original 120,000-file HFS+ boundary | Original separate 12-minute invocation |
| HFSX node-map boundary | Original 120,000-file HFSX boundary | Original separate 12-minute invocation |
| HFS editing | Files/catalogs, metadata, links, four journal/filesystem copy profiles | A separate five-minute invocation for each original group/profile |
| Existing APFS edits | Files, directories, metadata, links, copying | Original separate five-minute invocations |
| Filesystem recovery | HFS journal and APFS checkpoints | Separate five-minute invocations |

Construction and repacking share one retained job per host, with separate
five-minute invocations. Short race groups share setup while retaining their
original selectors, source restrictions, instrumentation and process deadlines.
The six cross-build targets run sequentially in one Linux job and all must pass.
No platform target is inferred from another platform's successful build.

Module and compilation caches are enabled. The replay runner always supplies
`-count=1`, and the standalone library race command now does so explicitly.
Already-compressed portable output archives use artifact compression level zero;
archive contents and native verification remain unchanged.

Hosted replay invocations now share verified decoded source disks under
`RUNNER_TEMP/apfs-decoded-inputs`, with a 2 GiB logical-byte cap for the entire
job. The portable runner chooses that location internally and records the cache
policy in its execution environment. Ordinary local replay remains uncached.
APFS editing, HFS editing and the larger offline families use one bounded sparse
decoder, retaining their original per-archive bounds and captured hashes.

Cached files are read-only, with original and decoded hashes checked before use
and after each consumer. Output mutation uses separate scratch. Full-cache,
oversized and unknown-length inputs use the bounded uncached path. OS file locks
coordinate processes; cancelled or killed writers cannot publish partial input
or retain a stale ownership lease. No verdict or output is cached.

The retained [HFS profile and input benchmark](qualification-evidence/profiles/hfs-catalog-map-growth/README.md)
show the limited scope of this saving. The real 120,000-file cases, UDRO/UDZO,
all original native sources, refusals and deadlines remain unchanged. Complete
hosted comparison and timing campaigns are still required.

Assertion identities include library unit-test sources as well as acceptance
tests. Adding or changing those assertions invalidates prior test evidence;
changing a test while replay runs prevents receipt publication. Changing only a
test updates the assertion fingerprint while keeping the production fingerprint
stable.

On a main-branch merge, CI and native qualification may each inherit their own
complete successful run from that exact PR within the preceding 24 hours.
Checkout authentication requires
identical complete Git trees, and verification checks the original case plans,
event bytes, assertion/source fingerprints, retained inputs and recorded build
tools. Build, library-race and source-check jobs must also have succeeded.
Inheritance retains the original receipt digests and tested revision explicitly.

Implementation pull requests and manual dispatches execute full portable CI. Missing,
expired, failed or incompatible prior evidence selects full execution. The
existing quality gate requires either complete original proof or every freshly
executed group.

Native inheritance independently requires the original complete Apple → Go →
Apple campaign, including all current-Go HFS construction experiments, every
portable host and all three Apple verifier versions. Archived Apple event bytes
and original observations are checked alongside the Go source snapshots. A
copied Go receipt in a readback archive cannot replace its original producer.
Output identities must have their required native verification, including each
randomized ciphertext and the recovery families' matching source versions.
Restored approved inputs carry admission records, never assertion verdicts.

Implementation PRs, manual campaigns and scheduled refreshes continue to execute
fully. Both original completion gates remain required. Hosted positive inheritance
and the final timing campaigns remain outstanding; local admission tests do not
establish runner-minute savings.

A single Go classifier compares original committed Git objects before a
documentation PR looks for prior evidence and again during evidence admission.
Only recognised Markdown documentation and changes to an existing single-package
release version label qualify for this source projection. Captured evidence,
code, fixtures, workflow/build configuration, agent instructions, aliases,
deleted helpers and unknown files require the complete work. Release-label
additions/deletions, expanded schemas, duplicate keys and invalid versions do too.

Classification grants no verdict. A documentation PR still needs a recent,
authenticated complete original campaign for its base. The original source tree,
tested revision, receipt bytes and digests are retained beside the current tree
and exact changed paths. Missing or incompatible proof selects full execution.
If a prior PR already reused evidence, its record supplies only an original run
ID hint: admission rechecks that original run's API state, jobs, uploads, source,
fingerprints and event bytes directly. It never chains inherited verdicts.

The native workflow now evaluates admission on every PR instead of omitting the
workflow through a path filter. Its existing required completion gate receives
either validated original evidence or the complete fresh campaign. Fork PRs
and events with incomplete provenance execute fully.

Fresh HFS file and catalog comparisons share ten jobs rather than twenty. Linux
retains its per-source race instrumentation; Windows and macOS still compare all
three native sources. Catalog comparisons keep their separate four-minute
deadline and output directories. Files, catalogs, metadata and links travel in
one archive containing each original execution receipt. Copying retains its
separate bounded jobs.

Each recovery verifier job now checks all three portable hosts on one disposable
Mac. APFS and HFS each use three Mac jobs rather than nine. Every host invokes
the original verifier and completion check separately, with independent
diagnostic directories. All three macOS verifier versions remain required.
Matching plaintext does not skip these checks, and the batched loops fail if
any host's verifier or completion check fails. Their original 20-minute APFS and
15-minute HFS job envelopes remain unchanged.

The completed [CI campaign](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/38896636832)
at `021adb712e2ef79ce9924725cd74c30f1d7502ab` informed the grouping: the short
retained groups each took about one to three minutes, while the HFS node-map
jobs took up to ten minutes. HFS editing has a 15-minute job envelope to retain
headroom for all seven independent processes on slower hosts. Its assertion
deadlines and datasets have not changed.

Retained batching accounts for 83 jobs, compared with 170 in that completed CI
campaign. Fresh CI now adds one evidence-admission job; an admitted identical
merge executes only that job and the existing quality gate. The independent
offline chains add seven child completion
jobs underneath the existing outer completion gate. These are scheduling counts,
not a measured claim about total runner time or the final reduction target.
Expanding both CI matrices against the merged replay implementation preserves
all 221 retained and race invocations, including their source/host axes,
selectors, race instrumentation, skip expressions, parallelism and process
deadlines. The portable default selector and required outer dependencies also
remain unchanged. This structural comparison does not supply execution verdicts.
Fresh capture/replay and retained replay still execute separately until original
receipts prove equivalence on identical inputs. The final old/new comparison and
three warm-cache campaigns remain required before retiring superseded paths.
