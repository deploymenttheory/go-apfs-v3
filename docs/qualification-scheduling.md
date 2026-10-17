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

Matrix expansion predicts 83 jobs for `ci.yml`, compared with 170 in that
completed campaign. The independent offline chains add seven child completion
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
