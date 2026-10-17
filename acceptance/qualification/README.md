# Qualification coverage

This directory declares acceptance obligations and executes the existing tests
against verified native inputs. The source audit alone does not certify a run;
execution receipts and the existing required gates establish completion.

`registry.json` records each capability's purpose, independent expectation,
entrypoints, collector/verifier scripts, retained and fresh source versions,
portable hosts, native verifier versions, output formats, race coverage,
negative controls and native continuations. It also indexes the original
retained manifests and their case IDs. Both the readable manifest projections
and original compressed manifests remain unchanged.

Run from the repository root:

```sh
go run ./acceptance/qualification
go run ./acceptance/qualification -verify-corpus all
go test -count=1 ./acceptance/qualification
python3 -m unittest discover -s acceptance/qualification -p 'test_*.py' -v
python3 acceptance/qualification/measure.py --check
```

These commands inspect source code and ordinary files only. They never create,
attach, mount, check or mutate a filesystem through native macOS tools.

`corpus.json` pins the existing retained files and provenance independently from
execution results. The same internal resolver admits committed trees and local
content-addressed bundles. See [catalog identities, bounds and candidate
preparation](../../docs/native-corpus.md). The default audit checks catalog and
registry agreement; `-verify-corpus all` also checks every retained member and
original manifest. It runs in the existing source-check job. The replay runner
uses the same resolver and records case-level execution evidence.

CI validates its reviewed Apple inputs once on Linux, then shares the original
catalog, permanent provenance and input bundles with the existing portable and
acceptance jobs. Each replay explicitly supplies `-reference-pin` and
`-bundle-dir`; the Go resolver still checks its own selected input bytes. The
required controls come from the reviewed replay recipes. Source checks, library
race checks and cross-builds remain independent of input transport.

Before a reviewed pin exists, those jobs use the original retained catalog with
the same selectors, hosts, instrumentation and process deadlines. Once a pin
exists, missing or corrupt reviewed assets fail admission. Input preparation
emits no execution verdict, and the complete CI gate requires it alongside every
existing test group. The capture dependency contract includes this transport
wiring, so it must be established before publishing the first shared pin.

The Go syntax audit discovers entrypoints, skip calls (including helpers and
nested subtests), and bare returns in an entrypoint's own body. Seven existing
continuation entrypoints may return or skip when their native inputs are absent.
Their registry explanations identify the required readback jobs that supply
those inputs. An inputless execution is not evidence of continuation success.

The audit rejects unregistered or duplicate entrypoints, missing explanations,
new skip/return sites, changed acceptance source files, changed workflow
contracts, invalid job references, unregistered corpus directories, absent or
changed manifest files and changed retained case/source inventories. The full
workflow bytes bind selectors, matrix axes, conditions, deadlines and gate
dependencies without introducing another YAML parser or partial CI mode.
This conservative binding requires a coverage review whenever those files
change. Runtime missing/skipped-case detection uses the execution events and independently
required case inventory; a static digest does not establish execution coverage
or assertion correctness.

Git checkout keeps Go/YAML/JSON source contracts at LF on every host. The later
`acceptance/testdata/** -text` rule still preserves exact original native bytes.

When changing a capability:

1. Read its purpose and expectations. Add or amend cases in the existing tests
   and independent capture/verification family.
2. Update the registry's relevant capability, entrypoints, dimensions and job
   references. Explain any new skip or optional-input return. Preserve every
   original obligation unless an explicit capability decision changes it.
3. Review changed test/workflow bytes and update their SHA-256 values explicitly.
   There is deliberately no command that automatically approves all changes.
   `go run ./acceptance/qualification -inventory` prints discovered syntax for
   comparison; it does not modify the registry.
4. Index added retained manifests and case IDs, retaining existing original
   digests and evidence. Do not rewrite a native observation to satisfy replay.
5. Run the audit and existing required gates. Review whether a collector change
   needs fresh native inputs, rather than merely refreshing a file digest.

`apple-independent` means the original reference was produced without the Go
implementation under test. `current-go-experiment` means native work depends on
fresh Go output; the matched HFS header-growth experiment is in this category.
Its retained Go-labelled controls are historical evidence, not current writer
qualification. `native-continuation` consumes fresh Go output after Apple edits
it. `harness-control` tests evidence admission with ordinary files. These
categories govern future corpus reuse; none creates an inherited verdict.

An empty `native_majors` or `fresh_sources` list means there is no corresponding
dedicated current gate. Race descriptions state the actual restrictions, rather
than promising an unrestricted cross product. For example, construction race
checks use macOS 27 inputs; several large offline families have no dedicated
race jobs. The fragmented HFS fresh comparator also checks collapse/reuse when
fresh inputs provide those states; the separately named retained lifecycle
entrypoint is inventoried independently.

See [the harness design and work order](../../docs/qualification.md) and
[the original performance baseline](../../docs/qualification-evidence/README.md).

Portable execution uses the reviewed `replay.json` recipes and the verified
catalog. Each recipe describes the original entrypoint's real subtest boundaries,
source cases, encoding/encryption variants and required outputs. Run the existing
selector through the shared runner:

```sh
go run ./acceptance/qualification -replay -- -v -timeout 5m ./acceptance -run '^TestNativeFileReading$'
go run ./acceptance/qualification -replay -- -race -timeout 5m ./acceptance -run '^TestNativeImageBuilding$/macos-27/'
```

Before starting Go, the runner declares every required case and output. It always
uses fresh assertions (`-count=1`) and consumes the original `go test -json`
events. A missing run, skip, duplicate, failure, unexpected child, missing output,
source/input mutation or interrupted process prevents receipt publication.
`artifacts/qualification/replay-*/` retains the plan and events for diagnosis,
including failed executions. A `receipt.json` appears only after completion.
Required native continuations fail when their inputs are missing; inputless
continuation entrypoints in a broad retained suite provide no successful verdict.

Receipts bind actual production and assertion source digests, immutable input
identities, the actual host/toolchain/build flags, race mode, original execution
origin and the produced file hashes. There are separate fingerprint domains for
Apple capture, portable replay and Apple verification. Capture records check
returned per-case observations against the reviewed inventory; they preserve
native refusals as observations. Apple-verification fingerprints bind the actual
portable bytes and native tool/source identities. Origins are never rewritten. Existing verifier-only reuse requires its explicit
admitted source run and an unchanged portable contract. Historical ledgers and original captured data are unchanged.

`-classify-changes-from <exact-original-revision>` inspects committed Git objects
and grants no execution verdict. Event admission uses this same classifier when
considering documentation or recognised release-label changes. The original
complete campaign and every source/input/tool/receipt check remain required;
unknown dependencies execute the full bench. Source projections retain both
trees and original execution origins. See the [event policy](../../docs/qualification-scheduling.md).

Existing output archives carry their replay proof under `.qualification/`;
ledger bytes are excluded from the output identity to avoid self-reference.
The Apple programs declare required source/profile/host/output sets before
checking them and record success only after the original assertions. Identical
plaintext host outputs retain each host obligation while sharing one native
check. Distinct ciphertexts each unlock independently. Final Go-after-Apple
outputs have separate verification scopes. CI retains the events and receipts;
the existing capture, replay, readback and required-job gates remain in place.
Each Apple readback job also names its required pre-execution plans explicitly
and runs `qualification_complete.py` before succeeding. Missing scopes, changed
plans, lost events/outputs and mismatched origins fail that completion check.

Input location does not imply fresh-capture requirements. The existing fresh
workflows explicitly require compression boundaries, copy truncation/set-ID or
metadata collapse/reuse controls where applicable. The internal input map keeps
HFS file and catalog corpora distinct even though their direct-test overrides
share an environment variable. Missing or changed inputs never fall back to a
different corpus. Embedded/external build assets need an explicit identity
contract before being introduced; the current source identity gate refuses to
silently omit them.

Recovery recipes explicitly name the original capture contract separately from
the readable retained index's scenario. That projection preserves the same case
inventory and never rewrites either document. Snapshot lifecycle parent images
and their original manifest are resolved inside `snapshot-reference/`; state
images remain relative to the lifecycle capture itself.

Adding `-execution-index` to `-check-execution-evidence` exports the admitted
case and output identities for campaign comparison. The controller must still
authenticate the complete original workflow and artifact inventory; a supplied
origin document is not authority. The index adds no filesystem verdict and
does not permit removing a test or required gate.

Each case retains its original receipt digest. Its invocation records the
original run, revision, host, race mode, tools and flags once. Replay source
identities use the existing macOS-version projection, including the declared
auxiliary inputs. A job holding additional source versions or sibling inputs
does not change an individual case's identity. Fresh native-continuation input
hashes remain explicitly distinct from immutable Apple reference inputs.
