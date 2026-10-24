# Acceptance testing

The product claims to read, build and edit APFS and HFS+/HFSX images the way
macOS does. Acceptance testing therefore compares the product with
fixtures that Apple tools produced, and verifies images the product produced
with Apple tools, on macOS 26 and 27. macOS support starts at version 26.
Three tiers do this:

| Tier | Where | What | When |
| --- | --- | --- | --- |
| Fixture corpus | macOS 26, 27 runners | Recipes executed with Apple tools and system calls; the kernel's view recorded | Manual dispatch, when a recipe changes or a macOS version is added |
| Portable conformance | Linux, Windows, macOS | The product reads every fixture from every producer and must match the observation; it builds, edits, copies, repacks and encrypts images from the fixtures | Every pull request |
| Native truth | macOS 26, 27 | Each version judges, with `hdiutil`, `fsck`, `codesign` and mounted readback, the images every host derived from its own fixtures; native writes and a further product edit follow on a representative set; fixtures from the other versions are cross-mounted | Every pull request |

One pull request starts ten jobs, three of them macOS: source checks,
race-checked unit tests, portable conformance on Linux, Windows and macOS,
the slow bucket on Linux and Windows, native truth on macOS 26 and 27,
and `gate`. Ruleset 24806824 requires `gate` (the `Required checks` status)
before anything merges to `main`.

The native jobs start beside the source checks and portable jobs.
Each first reads the other version's fixtures, which
needs only the corpus, while the portable jobs produce their images; it
then collects and verifies the slow bucket's images before every host's main
outputs. The slow artifacts arrive while the main producers are still working,
so their verification uses that waiting window. Both output phases remain
required. A phase whose inputs come from a failed job stops at once instead
of waiting. Performance qualification still requires complete warm runs.

## The matrix

- **Producers**: the active macOS fixture versions (26, 27).
- **Hosts**: where the product runs (linux, windows, darwin).
- **Verifiers**: the macOS versions that judge the product's output (26, 27).

Every fixture from every producer is read on every host. Every image the
product produces is verified by the macOS version whose fixture it came
from, on every host's copy where the copies differ: plaintext outputs must
be byte-identical across hosts, and each host's encrypted output must
decrypt to the same device. Every verifier therefore judges every kind of
structure the product writes, without repeating the same bytes three times.
Every fixture is also mounted on the other verifier, and any difference
the kernel reports must be in
`acceptance/known-drift.json`.

## Supported macOS releases

The minimum supported macOS release is 26. The explicit producer and verifier
set is currently 26 and 27; a future release enters that set through reviewed
fixture capture and qualification. Darwin portable conformance runs on macOS 26.
Linux and Windows remain required portable hosts. Product readers select support
from filesystem structures and formats, without an image-origin macOS restriction.

macOS 15 is excluded from capture jobs, the active lock, portable fixture cases,
native verification and mandatory offline replay. Its original bundles, command
logs, collector sources, observations, ownership archives and digests remain
unchanged as historical evidence. Archived provenance can list three captures;
that original inventory does not define the current two-version requirement.
Mandatory adapter replay selects only the supported captures. Generic injected
adapter controls continue to cover omitted inventories and uncertain ownership.

The recipe-tree digest includes its README and helper sources. A support-policy
change reuses the pinned macOS 26/27 bundles without editing that captured tree,
changing its recipe digest or recapturing solely to update wording. Version lists
inside that tree describe the original capture baseline; this document describes
current support. Historical run logs, timing data and known-drift observations
retain their original version identities. Required timing replay selects only
current verifiers, and old measurements do not qualify the revised matrix.

Local capture trees may contain one or both supported producers. Discovery ignores
unsupported version directories; an unsupported-only tree fails clearly. Normal
pinned acceptance requires both supported bundles and every required case. Missing
supported evidence, a digest mismatch or a skipped required contract remains fatal.

## Fixture corpus

`acceptance/recipes/*.json` declare what each fixture contains. The schema
is in `acceptance/schema`; `acceptance/recipes/README.md` maps every
capability in [implementation.md](implementation.md) to the recipes that
cover it. `cmd/apfs-fixture` (`go build -tags fixture`, macOS only) executes
recipes. It may call only the Apple programs the schema allows, perform
POSIX operations through the kernel, or run a capture-tool procedure such
as pinning an `asr` snapshot. It never imports the product;
`acceptance/boundary_test.go` fails if it or the native verifier does.

The observer records, for every object, what `lstat`, `listxattr` with
`XATTR_SHOWCOMPRESSION`, `readlink`, a full kernel read, `SEEK_HOLE`,
`F_LOG2PHYS_EXT` and `getattrlist` report, plus `diskutil` and `hdiutil
imageinfo` plists, the raw device digest, raw header sectors, the journal
digest, snapshot inventories, lookup outcomes, exported AppleDouble files,
`fsck` and `codesign` verdicts and the complete command transcript.

Each producer's capture is one bundle, `fixtures-macos-<major>-<digest>.tar.gz`,
published as a release asset and pinned by `acceptance/fixtures.lock.json`.
The lock also pins the digest of the recipes tree; a recipe change fails CI
until a new corpus is captured and the lock is updated by review.

### Capturing

`fixtures.yml` is dispatch-only. A dry run captures and uploads bundles as
workflow artifacts; a full run also creates a prerelease, verifies the
uploaded assets by digest, writes the lock and opens a pull request that
changes only the lock. Before the workflow exists on `main`, a pull request
can run a dry run of one recipe by adding the label `capture:<recipe>`, or
of every supported recipe with `capture:all`.

```sh
gh workflow run fixtures.yml -f dry_run=true -f recipes="file-corpus"
gh workflow run fixtures.yml -f dry_run=false
```

### Adding a recipe

1. Write `acceptance/recipes/<capability>.json`. Names are capability-based;
   no ordering numbers. Run `go test ./acceptance -run Recipe` until it
   validates.
2. Add payload files under `acceptance/recipes/payloads/` with their
   producer recorded in that directory's README.
3. Add the recipe to the capability table in `acceptance/recipes/README.md`
   and to `consumers` in `acceptance/corpus_test.go` with the tests that
   assert on it.
4. Capture with the `capture:<recipe>` label on the pull request, then run
   the full capture, review the lock pull request and merge it. The
   publish job opens that pull request with the Actions token, which starts
   no workflows, so it dispatches CI on the lock branch itself; `gate`
   reports on the lock commit from that run.
5. Record any legitimate difference between macOS versions in
   `acceptance/known-drift.json` with its reason.

### Local use

```sh
go test ./acceptance/...                    # downloads the pinned corpus once
APFS_FIXTURE_DIR=/path/to/capture go test ./acceptance/...   # a local capture
APFS_OUTPUT_DIR=/tmp/out go test ./acceptance/...            # retain outputs
go test -tags slow -run 'TestGoEditsReproduceAppleStageStates/.*/hfs-catalog-map-growth' ./acceptance   # the slow bucket
```

The compressed corpus cache is `os.UserCacheDir()/go-apfs-v3/fixtures/<digest>`
or `APFS_FIXTURE_CACHE`. Original captures and their digests are retained.
`Corpus.AcquireImage` returns an explicit lease. Gzip-compressed raw inputs are
expanded sparsely in a unique run-owned child of `APFS_FIXTURE_EXPAND` or the
default temporary scratch parent. Only that child belongs to the run; the
configured parent, earlier runs and local captures remain outside cleanup.
Zero runs are left unwritten, expansions bind both the absolute source path and
image digest, and concurrent readers of that source receive only completely
published copies. Distinct source files retain separate backing paths even when
their bytes match.

Close borrowed values, readers and native attachments before calling
`lease.Release(cleanupErr)`. A confirmed last release removes the derived raw
file. An uncertain reader close or native attachment cleanup retains the same
absolute backing path and reports the cause. `Corpus.Close`, called by each
test binary's `TestMain`, reports outstanding leases and retained paths rather
than deleting them. Native fixture scratch defaults under `APFS_NATIVE_WORK`
so retained failures enter the existing diagnostic artifact. The original
compressed files and uncompressed original captures are never deleted by a
lease. An assertion or product-operation failure with healthy cleanup still
allows release.

Portable leases normally span one leaf test and native leases span one checked
operation. A later leaf can therefore expand the same input again. This trades
repeated decompression for lower retained disk use; hosted runs must measure
peak storage and runtime with the existing deadlines before making performance
claims. Interrupted processes can leave explicitly owned scratch children;
subsequent runs do not infer that those backing paths are safe to remove.
`cmd/apfs-fixture capture` refuses to run outside a
disposable VM: a development Mac once panicked under these tests
([native-testing-incident.md](native-testing-incident.md)). Inside one, set
`APFS_NATIVE_DISPOSABLE_VM=1`.

### Interrupted images

`hfs-journal-interruption` and `apfs-checkpoint-interruption` retain actual
native write windows separately from their recovered expectations. Capture
attaches a writable raw image with `-nokernel -noautofsck`, confirms the exact
image/device/owner in `hdiutil info`, and changes metadata through the kernel
while requesting `F_FULLFSYNC`. A bounded C observer pauses only that image's
helper, copies its backing bytes and resumes it. An independent watchdog
resumes the helper if the observer dies. No transaction is manufactured.

Read-only acquisition measurements reject missed windows and distinguish
linear/wrapped journals, complete/incomplete tails and checkpoint data/mapping/
committed/wrapped windows. These measurements do not supply expected filesystem
states. HFS originals are never mounted: Apple's replay-only syscall runs on
a copy, whose device bytes are retained before fsck or mounted observation.
An acquisition that caught a partially written committed journal is rejected
before any native verdict and the bounded window search continues. The first
unusable snapshot is retained verbatim, every rejection is recorded, and I/O
failures remain fatal. Native replay and checker verdicts are never retried.
APFS's checker supplies the selected XID and its kernel mount supplies the view.
Deliberate APFS checksum damage records the parent digest and exact byte change;
a separate descriptor-disabled control supplies the independently checked older
state. Damaged originals are never mounted to fabricate a fallback expectation.

Observations bind these cases with `recovery`; HFS replayed states also name
their `replayOnly` image. Each case retains the native helper sources and binary
digests. All original images, transcripts, observations and digests remain
immutable. A full capture includes both recipes; missing profiles or stages
fail portable conformance.

Apple's replay-only HFS state still has a mounted primary-header flag. Portable
read parity requires ordinary reads to refuse that state explicitly; recovery
adds the validated unmounted marking and compares its readable result with the
same native observation. No captured header is rewritten to make a test pass.

## Portable conformance

`acceptance/*_test.go`:

- `TestReadParity` opens every case and requires the product to report
  exactly what the kernel reported: entries, identities, metadata, logical
  hashes, symlink targets, attributes by digest, the security attribute
  against the recorded ACL, compression types, snapshot inventories and
  historical views, and every recorded lookup outcome.
- `TestBuildFromFixtures` builds every fixture's `Fixture` subtree into
  UDRO and UDZO images, with every compression policy where the fixture
  exercises compression, and encrypted builds; the build must read back
  as the subtree.
- `TestConstructedContainersMatchNativeVolumes` rebuilds every retained
  multi-volume and System/Data case into UDRO and UDZO, preserving the names,
  case policies, roles, reserves, quotas, group relationships, contents, clocks,
  metadata, forks and aliases. Filesystem identities are fresh. A fourth input
  is genuinely empty: the captured volume named Empty already contains pressure
  files. Public planning, streaming, publication and failure controls accompany
  the twelve outputs. Missing producers, cases or native outputs fail.
- `TestPackingReopenedPreservationSourcesMatchesNativeFiles` requires original
  native readers, reopened workspaces and CLI-reopened sessions to produce the
  same image bytes. Twelve additional images return to Apple tools. Packing
  cannot change the immutable inputs or persisted sessions.
- `TestCloneReadsUseNativeSharedExtents` traces reads through public data/fork
  APIs to actual input-device offsets and compares them with retained native
  physical extent measurements. It distinguishes shared clones, hard links,
  byte-identical ordinary copies, partial copy-on-write and independent forks.
  `TestStorageAccountingMatchesNativeAllocation` reconciles native geometry,
  free space and reserves, volume/snapshot counts, container UUIDs and selected
  transactions. Protection counts retain conservative internal bounds; the
  captures do not supply exact native protection counts.
- `TestSnapshotReadersKeepTheirHistoricalOwnership` interleaves live, named and
  XID-selected historical reads, including held values and invalid selectors.
  `TestSnapshotSessionsRetainTheSelectedHistoricalView` opens both captured
  snapshots through separate CLI name/XID selections, verifies persisted source
  identities and requires equivalent preservation exports. All twelve exports
  receive an independent native-tier verdict against the selected historical
  view; missing or invalid history cannot fall back to the live volume.
- `TestHistoryAndEncryptedWritersRefuseWithoutPublication` checks the current
  encrypted/history admission boundaries without writing or publishing outputs.
  `TestMultipleVolumeEditingRefusesMissingAndUnknownSelectors` requires explicit
  valid volume selection and preserves the original source and destination state.
- `TestRepackPreservesEverySector` repacks every retained image into both
  encodings; the decoded disk must hash to the digest the kernel reported
  for the attached device. Encrypted sources are decrypted and rewrapped.
- `TestRepackRefusesSignedAndLockedImages` requires refusals to publish
  nothing.
- `TestExistingImageEditsMatchAppleStates` replays Apple's peak and final
  mutations with the editor and compares the result with Apple's own stage.
- `TestGoEditsReproduceAppleStageStates` translates every stage of the
  recipes that apply ordinary operations (`apfs-container-geometry`,
  `apfs-directory-statistics`, `hfs-attributes-initialization`,
  `hfs-fragmented-metadata`, and `hfs-catalog-map-growth` under the `slow`
  build tag) into editor changes, applies them to Apple's image of the
  stage it starts from, and reads the result back against the stage's own
  observation, including directory statistics. Timestamps are compared
  except on the paths the stage changed, whose clocks differ, unless the
  recipe pinned them with `settimes`; identities are compared for entries
  that existed before the stage, because Apple's HFS kernel consumes a
  catalog node ID whenever the catalog B-tree grows mid-insert and the
  editor allocates contiguously. A stage no editor operation can produce
  is listed in `unreplayableStages` with its reason; any other stage that
  cannot be translated fails the test.
- `TestEveryCorpusCaseHasAConsumer` fails when a recipe is in the corpus
  without an assertion beyond read parity.
- `TestAppleDoubleMatchesNativeExports` decodes every retained `file-corpus`
  AppleDouble export and compares FinderInfo, resource-fork bytes, container
  flags/debug tags and ordered serialized attributes against an independent
  reader. Empty attributes, serialized ACL text and attribute flags remain
  exact. Re-encoding returns one canonical `.bin` output per native export;
  local repeats and every portable host must produce identical bytes. Padding
  and entry offsets may differ from the original Apple layout. Missing native
  producer/profile controls or returned outputs fail the gate.
- `TestWorkspaceOperationsMatchAppleStates` extracts `workspace-edits` and
  chains content replacement, ordered tree edits and metadata/fork edits through
  new immutable workspaces. Every stage is reopened and compared with its native
  observation. Source identities and link groups remain intact; new identities
  are explicitly portable. Parent manifest digests must match the preceding
  export. Native rejection and filename-boundary controls must produce the
  corresponding public error category without publishing a completed workspace.
- `TestFileCommandSessionsMatchAppleJourney` runs the captured journey through
  separate product CLI processes, including session open/verify/export/remove,
  ordinary commands, declared host inputs and rejection controls. Rejections
  must leave the published revision unchanged. `TestSessionPermissionsMatchAppleStates`
  reopens the public session API between operations, with explicit native actor
  ownership, and checks ACL inheritance, set-ID writes/truncation, chown effects
  and ordinary/preserving/no-attribute copy composition. Both consumers export
  the before and every native after state. Missing producers, profiles, stages
  or native output artifacts fail the gate.
- `TestRecoveryMatchesAppleStates` inspects and recovers every interruption:
  HFS replay must match Apple's replay-only disk byte for byte, with only the
  documented primary unmounted flag added at publication; APFS must select
  Apple's XID and change only block zero and rejected descriptors. Recovered
  files, identities, metadata, links, forks and signatures must match Apple's
  state. Original inputs remain unchanged and failed publication leaves no output.
  `TestRecoveryCopyInterruptedBeforePublication` kills a child process after
  observing an actual partial staging copy and requires the same source/output
  guarantees. Both recovery encodings return to the native tier; UDZO outputs
  also undergo native/Go/native continuation.

Outputs are written to `APFS_OUTPUT_DIR` with `outputs.json` describing
each one's expectation; CI uploads them per producer as
`outputs-<host>-macos-<major>`. Locally every output is produced twice and
the copies must be byte-identical (encrypted copies must differ). CI
produces each output once: the native tier requires every host's image or
AppleDouble copy to be byte-identical, which covers the repeat and catches more.

Workspace consumers return `.tar.gz` preservation exports through the same
artifacts. Archive headers retain portable names and bytes, omitting host owner
IDs, permissions and wall clocks. Aliases are serialized as regular files, with
logical link identity retained in the manifest. Workspace edits preserve source
timestamps unless the recipe explicitly supplies a metadata timestamp. Session
clocks are fixed from the captured scenario (one hour after its latest timestamp);
captured operation clocks are projected onto that instant while pre-existing
clocks and explicit assignments remain exact. Fresh objects cannot invent
runner-injected provenance; copied provenance remains exact. These policies
project comparisons without modifying native observations.

## Native truth

`go test -tags native ./acceptance/native` on each macOS version, with
`APFS_EXPECT_MAJOR`, `APFS_HOST_OUTPUTS` (each host's
`outputs-<host>-macos-<major>` artifact and the slow bucket's
`slow-outputs-<host>`) and `APFS_PRODUCT_CLI` (the built product). The
portable jobs upload one artifact per producer, so a native job downloads
only the third it verifies. It pairs every output by name across hosts,
requires plaintext images to be byte-identical and encrypted images to
decrypt to the same device, then judges each output:

- **Sector-preserving repacks**: the attached device digest, which must
  equal the digest the kernel recorded for the source. The sectors are
  Apple's own image, already mounted and checked on the producing Mac, so
  what Apple must still accept is the container. `hdiutil verify`, which
  re-reads a whole image to check its UDIF checksums, runs on the first
  repack of each format and encryption in a lineage. Apple decrypts one
  host's copy of each encrypted repack, rotating through the hosts; every
  host decrypts all of its own encrypted outputs with the product in the
  portable tier. Interrupted inputs are preserved byte for byte too; their
  recovered outputs receive the separate filesystem-health verdict below.
- **Images the product wrote** (builds, edits, stage replays, encrypted
  builds): `hdiutil verify`, read-only attach, `fsck_apfs -n` or
  `fsck_hfs -fn`, `codesign --verify --deep --strict`, mounted readback
  with the capture observer, and comparison with the expected view.
  Fresh containers require every volume and group, including the empty peer,
  signatures on each expected volume and the System object-ID namespace.
  Existing-image checks preserve the complete peer inventory and static volume
  metadata. Fresh object IDs may differ; link counts and alias relationships
  remain exact.
- **Continuation**, on a representative set marked where outputs are
  recorded (the compressed build of each profile and storage policy, the
  final edit phase of each mutation source, and the last replayed stage of
  each recipe): a sparse writable raw copy, the native write sequence (bulk
  creation, growth, links, renames, removal, reuse, large attributes, a
  resource fork, native compression), `fsck`, an edit through the product
  binary, full preserved-state comparison, a further bounded allocation through
  Apple's kernel, checker acceptance and remounted readback of the complete
  result. Successful scratch copies are removed; failures retain their disk
  states and command diagnostics.

The constructed container's continuation independently writes every peer,
exhausts the limited volume's quota, reuses released quota, fills an unreserved
peer and proves the reserved volume remains writable. After syncing the reserved
proof, it truncates and removes the unreserved pressure file, deletes the proof,
then writes and syncs distinct contents on every peer in the same mount session.
Subsequent native bulk writes, clean unmount, filesystem checks, the Go edit and
final native allocation must all succeed. Pressure failures remain acceptance
failures; alternative cleanup sequences do not qualify this behavior. The System/Data output
requires native bulk allocation on System and checker acceptance. Go currently
refuses mutation of any role-bearing volume; that exact refusal must leave its
input unchanged and publish no destination. It is recorded explicitly rather
than claiming a successful Go edit of System/Data.

Cross-version verification requires every live and retained snapshot view,
matching volumes by name instead of attachment order. Missing and duplicate
views fail. Retained diskutil command plists supply roles and container UUIDs
that older observation records omitted; this is a read-only projection of the
original commands and digests. Global listings are scoped to the observed
container before validating its complete inventory; unrelated containers being
detached cannot invalidate that target. New APFS listing transcripts retain
complete text up to the parser's eight MiB bound. Missing text or malformed target
evidence fails explicitly. Captured evidence is never rewritten.

Transient readbacks retain input-file digests and all mounted observations.
They omit whole-device hashing when no assertion consumes it. Repack/recovery
disk-digest checks and fresh-container measured sizes remain required; fixture
capture continues recording both file and device digests.

Native attachment cleanup classifies the complete backing-image identity before
each detach request. Capture and verification use the same adapter contract:

| Ownership state | Evidence and cleanup result |
| --- | --- |
| Owned | The current device has the expected complete image path; normal detach is permitted. |
| Foreign | The device belongs to another image; no device action is permitted and cleanup returns an unreleased-attachment error. |
| Absent | Independent image scopes and the complete kernel media inventory corroborate that the device is gone, and the expected image is not still listed elsewhere; no detach is needed. |
| Unknown | Identity or absence could not be proved; cleanup fails with the original cause and performs no device action. |

A successful empty scoped `ioreg` query means that class had no matches. It
permits another independent query, but does not establish absence. Path parsing
uses macOS syntax; resolving the expected host file and symlink identity is a
separate step. The [retained platform captures](../acceptance/fixture/testdata/native-image-ownership/README.md)
preserve the original command bytes and document the portable replay projection.

Every portable, catalog-growth and native verification job first executes all
untagged acceptance helper tests. A closed inventory requires the evidence,
path, ownership-state, cleanup-error and failure-retention contracts to actually
run and pass. A missing or skipped contract, failed package, incomplete event
stream or nonzero test exit stops that job before corpus restoration and
filesystem verification. Windows executes these helpers; cross-compilation is
not runtime qualification. Tests use `-count=1` with both cold and warm build
caches, so an earlier test result cannot stand in for the current invocation.

Each macOS verification job also executes the live ownership contract before
building the continuation CLI. Its original schema-2 packet must bind all seven
owned, crossed, alias and post-close claims to that job's checkout, run attempt,
architecture and expected kernel major. Complete original command streams are
checked against their retained sizes and digests. The existing native ownership
artifact keeps those bytes and adds gate event logs and receipts in `gate-events/`;
portable jobs retain separate small contract artifacts. Uploads run on failure
as well as success, and upload failure blocks dependent verification. These are
local prerequisites within the existing jobs: all filesystem phases, matrices
and the final required gate remain mandatory and independent jobs do not wait
for another job's contract verdict.

Preservation exports receive a separate independent verdict. The verifier reads
their JSON and archive format without importing the product. It checks source
and creation identities, link groups, original byte names and portable name
mapping, every logical/raw/blob digest, projected file and symlink record,
metadata and serialized ACL bytes against the captured Apple view. Edits must
retain the preceding export's actual manifest digest. Host metadata availability
and creation provenance can differ between session exports, so every host's
complete archive is checked individually against the same native reference.

AppleDouble outputs are bound to the original export's path and digest. The
independent reader checks every host's actual bytes and serialized values.
The native job builds a small adapter that only calls Apple's public
`copyfile(..., COPYFILE_UNPACK)` API, then unpacks both the retained Apple
control and one byte-identical portable output onto fresh ordinary files on
the same destination filesystem. Native positive controls must restore every
nonempty ordinary attribute, FinderInfo and resource fork, and restore an ACL
when serialized ACL text is present. The unpacked data fork must stay intact;
the complete native attribute inventory and raw ACL must match the control.
Empty-value omission and ACL application remain native policy; serialized
presence and values are checked separately and exactly. Command transcripts
and readback digests are written to the native diagnostics directory. The
adapter is built and run only on guarded disposable CI VMs; no new captures,
fixture changes or CI jobs are required.

A known product limit is recorded where the output is produced, never by
weakening a comparison: `knownProductLimits` in
`acceptance/stage_replay_test.go` names the refusal a tracked issue makes
the continuation's product edit fail with. The native writes and their
`fsck` still run, the edit must fail with exactly that text, and an edit
that succeeds fails the check until the entry is removed with the fix.

Subtests run five at a time with `-v`, so progress is visible. Complete lineages
start longest first using retained timings; their members keep their order. Outputs
and fixtures that share filesystem identities (one recipe and profile's
lineage, or any fresh build) are attached one after another, never in
parallel. The job
summary lists every verdict and the cross-version drift table.

### Qualification boundaries

This coverage concerns the current admitted implementations. The `apfs-clones`
family isolates plaintext APFS/APFSX sharing from snapshots and volume encryption.
It retains native replacement, truncation, metadata, fork/attribute, unlink and
reclamation states. Portable edits must preserve untouched physical sharing;
native verification compares the sharing graph and requires further native clone
writes followed by the ordinary Go/native continuation.

The `encrypted-image-edits` family supplies native before/after states for APFS,
APFSX, HFS+ and HFSX and AES-128/AES-256 envelopes. Every producer emits both UDRO
and UDZO outputs with preserved, replaced or removed envelope credentials. Native
checks measure cipher policy independently and require the replaced password to
fail authentication. Encrypted continuations retain the source cipher through a
further Go/native edit. Both families require exact operation-clock projections
and preserved untouched timestamps rather than timestamp exemptions.

Positive software-encrypted APFS volume writing remains separate product work.
Existing nested encryption controls enforce distinct image/volume credentials,
authentication and the explicit write refusal; they do not qualify positive
nested writes. Snapshot mutation still requires the independent oracle in #74.

`TestRecursiveHostImportsPreserveNativeLogicalTrees` checks an attribute-free
subset of the native workspace tree: names, contents, empty directories, symlink
targets and hard-link classes. Archive metadata is compared with ordinary host
stat observations and explicit platform defaults; uncaptured ACLs and unavailable
attribute inventories must be reported. These portable controls emit no native
image artifacts. Full archive preservation of a foreign host's ACLs and attributes still needs an
independent host-input inventory policy and native control, tracked in
[#143](https://github.com/deploymenttheory/go-apfs-v3/issues/143). Host owner IDs,
birth-time availability and provenance cannot be treated as restored fixture
metadata or silently exempted from deterministic image checks.

The performance changes preserve the required gate. The support-policy revision
uses the ten-job workflow described above; the retained run measurements describe
their original eleven-job workflows.
Issue #134 remains open until three consecutive warm runs of the complete
combined workload record at most twelve jobs and forty-five minutes wall clock.

### Reproducing reliability qualification

Check the adapters and evidence validator without downloading or expanding the
real corpus:

```sh
go test -count=1 ./acceptance/fixture ./acceptance/native ./acceptance/corpus ./acceptance/schema ./.github/scripts/platform-contracts
go test -count=1 ./acceptance -run '^TestFixtureAndVerifierPackagesDoNotImportTheProduct$'
```

Then run the complete required CI matrix on the candidate revision. Retain its
checkout revision, run and attempt, platform/tool identities, contract receipts,
output manifests, case outcomes and elapsed times. Derive required case counts
from the pinned recipes, corpus and current output manifests; reconcile every
producer and verifier rather than copying counts from an older run. A failed,
missing or unfinished phase cannot qualify the change. Compare the original
fixture and expectation digests and review assertion changes independently.

The live ownership contract checks two blank raw images, their distinct full
paths, a real alias, crossed devices and completed cleanup. The retained native
captures demonstrate legacy CFData ownership and a successful empty modern-class
query. They do not establish filesystem health or a positive modern URL backend.
Those claims require their own native evidence and the applicable filesystem
verdicts. Capture new platform evidence on a disposable VM before changing its
interpretation; preserve original command bytes, collector source and digests,
and replay malformed and ambiguous controls alongside positive cases.

For storage qualification, exercise concurrent readers, cancellation, failed
cleanup and repeated runs. Each test binary checks `Corpus.Close`; an outstanding
lease, retained uncertain backing or failed run-directory deletion fails the
binary. The native fixture, slow and main invocations each own and close their
scratch child while retaining the compressed corpus. Record real working
footprint and runtime before making storage or speed comparisons; synthetic
lifetime checks alone do not supply those measurements. Never remove or move a
backing path whose release is uncertain. Document unresolved causes explicitly
and assess the integrated reliability outcome separately from product capability
and performance qualification.

## Diagnosing a failure

- **Portable**: the test name carries producer, recipe, profile and stage.
  Open the observation JSON in the corpus cache to see what the kernel
  reported; the difference message names the field.
- **Native**: the job summary names the output and the differing field.
  Every wait for macOS disk state (volume discovery after an attach, mount
  confirmation, a container appearing in `diskutil apfs list`, a busy
  `hdiutil`) goes through one bounded, jittered helper in
  `acceptance/fixture/settle.go`, is recorded in the case transcript, and
  is counted in the summary's wait table. A rising count records unsettled
  native state without identifying its cause. Verdicts are never retried.
  Diagnostics are uploaded on failure. A difference on one verifier identifies
  where it was observed; investigate the commands and observations before
  classifying it as an adapter, environment or product failure. Add verified
  legitimate version differences to `known-drift.json` with their evidence.
- **Capture**: the capture job prints each case; failures name the step
  index in the recipe. Diagnostics (transcripts, partial outputs) are
  uploaded on failure.

Capture writes its failure receipt after the existing cleanup has finished, so
the same report includes early format failures, cleanup commands and combined
operation/cleanup errors. Failure to retain that report is returned alongside the
original error. Native continuation transcripts likewise include commands across
observer handoffs and final cleanup. A tracked product refusal cannot suppress an
independent cleanup or evidence-retention failure.

For an exhausted busy detach, find `busy-detach-evidence` in the retained
command transcript. Its `StdoutText` is a JSON receipt containing the source
revision, workflow run and attempt, requested image/device, independent framework
and registry scopes, fresh related-device probes and mount source/FSID observations.
The expected image backend holding its own backing file is an observation; it
does not identify an ejection blocker. Missing or inconclusive observations leave
the cause unknown, and the original exhausted detach remains fatal.

To reconstruct the receipt, verify its `StdoutSHA256` against the UTF-8 bytes of
`StdoutText`, then parse that JSON. Each probe's `Command` is its original
transcript ordinal. In a merged continuation transcript, add the receipt's actual
ordinal minus `ReceiptCommand` to each probe ordinal. Read argv, exit status and
duration from the corresponding command. Base64-decode `Stdout.Data` and
`Stderr.Data`, verify each `StoredSHA256`, and compare the decoded length with
`Bytes`. Equal lengths also require the original `SHA256` to match. A shorter
retained stream or receipt error identifies incomplete evidence; it cannot support
a complete-output claim. Mount observations carry their own time and identity.
These probes have bounded time, target count and output retention and perform
no additional cleanup requests.

## History

The retired harness (removed in #110) ran about 311 jobs per pull request
in two to three and a half hours. Its evidence remains in git history and in
the `native-corpus-*` prereleases. The redesign is tracked in #98.
