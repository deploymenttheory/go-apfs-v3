# Acceptance testing

The product claims to read, build and edit APFS and HFS+/HFSX images the way
macOS does. Acceptance testing therefore compares the product with
fixtures that Apple tools produced, and verifies images the product produced
with Apple tools, on macOS 15, 26 and 27. Three tiers do this:

| Tier | Where | What | When |
| --- | --- | --- | --- |
| Fixture corpus | macOS 15, 26, 27 runners | Recipes executed with Apple tools and system calls; the kernel's view recorded | Manual dispatch, when a recipe changes or a macOS version is added |
| Portable conformance | Linux, Windows, macOS | The product reads every fixture from every producer and must match the observation; it builds, edits, copies, repacks and encrypts images from the fixtures | Every pull request |
| Native truth | macOS 15, 26, 27 | Each version judges, with `hdiutil`, `fsck`, `codesign` and mounted readback, the images every host derived from its own fixtures; native writes and a further product edit follow on a representative set; fixtures from the other versions are cross-mounted | Every pull request |

One pull request starts eleven jobs, four of them macOS: source checks,
race-checked unit tests, portable conformance on Linux, Windows and macOS,
the slow bucket on Linux and Windows, native truth on macOS 15, 26 and 27,
and `gate`. Ruleset 24806824 requires `gate` (the `Required checks` status)
before anything merges to `main`.

The native jobs start beside the portable jobs, after the two-minute
source checks. Each first reads the other two versions' fixtures, which
needs only the corpus, while the portable jobs produce their images; it
then collects every host's images as soon as they are uploaded, verifies
them, and does the same for the slow bucket's. A phase whose inputs come
from a failed job stops at once instead of waiting.

## The matrix

- **Producers**: the macOS versions that captured fixtures (15, 26, 27).
- **Hosts**: where the product runs (linux, windows, darwin).
- **Verifiers**: the macOS versions that judge the product's output (15, 26, 27).

Every fixture from every producer is read on every host. Every image the
product produces is verified by the macOS version whose fixture it came
from, on every host's copy where the copies differ: plaintext outputs must
be byte-identical across hosts, and each host's encrypted output must
decrypt to the same device. Every verifier therefore judges every kind of
structure the product writes, without repeating the same bytes three times.
Every fixture is also mounted on the two verifiers that did not produce it,
and any difference the kernel reports must be in
`acceptance/known-drift.json`.

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

The corpus cache is `os.UserCacheDir()/go-apfs-v3/fixtures/<digest>` or
`APFS_FIXTURE_CACHE`. Gzip-compressed raw images are expanded sparsely under
`os.TempDir()/go-apfs-v3-fixtures` or `APFS_FIXTURE_EXPAND`: zero runs are
never written, so an expanded corpus costs its data blocks (a few hundred
megabytes), not the images' nominal sizes, and the CI cache never carries
expansions. `cmd/apfs-fixture capture` refuses to run outside a
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
APFS's checker supplies the selected XID and its kernel mount supplies the view.
Deliberate APFS checksum damage records the parent digest and exact byte change;
a separate descriptor-disabled control supplies the independently checked older
state. Damaged originals are never mounted to fabricate a fallback expectation.

Observations bind these cases with `recovery`; HFS replayed states also name
their `replayOnly` image. Each case retains the native helper sources and binary
digests. All original images, transcripts, observations and digests remain
immutable. A full capture includes both recipes; missing profiles or stages
fail portable conformance.

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
  without a test that asserts on it.
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
produces each output once: the native tier requires every host's copy to
be byte-identical, which covers the repeat and catches more.

## Native truth

`go test -tags native ./acceptance/native` on each macOS version, with
`APFS_EXPECT_MAJOR`, `APFS_HOST_OUTPUTS` (each host's
`outputs-<host>-macos-<major>` artifact and the slow bucket's
`slow-outputs-<host>`) and `APFS_PRODUCT_CLI` (the built product). The
portable jobs upload one artifact per producer, so a native job downloads
only the third it verifies. It pairs every output by name across hosts,
requires plaintext copies to be byte-identical and encrypted copies to
decrypt to the same device, then judges each output:

- **Sector-preserving repacks**: the attached device digest, which must
  equal the digest the kernel recorded for the source. The sectors are
  Apple's own image, already mounted and checked on the producing Mac, so
  what Apple must still accept is the container. `hdiutil verify`, which
  re-reads a whole image to check its UDIF checksums, runs on the first
  repack of each format and encryption in a lineage. Apple decrypts one
  host's copy of each encrypted repack, rotating through the hosts; every
  host decrypts all of its own encrypted outputs with the product in the
  portable tier.
- **Images the product wrote** (builds, edits, stage replays, encrypted
  builds): `hdiutil verify`, read-only attach, `fsck_apfs -n` or
  `fsck_hfs -fn`, `codesign --verify --deep --strict`, mounted readback
  with the capture observer, and comparison with the expected view.
- **Continuation**, on a representative set marked where outputs are
  recorded (the compressed build of each profile and storage policy, the
  final edit phase of each mutation source, and the last replayed stage of
  each recipe): a sparse writable raw copy, the native write sequence (bulk
  creation, growth, links, renames, removal, reuse, large attributes, a
  resource fork, native compression), `fsck`, an edit through the product
  binary, and a final check. Each continuation's scratch is removed when
  it finishes.

A known product limit is recorded where the output is produced, never by
weakening a comparison: `knownProductLimits` in
`acceptance/stage_replay_test.go` names the refusal a tracked issue makes
the continuation's product edit fail with. The native writes and their
`fsck` still run, the edit must fail with exactly that text, and an edit
that succeeds fails the check until the entry is removed with the fix.

Subtests run three at a time with `-v`, so progress is visible. Outputs
and fixtures that share filesystem identities (one recipe and profile's
lineage, or any fresh build) are attached one after another, never in
parallel. The job
summary lists every verdict and the cross-version drift table.

## Diagnosing a failure

- **Portable**: the test name carries producer, recipe, profile and stage.
  Open the observation JSON in the corpus cache to see what the kernel
  reported; the difference message names the field.
- **Native**: the job summary names the output and the differing field.
  Every wait for macOS disk state (volume discovery after an attach, mount
  confirmation, a container appearing in `diskutil apfs list`, a busy
  `hdiutil`) goes through one bounded, jittered helper in
  `acceptance/fixture/settle.go`, is recorded in the case transcript, and
  is counted in the summary's wait table; a rising count is the first sign
  of a runner problem. Verdicts are never retried.
  Diagnostics are uploaded on failure. A difference on one verifier only is
  Apple version behaviour; record it in `known-drift.json` with a reason if
  it is legitimate.
- **Capture**: the capture job prints each case; failures name the step
  index in the recipe. Diagnostics (transcripts, partial outputs) are
  uploaded on failure.

## History

The retired harness (removed in #110) ran about 311 jobs per pull request
in two to three and a half hours. Its evidence remains in git history and in
the `native-corpus-*` prereleases. The redesign is tracked in #98.
