# Offline image editing regression verdict

The admitted offline editing profile is qualified at merged revision
`0065fa987bce2b93de4131c3c2b87d7b204120d4`. The full
[portable, retained-corpus, race and quality run](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/38510878495)
and [native compatibility run](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/38510878640)
completed successfully. This verdict closes the requirements in the
[qualification checklist](offline-editing-qualification.md), within the
[documented admission limits](offline-editing-limits.md).

## Construction and complete coverage

The tested PR source `23d24783dd2bdbc6857bfe0d744bd102270b6bfb`, actual CI
execution revision `05f3924a165f5bbc3f4f2c286b71609ca0243cb8` and merged
revision have identical Git tree `ab38c4a864aff7d7911955688dd2a236b25fbaf7`.
Original GitHub commit snapshots retain that comparison. Qualification therefore
applies to merged code without treating earlier, different construction revisions
as equivalent. This closure changes documentation and retained evidence only.

The portable run has 169 successful jobs, including the full quality gate,
all retained acceptance groups, library and acceptance race groups, cross-builds,
vet/lint and mocked native-recorder/verifier controls. The final native attempt
has 227 successful jobs and three conditional skips. PR checks additionally
include successful title and dependency reviews and the inapplicable Dependabot
auto-merge check: 398 successes and four conditional skips in total.

The three native skips are alternative execution paths: manual capture-only,
archived-output admission, and the HFS workflow's obsolete delegated journal
placeholder. Actual HFS journal recovery has its own successful required capture,
portable replay, Apple readback and aggregate. None of the seven offline editing
families is skipped: all 21 captures, 63 portable replays and 21 Apple readbacks
passed, together with the required offline aggregate.

The [permanent ledger](offline-editing-evidence/qualification/ledger.json)
retains every workflow/job verdict, original artifact identity and output binding.
Its 72 fresh native cases produce 180 distinct UDRO/UDZO outputs, each identical
across Linux, Windows and macOS: 540 host output bindings. Each image appears in
the successful Apple command transcripts on macOS 15, 26 and 27. Checkers use
`fsck_apfs`, `fsck_hfs`, or `diskutil verifyVolume`, according to the existing
verifier; their recorded statuses are zero. Applicable mounted observations,
signatures and continued native modification remain required by those verifiers.

## Requirement mapping

| Checklist requirement | Qualifying controls and tests | Independent Apple evidence |
| --- | --- | --- |
| Validated APFS geometry | `TestNativeAPFSGeometryEditing`; retained and fresh 1.5 GiB cases under both native name policies; bounded ownership/allocation inventories | Ledger `apfs`: original geometry, checker acceptance and further allocation |
| Selected volume, peers and volume limits | Same geometry test; 768 MiB multi-volume inputs, explicit UUID selection, unchanged peer bytes and reserve/quota refusal | Ledger `apfs`: mounted peers, allocation limits and continued writes |
| Directory statistics and repeated checkpoints | `TestNativeAPFSDirectoryStatistics`, `TestNativeAPFSDirectoryStatisticsTransitions`; retained transitions, overflow/refusal controls and repeated-edit stress | Ledger `statistics` and `statistics-transitions`: native `apfs.util` totals, generation relationships, forks/aliases/moves/deletion and continued allocation |
| First HFS attributes | `TestNativeHFSMetadataGrowth`; Apple's pinned formatter produces independently observed absent-attributes inputs | Ledger `hfs`: both name policies, first attributes, checker acceptance and continued allocation |
| Fragmented metadata and node maps | `TestNativeHFSMetadataGrowth`, `TestNativeHFSFragmentedMetadataGrowth`, `TestNativeHFSMetadataLifecycle` | Ledger `hfs` and `hfs-fragmented`: node-map growth, overflow extents, deletion, native root-collapse behavior and reuse; edited/collapsed/reused outputs |
| Ordinary ACL/set-ID and refusal policy | `TestNativePermissionInheritance`, `TestNativeSessionPermissionInheritance`, `TestNativeCopyPermissions`, `TestNativeCopySetIDPermissions`, `TestNativeCopyTruncationPermissions`; shared filesec/copyfile rejection controls and [admission inventory](offline-editing-limits.md) | Ledger `permissions` and `copy-permissions`: exact ACL/GUID/mode observations, root/non-root effects, copy/truncation behavior and subsequent native inheritance |
| Ordered commands and one publication | `TestNativeSessionPermissionInheritance`, existing file-command/session acceptance, editor failure controls; sessions remain ordinary command sequences | Complete portable/native regression, immutable retained session controls and the required native file-command and existing-image edit families |
| Completed-output publication | `TestPublicationPersistenceFailures`, `TestProcessDeathAtPublication`, `TestCancellationAfterPublicationFinishesFlush`, `TestPublishedFileClosedBeforeNameAndCleanupBeforeDirectoryFlush`, `TestFailedOutputIsNeverPublished`, `TestInterruptedImageCopyPublishesNothing`, `TestEditorFailureCannotPublishEvenIfCallbackIgnoresIt`; actual CLI interruption checks | Complete library/race/native recovery gates; fault controls establish host I/O outcomes alongside the independent filesystem oracle, with [Windows persistence limits](output-publication.md) retained |
| Immutable cross-platform evidence | 30 original retained captures / 102 cases plus this campaign's 21 original native input archives and 21 successful verdict archives | Exact source, command, collector, compressed/decoded native-image hashes and 540 actual output bindings in the permanent ledger |
| Complete regression and accurate scope | Both complete workflow verdicts above, original and recovered job snapshots, qualification evidence validator | Required aggregates passed; admitted profiles and separately scoped capabilities remain explicit |

## Reliability incident outcomes

HFS copy profiles remain in the original nine source/host jobs. Each runs four
separate test processes, preserving the five-minute deadline, flushing and all
assertions. The ledger retains all nine original logs and 36 successful profile
timings; the slowest profile took 41.49 seconds. Workflow selection and mocked
controls passed in the full quality gate. Windows private staging now explicitly
establishes sparse gaps, retaining observable incomplete-copy length. Its sparse
allocation and actual CLI interruption checks passed; the previously timed-out
Windows HFS metadata suite completed in 77.35 seconds under its unchanged deadline.

Apple image creation still has one bounded attempt. The recorder retains its
original status/output, guarded read-only failure probes, runner/tool identity and
owned partial-output metadata. The existing uploads now include the context
sidecar. Original busy-creation evidence remains archived unchanged. The lock
owner remains unknown; neither the deprecation warning nor filesystem corruption
is claimed as its cause. Fresh captures passed on macOS 15, 26 and 27.

Setup/DNS recovery and archived-output admission use the existing facilities;
their strict unchanged-construction and complete-source/host controls passed.
The final native run first encountered numeric EBUSY while detaching after macOS
26 core allocation checks. Only failed jobs were rerun on a fresh disposable VM,
on the identical source revision. That readback and its dependent full aggregate
passed; all prior successful captures, replays and Apple verdicts were retained.
The original and final job snapshots preserve both outcomes. No checker failure,
semantic mismatch or continued-write assertion was waived.

## Supported scope and remaining capabilities

This verdict covers ordinary plaintext APFS editing on the admitted single-device
geometry and clean HFS+/HFSX, including validated empty internal journals. Commands
use managed scratch and publish a validated new image. The 64 MiB APFS allocation
bitmap budget, admitted space-manager geometry, HFS Extents Overflow resident-file
constraint, bounded batches/traversals and protected-object rules remain in force.
Logical actor UIDs select metadata effects; they do not emulate host authorization
or resolve stored GUIDs to accounts.

Windows provides completed-file flushing and atomic name visibility, with no
unprivileged directory-entry flush guarantee. Fault controls do not establish
physical hardware power-loss survival. Snapshot-preserving mutation and lifecycle,
clones/shared streams, encrypted mutation, live journal writing and writable mounts
have separate algorithms and qualification requirements. Their status is unchanged.
