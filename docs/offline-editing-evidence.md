# Offline image editing evidence

The admitted offline editing profile is qualified. Original native expectations,
portable outputs and successful Apple verdicts remain separately recorded and
connected by exact hashes. The [regression verdict](offline-editing-regression.md)
maps the closed checklist to this evidence.

The [evidence index](offline-editing-evidence.json) identifies 30 retained native
captures, 102 filesystem cases and 444 source/expected-state archives across
macOS 15, 26 and 27. It links each readable manifest, original manifest, command
log, collector source and archive to its SHA-256. Expected filesystem values
remain in their original captures. Naming projections retain the original
manifest and its decoded digest.

The index was checked against the stored bytes: all original manifest and
command-log digests, 510 collector-source digests and 444 archive digests match.
Decoded disk hashes and lengths come from the native manifests; this inventory
check did not decode disks or invoke Apple tools. Go acceptance separately
checks decoded source hashes before replay.

## What the controls establish

| Capability | Independent native controls and purpose | Portable replay | Apple output checks |
| --- | --- | --- | --- |
| APFS geometry and selected volumes | [Larger and multiple-volume images](../acceptance/testdata/apfs-geometry): edit one volume while retaining geometry, untouched peers and reserve/quota policy | `TestNativeAPFSGeometryEditing` | Filesystem checks, exact files/forks/metadata/identities, signatures and further allocation |
| HFS metadata initialization and node maps | [First attributes and map boundaries](../acceptance/testdata/hfs-metadata-growth): use Apple's formatter and native writes to establish absent attributes files and metadata growth beyond the initial node map | `TestNativeHFSMetadataGrowth` | Both name policies, admitted journal storage, tree/extent growth and further native writes |
| Fragmented HFS metadata lifecycle | [Fragmented growth](../acceptance/testdata/hfs-fragmented-metadata) and [collapse/reuse](../acceptance/testdata/hfs-metadata-lifecycle): preserve overflow extents as trees grow, collapse and reuse allocation | `TestNativeHFSFragmentedMetadataGrowth`, `TestNativeHFSMetadataLifecycle` | Exact namespace, attributes, tree depth, overflow ownership, filesystem checks and continued allocation |
| ACL inheritance and set-ID effects | [Native permission operations](../acceptance/testdata/permission-inheritance): establish creator identity, inherited ACLs and privilege-bit transitions on both filesystems | `TestNativePermissionInheritance`, `TestNativeSessionPermissionInheritance` | Native ACL/mode readback and continued creation/writing |
| Copy permission preservation | [Ordinary copying](../acceptance/testdata/copy-permissions), [set-ID copying](../acceptance/testdata/copy-setid-permissions) and [truncation](../acceptance/testdata/copy-truncation-permissions): compare preserved metadata and existing destination identity with Apple `cp` and related operations | `TestNativeCopyPermissions`, `TestNativeCopySetIDPermissions`, `TestNativeCopyTruncationPermissions` | Exact ACL composition, modes, dates and continued writes |
| APFS directory statistics | [Origins and inheritance](../acceptance/testdata/apfs-directory-statistics): compare native directory counts, allocated bytes and invalidation behavior | `TestNativeAPFSDirectoryStatistics` | Native `apfs.util` observations, filesystem checks and subsequent modification |
| APFS statistics transitions | [Forks, aliases, moves and deletion](../acceptance/testdata/apfs-directory-statistics-transitions): retain totals and ownership across repeated checkpoints and allocation reuse | `TestNativeAPFSDirectoryStatisticsTransitions` | Exact transition totals, checkpoint wrapping, filesystem checks and continued allocation |

Fresh capture combines the supplemental retained controls into the existing seven
capability families. Each family requires macOS 15/26/27 sources, replay on
Linux/Windows/macOS, and Apple verification on macOS 15/26/27. Native verifiers
require byte equality across portable hosts before sharing a native check. They
verify both UDRO and UDZO outputs and perform the applicable native continuation
workloads before their final checks.

## Completed qualification campaign

The full [portable/race/quality run](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/38510878495)
and [native compatibility run](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/38510878640)
passed for source `23d24783dd2bdbc6857bfe0d744bd102270b6bfb`. Its Git tree,
the actual CI execution revision and merged main
`0065fa987bce2b93de4131c3c2b87d7b204120d4` are identical. Original commit,
run, job, artifact and PR-check snapshots are retained in compressed form.

The [qualification ledger](offline-editing-evidence/qualification/ledger.json)
retains all 21 successful fresh native input ZIPs and all 21 successful Apple
verdict ZIPs byte-for-byte, including commands, observations, collector sources,
original manifests, native image archives and every member digest. Their 72 native
cases complement the unchanged 30-capture/102-case baseline above. Capture success
and portable replay are not substituted for native output verification.

There are 63 successful portable source/host replay jobs. Each of the 180 distinct
UDRO/UDZO outputs has an actual SHA-256 and length, three byte-identical host
bindings, its native case/manifest and successful Apple verdicts on all three
macOS versions. The binding identifies the original output artifact and tar
member. The Apple transcripts contain a successful `hdiutil verify` for every
bound image, the applicable filesystem/metadata/signature checks, and native
continuation workloads. The original verifier source and successful job verdict
establish assertions performed directly through native filesystem APIs.

Generated Go images are omitted from permanent storage. The original reference
ZIP, exact source revision, Go 1.27.0, replay job command/environment and output
hashes retain the information needed to reproduce them. Retained native inputs
and verdicts survive the campaign's January 12, 2027 artifact expiry. Historical
supporting evidence also survives the earlier January 11 deadline.

## Validate and reproduce

From the repository root, check all retained file/member digests, original
collector/command hashes, complete source/host/runner coverage, successful job
bindings, Git-tree equivalence and output/native-verdict membership:

```sh
python3 docs/offline-editing-evidence/verify_offline_editing_evidence.py
```

To independently hash the original portable images while their artifacts remain
available, download the 63 output artifact IDs recorded in the ledger to a private
directory as `ARTIFACT_ID.zip`, then run:

```sh
python3 docs/offline-editing-evidence/verify_offline_editing_evidence.py \
  --portable-artifacts /path/to/downloaded-artifacts
```

This additionally checks each original GitHub artifact/tar digest and streams all
540 actual image digests. Both commands use ordinary files and Python's standard
library; they do not run native tools, mount images or extend acceptance CI.

For output reproduction, check out the recorded construction source revision,
use Go 1.27.0 and unpack a retained reference ZIP into a private directory. Use the
corresponding replay job's recorded command and environment from
`.github/workflows/offline-editing.yml` at that revision. For example, after
unpacking `qualification/native-inputs/apfs/macos-15/reference.zip`:

```sh
APFS_REQUIRED_NATIVE_MAJORS=15 \
APFS_NATIVE_APFS_GEOMETRY=/path/to/references \
APFS_GEOMETRY_OUTPUT=/path/to/outputs \
go test -v -count=1 -timeout 25m ./acceptance -run '^TestNativeAPFSGeometryEditing$'
```

Compare the output members with the ledger's `relativePath`, `sha256` and `bytes`.
Additional file-only reproduction on Go 1.27.1 matched eight original CI outputs:
two APFS geometry outputs and six fragmented-HFS edited/collapsed/reused outputs.
Their exact logs are retained. Native checker/mount/continued-write qualification
remains restricted to disposable CI VMs.

## Historical evidence and failure recovery

The index preserves thirteen earlier successful Apple verdict archives and their
original diagnostics, original run/job/artifact snapshots, five earlier successful
native input archives and the original macOS 27 HFSX/APM creation failure archive.
They remain supporting evidence for their recorded revisions. The earlier cancelled
recovery run's individual successes are retained without calling that incomplete
campaign qualified. The former campaign references remain in `historicalCampaigns`.

The final native campaign's first attempt failed during macOS 26 busy-detach
cleanup after core allocation checks. The existing failed-job rerun completed
successfully on the identical source revision, retaining every prior successful
capture, replay and native verdict. Original and recovered job snapshots are both
preserved. Conditional alternative-path skips are individually accounted for in
the regression verdict. No original observations or expected values were rewritten.

## Publication and failure controls

[Completed-output publication](output-publication.md) has separate controls for
ENOSPC, short/failed writes, flushing, cleanup, cancellation, publication races
and process death. The relevant tests include
`TestPublicationPersistenceFailures`, `TestProcessDeathAtPublication`,
`TestCancellationAfterPublicationFinishesFlush`,
`TestPublishedFileClosedBeforeNameAndCleanupBeforeDirectoryFlush`,
`TestFailedOutputIsNeverPublished`, `TestInterruptedImageCopyPublishesNothing`
and `TestEditorFailureCannotPublishEvenIfCallbackIgnoresIt`.

These controls establish the completed-file publication contract alongside the
independent filesystem evidence. Windows supplies file flushing and atomic name
visibility; the implementation does not claim a Windows directory-entry flush
or physical hardware power-loss guarantee. Snapshot/clone mutation, encrypted
mutation and writable mounts require their own qualification.
