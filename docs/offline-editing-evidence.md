# Offline image editing evidence

Qualification is awaiting the remaining CI verdicts. The required checklist
remains open; captured expectations, successful portable replay and successful
Apple verification are recorded separately.

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

## Current campaign

The primary runs are [portable/race CI](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/38464460509)
and [native compatibility](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/38464460753)
for revision `2230e4b58836db7c8db190cee963576f01be83a6`.
Its complete Git tree and merged main revision
`62eb1150e214681e168a389c606331e830163b3b` both have tree identifier
`b12c21be83a1faa486998252dd9acc5beef18034`.
Native captures record the actual pull-request merge execution revision
`c2efb7cf1f5399a8cc276944104400ff9fa431ea`; its tree is also identical.
The duplicate pending merge campaigns were cancelled; their cancellation is
recorded separately from the active campaigns' pending verdicts.

The [earlier recovery campaign](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/38429354258)
finished cancelled with 186 successful jobs. Its macOS 26 core capture passed
on recovery, while three offline portable jobs and subsequent qualification
remained cancelled or unsuccessful. Its retained 21 offline captures and 60
portable successes are credited individually. Constructor inputs changed in the
diagnostics correction, so these outputs do not replace the primary campaign's
required fresh capture/replay.

The index also retains thirteen earlier successful Apple verdict archives and
their original diagnostics: ten from the original offline editing campaign and
three from the directory-statistics verifier correction. Each has a successful
job URL, original artifact identity and archive/file digests. These are
supporting evidence for their original revisions. Cancelled jobs that uploaded
apparently complete verdicts are excluded. Original job/artifact API snapshots
are retained as compressed metadata, with exact decoded-byte digests.

Completed qualification must bind each actual portable output digest to its
native source capture and successful Apple verdict. A job must have succeeded;
an uploaded verdict from a cancelled job is insufficient. Original manifests,
observations, commands and source images needed to reproduce outputs must survive
artifact expiry. Generated outputs may be omitted from permanent storage when
their exact inputs, construction revision, toolchain and digests are retained.
These final output bindings and verdicts remain pending in the index.

The current macOS 27 core capture failed while Apple created an HFSX/APM source.
Its original diagnostic archive is retained under `offline-editing-evidence/failures`.
The probes show the new failed image still attached, while the preceding fixture
had detached successfully. The lock owner remains unidentified. The original
error is a missing capture verdict, not a portable filesystem-engine failure.
The core upload omitted the context sidecar; the existing upload paths have
been corrected to retain it alongside command diagnostics.

Successful fresh native input archives are retained unchanged under
`offline-editing-evidence/native-inputs`, including the original disk sources,
expected observations and collector provenance. Each is admitted only after its
capture job succeeds and its manifest, command, collector and recorded archive
digests match. This keeps the inputs for exact output reproduction available
after GitHub's artifact retention period without replacing the local baseline.

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
