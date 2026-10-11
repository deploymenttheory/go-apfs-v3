# Packing filesystem and disk images

`pack` builds a new APFS or HFS+/HFSX filesystem from a directory or session, or repacks
an existing disk image while preserving all decoded sectors. Both operations
run on Linux, Windows and macOS.
The filesystem builders and UDIF encoder are pure Go. Apple tools are used only
for independent acceptance verification.

```sh
# Pack the contents of a directory into the volume root.
apfs pack --filesystem apfs --volume-name Example ./source Example.dmg

# Use case-sensitive APFS names.
apfs pack --filesystem apfs --case-sensitive ./source CaseSensitive.dmg

# Build a previously edited session. Its filesystem and case policy are retained.
apfs pack --session build --volume-name Example Example.dmg

# Fix the construction clock and choose uncompressed UDIF.
apfs pack --session build --volume-name Example --format UDRO \
  --time 2025-06-07T08:09:10Z Example.dmg
```

Directory import uses the existing session engine with archive preservation and
regular-file hard-link preservation. Scratch is created and removed automatically.
The directory's contents become the volume root's children; the volume root uses
the session creation defaults. A session build retains its captured root metadata.
`--scratch-dir` and `APFS_SCRATCH_DIR` locate named sessions and select the
temporary import scratch root. Unnamed imports default to the system temporary
directory.

`--filesystem apfs|hfsplus|hfsx` is required for directory input. APFS additionally
accepts `--case-sensitive`. A named session retains its native filesystem and case
policy. Cross-format metadata conversion is not implicit. An empty directory or
session builds an empty filesystem using the same command.

## Several APFS volumes in one container

```sh
# Three independent volumes sharing one allocation pool; the last starts empty.
apfs pack --capacity 2GiB --time 2025-06-07T08:09:10Z \
  --volume Applications --session apps --reserve 256MiB \
  --volume Resources --directory ./resources --case-sensitive --quota 512MiB \
  --volume Empty Bundle.dmg

# Pair a System volume with a Data volume. The named target may appear later.
apfs pack --volume System --session system --role system --group-with Data \
  --volume Data --session data --role data Group.dmg
```

Each `--volume NAME` begins a new volume clause. `--session NAME` or
`--directory PATH` supplies its contents; omitting both creates an empty volume.
Volume names must be unique in the CLI so `--group-with` is unambiguous. Reusing
a session supplies independent copies in separate volumes; hard links stay within
their own volume. Volume order is retained.

`--case-sensitive`, `--uid`, `--gid`, `--role`, `--reserve`, `--quota`,
`--volume-uuid`, `--group-with` and `--group-uuid` apply to the preceding volume.
Session inputs retain their case policy and ownership; use ordinary session
commands to change metadata. Case and ownership-default flags apply only to
directory or empty inputs. `--capacity`, `--time`, `--container-uuid`, `--format`,
`--scratch-dir`, `--file-compression`, `--encryption`, `--output-password-file` and `--json` apply to the complete build. JSON reports import
defaults and unavailable attributes separately for each volume.

Reserves guarantee available bytes; quotas cap a volume's allocation. Both round
up to 4096-byte blocks, with zero meaning no constraint. Planning includes volume
metadata and existing payloads in quota usage, and unused reservations in shared
capacity. An overcommitted build fails before publication. Automatic sizing also
accounts for the space manager's capacity-dependent overhead.

At most 100 volumes are admitted. Apple's container slot rule allows one volume
per rounded-up 512 MiB of capacity: two volumes require more than 512 MiB, three
require more than 1 GiB. Automatic capacity satisfies that rule. A volume's quota
may be smaller than this container-level slot allowance.

Roles are `none` (default), `data` and `system`. System construction requires an
explicit System/Data pair. Put `--group-with DATA_NAME` on the System clause;
the Data clause must have `--role data`. Members must have the same case policy,
and a volume can belong to only one group. `--group-uuid` optionally supplies a
nonzero canonical UUID on the System clause. Otherwise group, volume and
container UUIDs derive reproducibly from the complete ordered build inputs.
The group records native identity and inode namespaces; it does not install
macOS, create firmlinks, seal a system volume or produce a bootable installation.

## Repacking an existing image

```sh
apfs pack --format UDZO original.dmg compressed.dmg
apfs pack --format UDRO original.dmg uncompressed.dmg
apfs pack --json disk.raw packaged.dmg
```

A file operand selects sector-preserving repacking. The complete decoded disk is
retained: partition tables and identifiers, every partition, filesystem allocation
and metadata, recorded unused sectors, APFS volumes, encrypted volume sectors and
retained snapshots. No filesystem is unlocked, repaired, rebuilt or resized. No
session or intermediate raw disk file is needed. Construction-only flags, including
`--filesystem`, `--volume-name`, `--capacity` and `--time`, are rejected for image
input. The report supplies the preserved disk size and SHA-256.

Lossless here means identical decoded disk bytes. The output DMG envelope is newly
encoded; its compressed bytes, CRCs and segment identifier can differ from the
input. Files and application signatures inside the disk retain their exact bytes.
Bytes that an original image already omitted cannot be recovered by repacking.

The admitted inputs are flat raw GPT/APM disks with 512-byte logical sectors or recognizable bare APFS/HFS+
volumes, and flattened, single-segment version-4 UDIFs with XML metadata and raw,
zero/ignored, zlib or bzip2 runs. Block tables and runs must cover the entire disk
in order without overlap or gaps. Stored payloads must be accounted for. Every
present data, block and master CRC32 is verified before encoding. An absent native
checksum is accepted only when its complete field is zero; a computed disk hash
does not establish authenticity or filesystem health. Structural/checksum errors
fail without publishing an output; there is no repair or salvage option.

The encoder retains source block names, identifiers, ranges and the recognized
native empty `plst` placeholder. Unknown resource keys or values, nonempty/unknown
`plst` resources, extended footers, container signatures, notarization data and
unaccounted envelope bytes are refused. License resources are therefore refused
rather than removed. Signed applications inside an ordinary DMG are supported;
a signature on the DMG itself requires a separate future signing workflow.
Password-only version-2 encrypted DMG envelopes are admitted with an explicit
source password and output policy, as described below. The same strict inner
UDIF resource checks apply after decryption. Separately encrypted APFS sectors
survive unchanged and need no volume password for this operation.

Without output encryption, identical decoded image bytes, format and tool version
produce identical output across hosts. Repacking hashes the decoded disk before and during encoding and refuses a
detected change. Inputs must remain immutable for the call. Memory is bounded by
the existing decoder cache, a 4 MiB output chunk and bounded metadata; it does not
scale with disk capacity. The existing 1 TiB disk and 16 MiB XML limits apply,
with at most 4096 block tables and bounded XML depth/node counts.

`diskimage.Repack` borrows a `block.Source` and an output writer. `pack.Repack`
opens a source file and publishes the completed image at a new path with the same
flush, no-overwrite and cleanup contract as fresh builds below. Reader ownership
and output-on-error rules remain explicit. Raw forensic imaging of damaged or
unrecognized partition maps retains a separate qualification gate.

## Encrypted DMG output

Encryption applies to the complete disk image, independently of APFS volume
keys. The same options work for directory, session and multi-volume builds, and
for sector-preserving repacking:

```sh
apfs pack --session build --encryption AES-256 \
  --output-password-file ./new-password.bin Encrypted.dmg

# Replace an image password while keeping every decoded disk sector.
apfs pack --image-password-file ./old-password.bin --encryption AES-256 \
  --output-password-file ./new-password.bin original.dmg changed-password.dmg

# Removing image encryption is always explicit.
apfs pack --image-password-file ./old-password.bin --encryption none \
  original.dmg decrypted.dmg
```

Choose `AES-128` or `AES-256`; `--output-password-file` is required with either.
The source password and output password are separate even if their bytes match.
A password file contains exact bytes: whitespace and final newlines are retained.
Use `-` for stdin through EOF; only one password can read stdin in a command.
New passwords require 1–4096 bytes with no NUL, to remain usable with Apple's
NUL-terminated password input. Passwords never appear in reports or command-line
arguments. The CLI clears its password buffers after use; library passwords are
borrowed for the call and remain unmodified.

Output is a password-only `encrcdsa` v2 envelope around UDRO or UDZO. It uses
AES-CBC for payload blocks, the format's HMAC-SHA1 block IV derivation, and
PBKDF2-HMAC-SHA1 with 600,000 iterations and a fresh salt to wrap new payload keys
using AES-192-CBC. Every call draws a new identity, salt, wrapping IV and keys
from `crypto/rand`. There is no deterministic-encryption option. Identical build
inputs and clocks retain identical plaintext image/disk bytes; ciphertext differs
between runs and hosts. Unencrypted builds remain byte-identical.

Encryption streams directly into a private ciphertext staging file. It does not
create a plaintext DMG or raw-disk temporary file. Directory import and named
sessions retain their existing plaintext scratch policy. Write, callback,
cancellation, flush and publication failures use the normal cleanup contract.
The library's encrypted output writer must be an empty `io.WriteSeeker`, because
the complete plaintext length is recorded only after successful encoding.

Encrypted repacking accepts exactly one supported password record. Both Apple's
older 3DES-wrapped and current AES-wrapped source keys are decoded; new keys use
the AES-wrapped profile. Certificate/keybag records, extra credentials, unknown
nonzero header resources and trailing bytes are refused rather than discarded.
Signed inner DMGs remain refused. This format does not authenticate the payload;
CRC checks detect damage in UDIF inputs, not authenticity. Repacking an encrypted
raw disk has no equivalent whole-disk checksum supplied by its envelope.

Use `pack.Options.Encryption` or `pack.ContainerOptions.Encryption` for builds.
`pack.RepackWithOptions` and `diskimage.RepackWithOptions` take
`diskimage.RepackOptions`, with `SourcePassword`, `Encryption` and explicit
`Decrypt`. A nil source password means none supplied. The original `Repack` API
retains its credential-free behavior and refuses encrypted input.
`diskimage.Encrypt` also exposes the bounded streaming envelope encoder. Keep all
sources immutable until completion, and discard library output on any error.
Image encryption does not create or change FileVault/APFS volume keys.

## Fresh-output and preservation contract

The output is a single-region UDIF without a partition map, with 4096-byte
filesystem blocks. HFS+/HFSX is clean and nonjournaled. APFS contains one or more
unencrypted, unsealed volumes and a complete initial checkpoint, object maps,
filesystem/extent-reference trees, space manager and free queues. It is a fresh
filesystem; source snapshots, clone sharing, physical allocation and native inode
numbers are not carried into a rebuild. `--format UDZO` (default)
uses zlib compression; `UDRO` uses raw chunks. Both represent zero chunks without
storing their bytes and include data, block and master CRC32 checksums. Compression
of the DMG envelope is independent of compression of files inside the volume.

Names use the pinned native comparison rules: APFS retains spelling and compares
with normalization, while HFS uses its frozen decomposition. Case policy belongs
to the source session. Data,
resource forks, ordinary attributes, opaque security attributes, public FinderInfo,
ownership, permissions, BSD flags and all four captured timestamps are preserved
when representable. Symlinks retain literal targets. Regular-file aliases share
one native inode through APFS sibling records or HFS's private-directory indirection. Native inode numbers
and the physical extent layout are newly assigned. Link counts describe the aliases
inside this build; references outside a captured subtree cannot exist in its output.

Unchanged decmpfs types 1, 3, 4, 7 and 8 can retain their stored representation.
Native build acceptance covers each admitted type, including native LZVN resource
storage and the type-7 stored marker. Other preserved compression types fail explicitly.
`--file-compression` can explicitly replace file storage as described below.
Sparse input has identical logical bytes but is allocated contiguously.

Uncaptured required metadata, subsecond or out-of-range HFS timestamps, unsupported
object types, directory hard links, reserved names/attributes and unrepresentable
FinderInfo fail explicitly. An input claiming an independently present empty resource fork is rejected in
this construction profile. Available attributes are never
silently dropped. Host-import defaults and unavailable attributes are reported;
packing cannot recreate metadata the host did not provide.

APFS preserves nanosecond times in the supported 1970–2262 signed-nanosecond
range, including exact epoch zero. Tracked documents receive fresh document IDs.
Active compressed inputs must have consistent decmpfs headers, sizes, flags and
decodable storage; the default preserves stored compression. Unknown BSD flag bits,
reserved filesystem-owned attributes and unsupported object kinds are refused.
APFS symbolic-link targets are literal, with a current 1023-byte construction limit.

`--uid` and `--gid` set directory-import defaults for unavailable ownership. Existing
observed ownership is preserved. Use session `chown`, `chmod`, `touch` and the other
file commands for deliberate changes before packing. Flags accept ordinary operands;
JSON is an optional output report only.

## Transparent file compression

```sh
apfs pack --filesystem apfs --file-compression zlib ./payload App.dmg
apfs pack --session build --file-compression none App.dmg
```

The same policy applies to APFS, case-sensitive APFS, HFS+ and HFSX, and to every
volume in a multi-volume build. `--file-compression preserve` is the default:
existing qualified compression storage remains byte-exact, and ordinary files
remain ordinary. `zlib` reads logical contents and requests fresh native decmpfs
type 3 (attribute storage) or type 4 (resource-fork storage). `none` writes logical
data without active compression, removing its decmpfs attribute and only the
resource fork owned by that compression type. Inactive decmpfs metadata stays
opaque. These options apply to fresh filesystem builds; sector-preserving image
repacking refuses an explicitly supplied file-compression option.

File compression is independent of `--format UDRO|UDZO`, which describes the DMG
envelope. Both DMG encodings and encrypted output can contain compressed files.
The shared storage preparation runs before either filesystem engine plans its
layout, so compressed sizes drive automatic capacity and allocation. It keeps
names, logical contents, hard-link relationships, ordinary attributes, independent
forks and recorded timestamps. Only compression-owned storage and UF_COMPRESSED
change. Existing application signatures continue to cover the same logical bytes.

An attribute can contain at most 3802 bytes including the 16-byte decmpfs header.
Larger representations use a Resource Manager `cmpf` resource with independently
encoded 64 KiB blocks; incompressible blocks use Apple's stored marker. Compression
is used only when its complete attribute/resource representation is smaller than
the logical data fork. Empty and tiny files, incompressible files, representations
exceeding Resource Manager's 32-bit range, an independent
fork that would conflict with required resource storage, and inactive decmpfs
attributes are reported with explicit reasons. An independent resource fork can
coexist with attribute-based compression and is never overwritten. Under `zlib`,
an existing active representation is decoded first; a skipped file becomes
ordinary storage with its logical bytes and independent metadata preserved.

JSON reports include `fileCompression` and one `compression` outcome per regular
file identity considered by an explicit policy. Each outcome carries its first
byte-sorted path, source object, optional volume, action, reason, native type,
logical bytes and stored bytes. Text output lists skipped files and reasons;
hard-link aliases share one outcome. With `none`, outcomes identify files whose
active compression was removed. Default `preserve` adds no per-file outcomes.

The encoder uses one 64 KiB input buffer plus codec scratch. Resource descriptors
are patched in managed, private temporary files; their index and encoded data
must fit Resource Manager's 32-bit ranges. Scratch contains encoded file bytes,
can consume disk space proportional to the encoded files, and is removed before
return, including after cancellation or I/O failure. `--scratch-dir` selects its
parent; callers never configure internal paths. The complete preparation has a
shared 64 MiB metadata budget across container volumes and the builders' existing
entry/depth limits. Rechecking logical source hashes after writing prevents staged
compressed bytes from hiding changed input. Sources remain borrowed and immutable.
Destination publication still requires successful writing and scratch cleanup.

Fixed inputs/options and the pinned Go encoder produce byte-identical plaintext
output across hosts. Apple and Go compressed streams may differ; native codec and
filesystem readback establish equal logical bytes, rather than matching encoder
bytes. Fresh native qualification is described in the acceptance documentation.

## Capacity and reproducibility

`--capacity` specifies APFS container or HFS volume bytes, optionally suffixed `KiB`, `MiB` or `GiB`.
Capacity rounds up to a 4096-byte block and must be at least 8 MiB. Automatic sizing reserves space for every
payload and metadata tree plus free space, with an 8 MiB minimum. Insufficient
capacity fails before output publication.

`--time RFC3339` fixes the construction clock; HFS requires whole seconds while
APFS accepts nanoseconds. It does not normalize captured file timestamps. Without it the command samples the current UTC clock.
Default native identifiers derive from canonical metadata and payload hashes.
HFS `--volume-id` accepts an eight-byte identifier as 16 hex digits. APFS accepts
`--volume-uuid` and `--container-uuid` as nonzero canonical UUIDs; absent values use
distinct content-derived UUIDs. Options belonging to the other format are refused.
Enumeration, native object-ID assignment, allocation, zero filling, chunking and zlib settings
are deterministic. Identical captured inputs and options produce byte-identical
unencrypted outputs across all three hosts; encrypted output preserves identical
plaintext bytes but uses fresh randomness. Different host-import observations or Go encoder
versions are not assumed to be identical. Reproducible builds should pin their
input session and tool version.

Planning bounds are 100,000 entries per volume, depth 256, 4096 attributes per object,
a shared 64 MiB metadata accounting budget and fewer than 16,000 used nodes per B-tree.
An APFS container or HFS volume is limited to 1 TiB. File data streams through a bounded 4 MiB DMG chunk buffer;
file size does not determine RAM usage. Content-derived identifiers require a
payload hash pass before the streaming output pass. No intermediate raw disk image
is materialized.

## Publication and library API

`apfs.Plan` and `hfsplus.Plan` borrow immutable `filesystem.Reader` values and
return bounded layouts with `Size` and `Write`. Each engine owns its format
options and validation. `pack.VolumeOptions` supplies common construction choices;
`pack.Write` selects the engine from the reader's native format.
`apfs.PlanContainer` takes ordered `apfs.VolumeSpec` inputs and
`apfs.ContainerBuildOptions`, including groups identified by volume indexes.
`apfs.Plan` is the single-volume wrapper around that engine. `pack.WriteContainer`
streams its result; `pack.CreateContainer` publishes it with the same contract
as `pack.Create`. All readers remain borrowed and immutable through completion.
`diskimage.EncodeVolume` independently consumes a sized sequential source with an
`Apple_APFS` or `Apple_HFS` content hint. The existing `Encode` retains its HFS default. `pack.Write` connects them with
bounded streaming and stops
both sides on failure. Readers and values retain their existing lifetime rules.

`pack.Create` writes a private sibling temporary file, flushes and closes it, then
publishes with a no-overwrite hard link. An existing destination, including a
symlink, is refused. The destination host filesystem must support hard links
(e.g. NTFS on Windows). A failure before publication leaves the destination absent;
normal cleanup removes staging. Abrupt process termination can leave a private
`.apfs-pack-*` sibling. The final image is complete once publication succeeds;
power-loss directory durability and edits to existing images have separate gates.
The CLI refuses destinations inside the managed session scratch directory.

## Independent qualification

One `image-building` acceptance family starts from Apple-created APFS,
case-sensitive APFS, HFS+ and HFSX images.
Its source contains deep catalog trees, large and empty attributes, resource forks,
compressed files, native filenames, aliases and an Apple-signed universal app.
Every portable host captures a session and builds UDRO and UDZO twice. Automatic
8 MiB and explicit 160 MiB capacities exercise multi-block allocation bitmaps and
checksum-covered zero chunks; long keys force a three-level catalog. Local
comparisons check the original observations and reproducibility. CI returns every
output to macOS 15, 26 and 27 for `hdiutil verify`, `fsck_apfs -n` or
`fsck_hfs -fn`, read-only mounted
readback and `codesign --verify --deep --strict`. An independent Python comparison
checks exact values and a bijection of link identities; hashes must match across
portable hosts for the same captured input and options. No Go writer or reader
supplies the native expected values or the final native verdict. CI requires
same-input output hashes to match across hosts before verifying one identical
copy of each image on every macOS version.

APFS adds exact birth nanoseconds, tracked documents, 53 native positive/negative
name lookups per profile and an independently observed empty-directory build. Each
Mac also modifies every APFS output through a disposable shadow: file growth, hard
links, rename, deletion, tree growth and allocation reuse. The new checkpoint must
pass Apple's checker without repair and retain its contents after remounting; the
original image hash must remain unchanged. Fresh builds qualify native continued
use, not Go transactions or power-loss durability.

Two additional cases remain within this same family: a three-volume container
with mixed case policies, a reserve, a quota and an empty volume; and a System/Data
group. Their native inventories supply UUIDs, roles, grouping and space limits.
Native pressure controls exhaust the limited volume and an unreserved neighbour,
prove that the reserved volume can still write, then delete and reuse allocations.
Every volume undergoes independent file growth and remount checks. These cases
add four images per producer/consumer, without multiplying all existing file
profiles. All 117 host images must agree in triples; each Mac checks the resulting
39 distinct images, including 27 APFS allocation journeys.

Native image-building tests require a disposable macOS VM. The helper admits
GitHub-hosted Actions VMs, or an explicit `APFS_NATIVE_DISPOSABLE_VM=1` inside
another isolated disposable VM. It refuses a normal local invocation. The
[kernel-panic incident](native-testing-incident.md) explains this requirement;
shadows protect image bytes, not the host kernel. Portable Go tests need no
native attachment and remain suitable for local development.

The `image-repacking` family reuses independently captured signed-app and snapshot
images, then adds native bare HFS+, raw GPT and HFSX Apple Partition Map disks with seeded free
sectors, and two APFS volumes sharing a container, one encrypted. Inputs exercise
raw, UDRO, UDZO and UDBZ storage. Apple devices supply the complete disk hashes;
all three hosts produce UDRO/UDZO twice. All 90 outputs must agree in triples;
every Mac verifies the 30 distinct images with
`hdiutil verify`, raw-device SHA-256, partition/volume inventories, native mounted
file and raw-attribute observations, retained snapshot mounts, encrypted-volume
unlocking, filesystem checks and application signature verification. Cross-host
image hashes must agree. The native comparison never invokes Go.

Encrypted output extends these two existing acceptance families. A bounded set
covers APFS, case-sensitive APFS, HFS+, HFSX and a System/Data group, both ciphers
and both UDIF encodings. Repacking adds all five disk-preservation profiles,
password replacement, explicit decryption, and the existing Apple-created
encrypted UDRW input. The outer envelope never needs an APFS volume password.
Every Mac independently unlocks each of the 108 randomized portable outputs,
checks the reported native cipher and rejected passwords, verifies UDIF CRCs,
and hashes the complete attached device against its independently qualified
plaintext disk. Password changes also reject the old credential. The raw input
comparison starts from Apple's decrypted source device. The 18 explicitly
decrypted outputs must agree across hosts and have no image encryption.
Source and output hashes remain unchanged by native readback. These checks add
no new workflow or scenario family and never use a Go decoder for the final
native verdict.
