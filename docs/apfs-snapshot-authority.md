# APFS snapshot execution authority

Research checked 2026-11-03 for [issue #74](https://github.com/deploymenttheory/go-apfs-v3/issues/74). The required capability is native creation and naming of snapshots, followed by native reversion of an ordinary disposable APFS image on macOS 26 and 27. No complete supported execution route is established by the evidence below. Packaging a helper is conditional work, not a demonstrated solution.

## Existing observations

The issue's retained evidence reports unsigned `fs_snapshot_create`, `fs_snapshot_rename` and `fs_snapshot_revert` calls returning `EPERM`, and an ad-hoc signed observer claiming `com.apple.developer.vfs.snapshot` being killed at launch. Missing DER entitlements and an ordinary-directory `ioctl` alternative were already ruled out. These are observations of the tested configurations, not proof that every Apple-authorized configuration fails. No new native operation was run for this note, and original captures, logs and digests remain unchanged. [Evidence record](https://github.com/deploymenttheory/go-apfs-v3/issues/74).

## API authority and its limits

Apple's snapshot manual documents superuser privileges plus an additional entitlement. The filesystem must support snapshots, and the descriptor identifies its root. [Apple snapshot manual](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/man/man2/fs_snapshot_create.2).

Apple's published dispatcher at commit `f6217f891ac0bb64f3d375211650a4c1ff8ca1ea` requires one of `com.apple.private.vfs.snapshot`, `com.apple.developer.vfs.snapshot`, or `com.apple.private.apfs.arv.limited.snapshot`; otherwise it returns `EPERM`. That gate has no platform-binary exemption. Create, rename and revert then require superuser authority, device write authorization, or `com.apple.private.vfs.snapshot.user`. Those checks do not guarantee acceptance by subsequent MAC/filesystem policy. The private entitlement names are implementation evidence, not third-party provisioning offers. [Pinned Apple source, `vfs_context_can_snapshot` and `fs_snapshot`](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/vfs/vfs_syscalls.c).

The same source describes revert as taking effect on the next mount. Its internal fallback obtains the snapshot vnode; it does not establish an ordinary-directory control route. `fsctl_internal` explicitly returns `EINVAL` for `APFSIOC_REVERT_TO_SNAPSHOT` before filesystem dispatch. [Pinned Apple source, `snapshot_revert` and `fsctl_internal`](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/vfs/vfs_syscalls.c).

The inspected `vfs_syscalls.c` has SHA-256 `b30d68fb85f34b864b5e71e3127541c2674e0fb52e59d6ee072c8b0ecbb46a4f`. This is pinned published source, not proof that either target VM runs an identical kernel or that proprietary APFS policy is exhausted by these checks. A normal signing identity, root execution, or an app wrapper alone does not establish the required entitlement authority.

## What Apple documents about signing

Restricted macOS entitlements require provisioning-profile authorization. A profile binds the permitted signer, app identity, execution scope and lifetime, and entitlement allowlist; claiming an entitlement in a code signature is a separate step. A standalone executable has nowhere to embed its authorizing profile. Apple's documented arrangement is an app-like bundle with `Contents/embedded.provisionprofile`, signed by a matching authorized identity. [TN3125](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles), [daemon packaging example](https://developer.apple.com/documentation/xcode/signing-a-daemon-with-a-restricted-entitlement).

Those documents explain mechanics; their examples concern other entitlements. They do not promise snapshot entitlement approval, support for a particular distribution method, or successful snapshot operations. Apple's public macOS capability table does not list snapshot authority. Managed capabilities generally require Apple approval and may be limited to particular distribution options; this does not establish that snapshot authority is available through that process. [Supported macOS capabilities](https://developer.apple.com/help/account/reference/supported-capabilities-macos/), [provisioning with managed capabilities](https://developer.apple.com/help/account/reference/provisioning-with-managed-capabilities).

## Native tools

The following inventory reads Apple-installed manuals as ordinary files on macOS 27.0.1, build 26A434. It establishes the documented interface on that host, not successful execution or macOS 26 parity.

| Route | Documented scope | Consequence for this capability |
| --- | --- | --- |
| `diskutil(8)`, source `/usr/share/man/man8/diskutil.8` | APFS `listSnapshots` and `deleteSnapshot`, including deletion `-wait` | The APFS verb block provides no documented create, rename or revert verb. |
| `apfs.util(8)`, source `/usr/share/man/man8/apfs.util.8` | `-R SNAPSHOT device` marks reversion on the next mount | A documented revert candidate, requiring a subsequent mount and independent completed-state verification; it does not supply creation or renaming. |
| `tmutil(8)`, source `/usr/share/man/man8/tmutil.8` | `localsnapshot` acts on all Time Machine-included APFS volumes | No arbitrary image target or requested snapshot-name operand is documented. |
| `bless(8)`, source `/usr/share/man/man8/bless.8` | `--create-snapshot` concerns an APFS system root and next boot | This does not document the required ordinary-image lifecycle. |

Manual SHA-256 values, in table order:

```text
diskutil.8  2a55a1d4465782826baacb7d6322d88f61d1cc5892969bb00d1c709e3e23cb63
apfs.util.8 354a1c22779553dafd7ef78b1406491532d3de68c7e250f1110dcd2ff80929aa
tmutil.8    1fb713e58c2c09335cf838af00057f746625dca90a08f762d294a1596ed43cd5
bless.8     ddeea4727577c30cb8e6c4cd09d09bcaca500eb4387f8f2c06ed01ce847ca7ae
```

## External prerequisites and unresolved facts

A custom helper route needs Apple confirmation that the required snapshot entitlement is available to this developer/app and distribution context, an actual authorizing profile, and access to its matching signing identity through an approved signing facility. Availability of those assets is unknown; none is inferred from an entitlement file or ordinary developer membership. Apple directs special-entitlement troubleshooting to the Apple group that authorized it. [Apple entitlement diagnostics](https://developer.apple.com/documentation/bundleresources/diagnosing-issues-with-entitlements).

Only after authority is established would bundle construction and per-OS disposable-VM qualification resolve launch acceptance, API acceptance, named snapshot history and completed reversion after remount. Existing ad-hoc signing cannot create that authority. A native-tool replacement would instead need a documented route covering the full target/name/lifecycle contract. Until either prerequisite exists, preserve the blocker and original failures; neither a speculative helper bundle nor another equivalent privilege probe establishes recovery.

## Authenticated account inspection

On 2026-11-03, the maintainer-authorised Chrome session could access Certificates, Identifiers & Profiles. The App ID registration preview exposed its Capabilities and Capability Requests lists; no entry containing APFS, VFS or snapshot was present. No identifier, capability request, certificate or provisioning profile was registered during this inspection. This establishes what was visible in that registration context, not entitlement availability for every App ID or team. Some managed capabilities are App-ID-specific. [Apple capability guidance](https://developer.apple.com/help/account/reference/provisioning-with-managed-capabilities), [Apple DTS explanation](https://developer.apple.com/forums/thread/726882).

## Inquiry submitted to Apple Developer Support

Status: submitted to Apple Developer Support under Entitlements with the maintainer's explicit approval on 2026-11-03. Apple confirmed receipt; its case reference is retained in the private handoff. Awaiting clarification of entitlement availability, signing/provisioning requirements and supported native alternatives. The request text below is the submitted draft; no successful snapshot authority or native mutation is claimed.

Subject: **Supported authorisation for APFS snapshot APIs on disposable image volumes**

We maintain the open-source go-apfs-v3 portable APFS reader/editor:
https://github.com/deploymenttheory/go-apfs-v3

We need a small macOS helper using the supported fs_snapshot_create, fs_snapshot_rename and fs_snapshot_revert APIs on disposable ordinary APFS/APFSX disk-image volumes on macOS 26 and 27. These native operations establish interoperable snapshot behaviour for our portable implementation. The intended scope is isolated image volumes on disposable CI VMs, with existing host security policy preserved.

Our retained experiments show EPERM from the unentitled helper and launch rejection when the snapshot entitlement is claimed through ad-hoc signing. In our authenticated developer account's App ID registration interface, we cannot find an APFS/VFS snapshot entry in Capabilities or Capability Requests.

Could you confirm:
1. Whether com.apple.developer.vfs.snapshot is available to third-party developers for this use, and the supported request, signing and provisioning route if so?
2. Which development or Developer ID distribution options are supported, including any registered-device restrictions relevant to disposable hosted macOS CI runners?
3. If this entitlement is unavailable, which supported Apple tool or API can perform arbitrary named snapshot creation/rename and completed revert on ordinary disk-image volumes?

Our source review and retained operation evidence are linked from:
https://github.com/deploymenttheory/go-apfs-v3/issues/74
