# Retained existing-image metadata controls (hfs-journaled)

Apple tools created and edited every input on disposable macOS 15, 26 and 27
VMs in [capture run 38206265871](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/38206265871),
at capture revision `855d6df`. No Go code generated these images or expectations.

Each manifest binds the exact source/metadata/final raw images, native commands,
OS/tool hashes, capture sources and originating reference-manifest hash. The
before/after observations retain inode IDs, names, contents, precise clocks,
flags, owners, complete raw attributes, forks, links and native checker verdicts.
The recorded implicit clock fields are the only values adjusted to the explicit
whole-second offline transaction clock during comparison.

The scenarios prove partial ownership/time/flag edits, FinderInfo differences,
empty values, 96 long attribute keys, inline/allocated storage transitions,
removal/reuse, hard-link sharing, physical symlinks and unchanged signed apps.
HFS additionally covers both name policies on fragmented sources and newly
formatted volumes. Native services can create attributes during fixture setup;
the actual initial tree record count is retained rather than assumed empty.

`TestNativeHFSJournaledImageMetadataEditing`
replays this immutable corpus. The same required pipeline refreshes controls,
builds real images on Linux/Windows/macOS and independently checks them with
Apple fsck, mounted readback, codesign and further native/Go/native operations.

The compressed corpus is approximately 13.5 MiB. Archives include
actual native post-edit filesystems so readers and future edits can use them as
references; recorded metadata alone is not substituted for an image.
