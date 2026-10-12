# Retained Apple hfs-journaled copy references

Immutable Apple-created source/copy/copy-final images and complete observations
from macOS 15, 26 and 27. Captured at `a097665039bf0fe25a094f3b83bed3f5f8c4747f` by the Apple-only producer, before the Go copy implementation was committed.

Source run: https://github.com/deploymenttheory/go-apfs-v3/actions/runs/38261098803

Each manifest binds native source/expected archive bytes and decoded hashes,
producer scripts, reference manifests, commands, tools and host inputs. The
producer uses Apple cp, ln and touch for copying; no Go result supplies an oracle.
Only recorded operation clock effects are projected to the fixed construction
clock during replay. Source preservation values are compared exactly. Two native
name policies cover signed applications/frameworks, links, ordinary and compressed
forks (including an explicitly active inline-compressed independent fork), host directory imports and complete destination-attribute replacement.
Data-only overwrite of the original data/fork inode qualifies shared physical
ownership range retirement. Journaled HFS controls also bind original journal bytes.

`Empty` and `Nested` host directories are reconstructed from the retained producer
recipe, because artifact ZIPs and Git retain files, not empty directories. All
three host input files are verified against their native hashes and sizes.

Run `go test ./acceptance -run ImageCopy` for portable retained-corpus replay.
Fresh capture, every-host replay and Apple fsck/readback/signatures/continuation
remain required in the existing filesystem editing pipelines. Native tools run
only on disposable VMs; local replay needs no mounts or native filesystem tools.

Inactive recognized/malformed compression headers and replacement of an active
compressed destination additionally qualify explicit preservation/omission and
complete cleanup of decoding metadata and compression-owned fork storage.
