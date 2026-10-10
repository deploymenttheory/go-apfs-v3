# Native APFS test incident — 2026-10-10

Multi-volume construction is not qualified for release. Native testing of the
experimental builder triggered APFS kernel panics on the development Mac. The
reported panic is `System ObjId overflow` at `jobj.c:1146`, in `fseventsd`, on
macOS 27.0.1 build 26A434. The panic backtrace includes Apple's APFS driver.

All native attachment and write tests on that host have stopped. The process
check after reboot found no surviving native image test processes. Generated
System/Data images from the two retained runs were renamed with
`.DO-NOT-MOUNT` suffixes; their bytes and the command diagnostics remain under
the ignored `artifacts/` directory. Do not attach these images.

## Evidence and candidate correction

Apple's checker accepted the generated container before the crash. Read-only
mounted metadata and application signature checks also completed for the grouped
UDRO output. The diagnostics do not record a completed subsequent writable
attachment. These checks did not establish that the image was safe for continued
native use. A disposable image or shadow does not isolate the host kernel.

File-only inspection of the independently captured Apple image found System
user-object IDs starting at `0x0fffffff00000010`, and its selected superblock's
`apfs_next_obj_id` at `0x0fffffff0000002a`. The generated image instead used
`0x0800000000000000` as its base and stored `0x0800000000000021` as the next ID.

The builder had carried over a v2 assumption about `UNIFIED_ID_SPACE_MARK`.
Apple's [APFS reference, File-System Objects](https://developer.apple.com/support/apple-file-system/Apple-File-System-Reference.pdf)
defines `SYSTEM_OBJ_ID_MARK` as `0x0fffffff00000000`. This agrees with the native
capture. The candidate correction uses that value for grouped System user
objects and their next-object allocator state. Reserved root/private IDs retain
the observed native values. An acceptance assertion now compares the generated
System inode namespace against the captured native objects independently of the
normal inode-identity bijection.

This is a concrete format mismatch and a strong explanation for the panic;
the correction has not been verified by mounting it. Native qualification remains
outstanding and must not be replaced with a successful Go round trip or fsck.

## Resuming native qualification

The image-building capture and verifier refuse native operations on a working host by default.
`APFS_NATIVE_DISPOSABLE_VM=1` is an explicit operator assertion that execution is
inside an isolated, disposable macOS VM. It must not be set on a working Mac or
assumed from a runner label. The helper also admits GitHub-hosted Actions VMs
using their runtime environment metadata. CI asserts that environment before
its first native operation.

The previous successful CI job records identify all three macOS runners as
GitHub-hosted. GitHub [documents these runner labels as fresh VMs](https://docs.github.com/en/actions/reference/runners/github-hosted-runners),
including the xcode-27 preview label. These VMs are the qualification environment.
Preserve panic diagnostics if a guest crashes.
Check the corrected group with Apple's checker, mounted reads, native allocation
and remounting in those guests, together with Linux/Windows/macOS replay. Keep
the native tests blocked on the development host even if the candidate succeeds.
