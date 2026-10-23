# Native image ownership observations

These three ZIP files are the unchanged provider artifacts from run
39941597269, on macOS 15, 26 and 27. Their provider digests, original members,
capture source commit, checkout commit, OS builds and tool digests are bound by
`provenance.json` and each original `ownership-evidence.json` inside its ZIP.
The archives include the two tiny unformatted controls; tests stream their
digests without expanding, attaching or mounting a raw image.

Each captured phase contains independent modern-class, legacy-class, root-only
media and BSD ancestry queries. The modern-class queries actually succeeded
with zero output. The two controls appear beneath `IOHDIXHDDriveOutKernel` in
the legacy and ancestry views, with exact CFData filesystem paths. Root-only
media inventories also contain actual conforming APFS subclasses. The ancestry
archive has dictionary-valued ancestor children and remains diagnostic-only.

The original adapter assertions failed. Their false booleans and error strings
remain inside the unchanged ZIPs. Complete platform collection is separate
from adapter support and from full filesystem qualification.

Replay selects original command results by phase and exact argv. It projects
the complete first, second and recorded symlink paths to distinct portable
identities only through `HostDisk.imagePathResolver`. It never substitutes a
host path inside native output, changes a boolean, invents a class-miss plist,
or derives identity from matching basenames. The separately declared relations
in provenance describe the native inventory facts to test. Post-detach records
describe observed membership; they do not silently classify a foreign device
as absent or replace the lifecycle policy.

`retainedNativePlatformCaptures` verifies the provider ZIP digests, every member
digest and every original command stream before exposing replay. The scoped
`-text` Git policy and read-only checkout-filter regression protect these bytes
on every portable test host.
