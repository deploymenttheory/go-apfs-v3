# Apple HFS journal recovery references

Captured on disposable macOS 15, 26 and 27 VMs in
[run 38285544453](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/38285544453).
The eight cases per OS cover HFS+/HFSX linear and wrapped pending rings, complete
transactions beyond the recorded end, and incomplete tentative payloads.

Apple created every filesystem and journal record. The collector paused only
the image-owned DiskImages helper at a real write boundary, copied its backing
bytes, then resumed it. Apple recovered a separate copy using its replay-only
kernel sysctl. All original interrupted, replay-only and native-readback disks
are retained as hash-bound gzip archives. Linear/wrapped captures contain actual
unapplied metadata; incomplete-tail captures prove recovery retains the last
committed state. Native checker and signature verification succeeded for every
case. No Go writer or decoder supplied native expectations.

Each readable `recovery.json` indexes the original native document in
`native-capture.json.gz`. Retention preserves that document byte-for-byte;
acceptance checks its archive digests, provenance and indexed boundaries.
Identical frozen producer scripts are shared in `scripts/`. Command transcripts
and capture diagnostics remain beside each OS version. To reproduce capture,
use the complete repository at the recorded producer revision on a disposable
VM; the shared scripts are provenance, not an isolated standalone tool bundle.

`acceptance/native/retain_hfs_recovery.py` performs file-only retention from
downloaded artifacts into a new directory. It neither mounts disks nor invokes
native tools. Fresh compatibility runs collect independent evidence and never
automatically replace this baseline. See [the recovery contract](../../../docs/hfs-journal-recovery.md).
