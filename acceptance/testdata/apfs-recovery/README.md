# Apple APFS checkpoint recovery references

Retained from [run 38298298833](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/38298298833)
at capture revision `2ab49b2` on disposable macOS 15, 26 and 27 VMs.

Each version has APFS and case-sensitive APFS controls:

| Case | Purpose | Independent expectation |
| --- | --- | --- |
| `data` | New stored checkpoint data exists before a newer checkpoint superblock | Apple selects the last complete checkpoint |
| `mapping` | New mapping blocks exist without their published superblock | Apple selects the last complete checkpoint |
| `committed` | A new checkpoint is published while block zero remains stale | Apple selects the newer committed state |
| `wrapped` | Checkpoint-data allocation wraps its actual native ring | Apple selects a complete state across wrap |
| `bad-mapping` | Deliberately flip one newest mapping checksum byte | A separate Apple-checked control disables that descriptor and proves the earlier state |
| `bad-object` | Deliberately flip one newest mapped-object checksum byte | The same independent earlier-state control proves safe explicit recovery |

The first four cases retain genuine paused image-helper write windows. The last
two are derived corruption controls, with exact parent hashes and modified byte
offsets/values. They are never presented as Apple-generated interruptions or
native repair output. Raw disks are 128 MiB; archives are bounded and hashed.

Each readable `recovery.json` index binds a verbatim compressed native document,
the source hashes and selected transactions. Original observations, OS builds,
tool/script hashes, checker/codesign commands and acquisition diagnostics remain
retained. Identical capture scripts are shared across versions.

`acceptance/native/retain_apfs_recovery.py` performs file-only retention. Tests
require all three versions and compare the original native evidence. Fresh CI
captures are separate artifacts and never replace this baseline automatically.

```sh
go test -count=1 -run TestNativeAPFSCheckpointRecovery ./acceptance
```

Native operations must remain on disposable VMs. Local retained replay only
reads/writes ordinary files. See the [contract and limits](../../../docs/apfs-checkpoint-recovery.md).
