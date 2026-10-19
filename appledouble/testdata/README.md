# AppleDouble sample

`apfs-example.txt.appledouble` is a native AppleDouble file produced by Apple's
`copyfile(3)` with `COPYFILE_PACK` (via `/usr/lib/libSystem.B.dylib`), never by
this project's codec. Its bytes are retained exactly as captured.

| Field | Value |
| --- | --- |
| Captured on | macOS 27.0.1, build 26A434, arm64 |
| Collector | `acceptance/native/preservation.py` (SHA-256 `1e3c6c9643a57488ee39a8d764be08883464c32a748a138d24bd87ce6f976d75`) of the retired acceptance harness |
| Original path | `acceptance/testdata/preservation/macos-27/apfs-example.txt.appledouble` at commit `2bd3e7a` |
| Packed source | `Fixture/example.txt` of the `preservation/apfs` case: a text file carrying `com.apple.provenance`, several `org.go-apfs.*` extended attributes (including an empty and a 32 KiB value) and a resource fork |
| Size | 65878 bytes |
| SHA-256 | `b143d0441cf06a4e320acc97b8dccd5e0af1eb4a69ce20550fe7e72617220057` |

The unit tests in this package use it only as structurally valid input for
damage and cancellation controls. Independent native round-trip verdicts belong
to the acceptance tier.
