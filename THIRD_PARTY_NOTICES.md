# Third-party notices

Original go-apfs-v3 code is available under the root MIT license.

`hfsplus/finderinfo.go` adapts portions of Apple's `core/hfs_xattr.c`, copyright
2000–2023 Apple Inc., under the Apple Public Source License 2.0. Its original
notices are retained. The Go adaptation replaces kernel structures with bounded
byte slices and exposes the native FinderInfo attribute view.

The source of this adaptation is supplied in this repository at
[hfsplus/finderinfo.go](hfsplus/finderinfo.go), under
[APSL-2.0](LICENSES/APSL-2.0.txt). It is available from
https://github.com/deploymenttheory/go-apfs-v3. The exact upstream revision and
source hashes are recorded in [the source inventory](docs/sources.json).

APFS and HFS+ format readers are original Go interpretations of the referenced
format specifications except for the explicitly identified adaptation.
