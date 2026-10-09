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

`hfsplus/links.go` adapts Apple's `cat_lookup`/`cat_resolvelink` indirection under
APSL-2.0, preserving regular-file hard-link identity and metadata while using
bounded Go tree readers instead of kernel structures.

`internal/names/hfs_tables.go` derives comparison/decomposition tables from
Apple's `UCStringCompareData.h` and XNU `vfs_utfconvdata.h`, copyright 1997–2005
Apple Inc. `internal/names/apfs_tables.go` materializes the pinned Apple XNU
Unicode 16 scalar normalizer and data, copyright 2016–2025 Apple Inc. The tables
retain their APSL-2.0 notices. The scalar normalizer also acknowledges Unicode,
Inc. (2016 and later) and IBM and others (1999–2015); see
[Unicode license](LICENSES/Unicode-3.0.txt),
[Unicode 2016 permission text](LICENSES/Unicode-DFS-2016.txt), and
[ICU permission text](LICENSES/ICU.txt).

These adaptations and the reproducible generator are supplied as source in this
repository. `python3 internal/names/generate.py SOURCE_DIRECTORY` requires the
four exact, hash-checked upstream files listed in its header and a C compiler.
It uses no host Unicode library. Ordinary Go builds need neither C nor cgo.
The generator, revisions, file hashes and native qualification evidence are
recorded in [the source inventory](docs/sources.json).

Other APFS and HFS+ format reader code is an original Go interpretation of the
referenced format specifications except where explicitly identified above.
