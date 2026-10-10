# Third-party notices

Original go-apfs-v3 code is available under the root MIT license.

`internal/finderinfo/hfs.go` adapts portions of Apple's `core/hfs_xattr.c`, copyright
2000–2023 Apple Inc., under the Apple Public Source License 2.0. Its original
notices are retained. The Go adaptation replaces kernel structures with bounded
byte slices and exposes the native FinderInfo attribute view. Both the HFS+ reader
and workspace attribute editor use this shared adaptation.

The source of this adaptation is supplied in this repository at
[internal/finderinfo/hfs.go](internal/finderinfo/hfs.go), under
[APSL-2.0](LICENSES/APSL-2.0.txt). It is available from
https://github.com/deploymenttheory/go-apfs-v3. The exact upstream revision and
source hashes are recorded in [the source inventory](docs/sources.json).

`hfsplus/build.go` and `hfsplus/build_tree.go` adapt Apple’s `newfs_hfs/makehfs.c`,
copyright 1999–2023 Apple Inc., under [APSL-2.0](LICENSES/APSL-2.0.txt). The Go
source is supplied here with the original notice, modification date and pinned
source inventory. They build new volumes from logical readers without kernel or
journal code.

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

`internal/codec/lzfse` adapts Apple's LZFSE/LZVN decoder and FSE tables, copyright
2015–2016 Apple Inc., under [BSD-3-Clause](internal/codec/lzfse/LICENSE).
`internal/codec/lzbitmap` adapts Corellium's libzbitmap decoder, copyright 2022
Corellium LLC, under [MIT](internal/codec/lzbitmap/LICENSE). The initial Go
translations came from v2 production code, copyright 2026 Deployment Theory;
v3 retains only decoders with bounded, caller-owned destinations. The LZ4
decoder adapts v2 original MIT code and is not represented as an Apple C port.
Revisions, source hashes, adaptations and independent native evidence are in the
source inventory. No native compression framework or C code is linked at runtime.

APFS encryption parsing and storage cryptography are original Go code using Go's
standard AES, HMAC and SHA-256. Apple specifications, pinned format documentation
and existing implementations were studied as recorded in the source inventory;
no apfs-fuse GPL code or CommonCrypto implementation was copied or translated.
The native acceptance collector calls installed Apple CommonCrypto APIs to
produce independent reference vectors; production Go has no native dependency.

Encrypted DMG reading is an original Go interpretation using standard AES,
3DES, HMAC and SHA-1 for Apple's existing format. Format facts were studied from
Willem Hengeveld's MIT-licensed `encrypteddmg` documentation and the MIT-licensed
`vfdecrypt.c` by Ralf-Philipp Weinmann, Jacob Appelbaum and Christian Fromme.
No Python or C implementation was copied or translated. Apple CSSM identifiers
and native image observations supply additional evidence. Exact revisions and
file hashes are recorded in the source inventory.

`appledouble/appledouble.go` adapts the AppleDouble/ATTR layouts and packing
sequence from Apple's `copyfile.c`, copyright 2004–2024 Apple Inc., under
[APSL-2.0](LICENSES/APSL-2.0.txt). The Go adaptation retains source notices and
replaces descriptors and whole-value allocations with checked borrowed sections
and bounded writes. It does not port native ACL/quarantine or process policy.
Its source is supplied at [appledouble/appledouble.go](appledouble/appledouble.go)
and https://github.com/deploymenttheory/go-apfs-v3. Exact upstream revision,
source hashes, changes and independent native controls are in the source inventory.

`internal/mode/mode.go` translates Apple's BSD `setmode`/`getmode` implementation,
copyright 1989, 1993, 1994 The Regents of the University of California, contributed
by Dave Borman at Cray Research. Its [BSD notice](LICENSES/BSD-setmode.txt) is retained.
The Go parser uses explicit umask input and bounded instruction slices. Pinned
source hashes and native libc qualification are recorded in the source inventory.

`golang.org/x/sys` v0.49.0 provides operating-system locks and metadata calls under
its [BSD license](LICENSES/BSD-x-sys.txt).
It introduces no cgo dependency.
