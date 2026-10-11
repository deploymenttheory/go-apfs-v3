# Retained Apple HFS catalog editing references

These immutable source/catalog/catalog-final disks and mounted observations were
captured without Go on disposable macOS 15, 26 and 27 VMs. HFS+ and HFSX are both
required. The profile is current empty internal journal.

Capture: [run 38159768827](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/38159768827),
branch commit `db720f1`. Each folder retains exact scripts, tool hashes, OS build,
command diagnostics, compressed/raw hashes and independent native checker verdicts.
The original input came from the existing fragmented HFS editing scenario.

The two states prove catalog creation/growth, cross-directory and case-only moves,
file replacement by rename, Unicode/colon names, unchanged independent forks and
attributes, first/final hard-link removal, compressed-file removal and allocation
reuse. Untouched application signatures are checked natively.

Portable replay opens ordinary files only. Original CNIDs must remain exact;
new CNIDs may differ from Apple's allocation history, with all identity equality
relationships checked independently. Creation uses an explicit clock and parent
UID/GID. Native ctime and affected parent mtime are compared under that documented
offline clock policy; contents, names, modes, ownership, birth/access times, flags,
links and raw attributes remain independent native expected values.

Fresh CI captures and native verification of actual portable output remain
required. Successful replay of this retained corpus alone does not qualify writes.
Do not regenerate expected files to make a Go implementation pass.
