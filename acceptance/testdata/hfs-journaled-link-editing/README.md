# Native hfs-journaled link editing references

Captured independently by Apple tools at commit `56aa13e` in [run 38225853680](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/38225853680). Go was not involved in sources or expected states.

Each macOS 15/26/27 directory contains two name-policy cases, with source and three lifetime images per case: first-link/alias/symlink growth, writes through aliases and removal, then final-link reclamation/reuse. All eight compressed raw disks per version have compressed and decoded hashes. Manifests bind exact copied capture recipes, commands, tool/OS versions and the original native source manifest.

A signed universal framework has only its symlinks removed before capture. Their recreation must restore the exact link targets and a valid native signature. The untouched signed application is independently verified throughout. Observations retain complete namespaces, original/created IDs, link counts, nanosecond clock observations, metadata and raw fork/attribute hashes.

These files are immutable regression evidence. Fresh required CI controls additionally exercise explicit destination `-h` and force replacement of a different alias of the same inode. Sources retain a clean initialized internal HFS journal; mutation uses completed-output transactions.
