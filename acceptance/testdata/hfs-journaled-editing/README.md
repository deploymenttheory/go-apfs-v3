# Apple-created journaled HFS editing references

These are unchanged native captures from run
[38150364332](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/38150364332)
at `3431004`, recorded independently on macOS 15, 26 and 27. Each version has
HFS+ and HFSX source/peak/final raw disks, native observations, Apple checker
verdicts, exact producer scripts, command transcripts and hashes. No Go code
participated in capture or supplied expected values.

Native volumes contain fragmented data/resource forks, compressed files,
hard-link aliases, independent forks/attributes and a signed universal app.
Manifests include actual journal size, byte order, cursors, sequence, complete
journal/JIB hashes and raw catalog backing CNIDs. Ordinary native pathname
lookup hides those backing files; the retained observer reads their catalog
records directly. Clean native primary headers have the unmounted bit set while
alternate headers retain it clear. The other journal state and geometry agree.

The portable test replays all six source volumes, checks contents and original
identities against native states, requires untouched journal bytes, and builds
both UDRO and UDZO outputs reproducibly. Run without native tools:

```sh
go test -count=1 -run '^TestNativeHFSJournaledImageEditing$' ./acceptance
```

The required existing-HFS-editing CI family captures fresh references separately,
replays them on Linux/Windows/macOS, and returns every distinct output to all
three disposable native VMs for checker/readback/signature and subsequent native
journal writes, followed by Go re-editing and another Apple verdict. It does not
replace these baseline observations automatically. Never mount generated
images or run native qualification on a working host.
