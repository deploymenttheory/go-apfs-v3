# Qualification coverage

This directory describes the acceptance obligations before changing their CI
execution. It does not replace the acceptance tests or certify a workflow run.
The existing required gates remain authoritative.

`registry.json` records each capability's purpose, independent expectation,
entrypoints, collector/verifier scripts, retained and fresh source versions,
portable hosts, native verifier versions, output formats, race coverage,
negative controls and native continuations. It also indexes the original
retained manifests and their case IDs. Both the readable manifest projections
and original compressed manifests remain unchanged.

Run from the repository root:

```sh
go run ./acceptance/qualification
go test -count=1 ./acceptance/qualification
python3 -m unittest discover -s acceptance/qualification -p 'test_*.py' -v
python3 acceptance/qualification/measure.py --check
```

These commands inspect source code and ordinary files only. They never create,
attach, mount, check or mutate a filesystem through native macOS tools.

The Go syntax audit discovers entrypoints, skip calls (including helpers and
nested subtests), and bare returns in an entrypoint's own body. Seven existing
continuation entrypoints may return or skip when their native inputs are absent.
Their registry explanations identify the required readback jobs that supply
those inputs. An inputless execution is not evidence of continuation success.

The audit rejects unregistered or duplicate entrypoints, missing explanations,
new skip/return sites, changed acceptance source files, changed workflow
contracts, invalid job references, unregistered corpus directories, absent or
changed manifest files and changed retained case/source inventories. The full
workflow bytes bind selectors, matrix axes, conditions, deadlines and gate
dependencies without introducing another YAML parser or partial CI mode.
This conservative binding requires a coverage review whenever those files
change. Runtime missing/skipped-case detection belongs to the case receipts in
[#79](https://github.com/deploymenttheory/go-apfs-v3/issues/79); a static digest
does not establish execution coverage or assertion correctness.

Git checkout keeps Go/YAML/JSON source contracts at LF on every host. The later
`acceptance/testdata/** -text` rule still preserves exact original native bytes.

When changing a capability:

1. Read its purpose and expectations. Add or amend cases in the existing tests
   and independent capture/verification family.
2. Update the registry's relevant capability, entrypoints, dimensions and job
   references. Explain any new skip or optional-input return. Preserve every
   original obligation unless an explicit capability decision changes it.
3. Review changed test/workflow bytes and update their SHA-256 values explicitly.
   There is deliberately no command that automatically approves all changes.
   `go run ./acceptance/qualification -inventory` prints discovered syntax for
   comparison; it does not modify the registry.
4. Index added retained manifests and case IDs, retaining existing original
   digests and evidence. Do not rewrite a native observation to satisfy replay.
5. Run the audit and existing required gates. Review whether a collector change
   needs fresh native inputs, rather than merely refreshing a file digest.

`apple-independent` means the original reference was produced without the Go
implementation under test. `current-go-experiment` means native work depends on
fresh Go output; the matched HFS header-growth experiment is in this category.
Its retained Go-labelled controls are historical evidence, not current writer
qualification. `native-continuation` consumes fresh Go output after Apple edits
it. `harness-control` tests evidence admission with ordinary files. These
categories govern future corpus reuse; none creates an inherited verdict.

An empty `native_majors` or `fresh_sources` list means there is no corresponding
dedicated current gate. Race descriptions state the actual restrictions, rather
than promising an unrestricted cross product. For example, construction race
checks use macOS 27 inputs; several large offline families have no dedicated
race jobs. The fragmented HFS fresh comparator also checks collapse/reuse when
fresh inputs provide those states; the separately named retained lifecycle
entrypoint is inventoried independently.

See [the harness design and work order](../../docs/qualification.md) and
[the original performance baseline](../../docs/qualification-evidence/README.md).
