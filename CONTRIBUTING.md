# Contributing

Start with [architecture](docs/architecture.md) and
[implementation status](docs/implementation.md). New operations need a stated
preservation contract and an independent native acceptance case. The acceptance
harness is being rebuilt under
[#98](https://github.com/deploymenttheory/go-apfs-v3/issues/98); until its
documentation lands, that epic describes the fixture corpus and the gates.

## Checks

```sh
go test ./...
go test -race ./...
go vet ./...
golangci-lint run
```

Use gofmt. Keep source decoding independent of CLI and native capture code.
Do not silently discard metadata, reinterpret corruption as absence, or make a
missing required fixture into a passing skip.

Native observations are immutable. Retain their original source and hashes;
changing Go code is not a reason to regenerate expectations. A recipe change
produces a new fixture release and a reviewed lock-file update.

Use ordinary unit tests for bounds, algorithms, invariants, and failure handling.
Acceptance cases must explain the user operation, why it matters, the independent
expectation, and the exact fields compared. Avoid redundant workflows and
per-file coverage quotas.

Report issues at https://github.com/deploymenttheory/go-apfs-v3/issues.
Follow [the code of conduct](CODE_OF_CONDUCT.md).
