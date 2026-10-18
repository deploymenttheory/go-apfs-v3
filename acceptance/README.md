# Acceptance

See [docs/acceptance.md](../docs/acceptance.md) for the three tiers, the
producer × host × verifier matrix, how to add a recipe and how to diagnose a
failure.

```sh
go test ./acceptance/...                                   # portable tier
APFS_FIXTURE_DIR=/path/to/capture go test ./acceptance/... # local capture
go test -tags native ./acceptance/native                   # native tier, disposable VM only
```
