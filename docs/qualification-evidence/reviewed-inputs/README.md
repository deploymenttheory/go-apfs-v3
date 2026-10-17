# Observed reviewed-input infrastructure campaign

These original job API pages record a complete successful campaign before an
approved Apple input pin was available. CI used retained inputs and native
qualification captured fresh sources. They establish an observed cost, not a
controlled common-input comparison or permission to retire replay.

| Measurement | Frozen baseline | Observed campaign |
| --- | ---: | ---: |
| Jobs created | 400 | 307 |
| Jobs executed | 397 | 298 |
| macOS jobs executed | 179 | 140 |
| macOS runner minutes | 535.033 | 473.617 |
| Peak concurrent macOS jobs | 5 | 5 |

Created jobs fell by 23.25%; macOS runner minutes fell by about 11.5%. The
targets of at most 200 created jobs and 401.275 macOS runner minutes remain
unproved. Runner image, cache and queue differences prevent treating this pair
as one of the required comparable warm measurements. The current branch head's
later campaign is not included.

Reproduce the figures without network access:

```sh
python3 acceptance/qualification/measure.py \
  --ledger docs/qualification-evidence/reviewed-inputs/campaign.json --check
```

The ledger binds original and compressed API bytes separately. Original run
metadata identifies the PR head `8cb4463fb7cadfc37912f337749f82505d2039d2`.
The original receipt identifies the actual tested merge
`d0c5433674b869428567231f398304739f72ac14`; its saved commit API response binds
tree `b9c431878b1043567a6112a9a5924ee295405ad9` and the PR-head parent.
The nested PR metadata in a run response can follow the PR's later head and
must not be substituted for these original execution identities. No original
response or receipt has been rewritten.

The completed original workflows are
[CI](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/39019910136) and
[native qualification](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/39019910257).
Their complete evidence was separately admitted against the tested source.
This performance ledger retains job timing and checkout provenance; it does not
replace full campaign admission or the required paired coverage/output proof.
