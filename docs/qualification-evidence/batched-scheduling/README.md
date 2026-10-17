# Observed batched qualification

The completed [native campaign](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/38921306255)
and [portable campaign](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/38921306018)
provide the first complete measurement of the batched scheduler. These results
do not prove the final equivalence or warm-cache targets.

| Measurement | Original baseline | Batched campaign |
| --- | ---: | ---: |
| Jobs created | 400 | 304 |
| Jobs executed | 397 | 295 |
| macOS jobs executed | 179 | 140 |
| macOS runner-minutes | 535.033 | 512.533 |
| Median macOS pre-start delay, minutes | 13.217 | 33.775 |
| Maximum macOS pre-start delay, minutes | 96.650 | 158.067 |
| Peak concurrent macOS jobs | 5 | 5 |

Job creation fell 24%; macOS runner consumption fell about 4.2%. The native rail
used 426.267 Mac minutes versus 427.167 in the baseline. Setup batching alone
has therefore not removed the dominant native work. The 39 independent Apple
capture jobs consumed 114.217 Mac minutes in this campaign. Reviewed input reuse
addresses that repeated work; current-Go HFS experiments remain separate.

The Mac pre-start delays increased while other campaigns contended for capacity.
They include dependency and scheduling delay as well as runner waiting; these
API fields cannot isolate queue time. This campaign uses freshly captured inputs
and was not controlled as one of the final three comparable warm campaigns.
Retained/fresh replay still runs separately. The targets of at most 200 jobs and
401.275 Mac minutes remain unmet by this observation.

The ledger's `revision` is the run API head
`d3ba114fb58db634f23f0ec5ef997ba0e2011d42`. Original portable receipts identify
the actual tested synthetic merge `23b5197853432a7b9c5435ce022352748f4eb88d`.
The original run, signed Git commit, associated PR and receipt are retained as
compressed byte-for-byte checkout evidence, alongside the authenticated source
binding. This provenance is not a new filesystem verdict. The historical
baseline files remain unchanged.

Reproduce every metric from the retained complete API pages:

```sh
python3 acceptance/qualification/measure.py --ledger docs/qualification-evidence/batched-scheduling/campaign.json --check
python3 acceptance/qualification/measure.py --check
```
