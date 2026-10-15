# Original qualification performance baseline

The baseline is the complete successful PR73 campaign at production revision
`67a1977a23f0966c94241579fb22d49492124592`:

- [macOS filesystem compatibility, run 38715716597](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/38715716597)
- [CI, run 38715716756](https://github.com/deploymenttheory/go-apfs-v3/actions/runs/38715716756)

`native-jobs.json.gz` and `portable-jobs.json.gz` retain the original paginated
GitHub jobs API responses without changing their decoded bytes. `baseline.json`
records the original and stored SHA-256 values and reproduced measurements.
These are performance observations, not new filesystem qualification receipts.
The coverage registry describes the current main checkout and includes any
subsequent changes; the baseline remains tied to its own recorded revision.

| Measurement | Native workflow | Portable workflow | Combined |
| --- | ---: | ---: | ---: |
| Jobs created | 230 | 170 | 400 |
| Jobs executed | 227 | 170 | 397 |
| macOS jobs executed | 131 | 48 | 179 |
| macOS runner-minutes | 427.167 | 107.867 | 535.033 |
| Median macOS execution, minutes | 1.767 | 1.400 | 1.667 |
| Median macOS pre-start delay, minutes | 9.850 | 51.650 | 13.217 |
| Maximum macOS pre-start delay, minutes | 54.817 | 96.650 | 96.650 |
| Peak concurrent macOS jobs | 5 | 5 | 5 |

The three skipped jobs are conditional archive/reference paths and the nested
HFS journal-recovery call already invoked by the top-level workflow. They are
retained explicitly in the API evidence and are not counted as executed work.

Reproduce and verify every recorded metric from the repository root:

```sh
python3 acceptance/qualification/measure.py --check
```

The measurement rejects missing API pages, duplicate jobs, wrong run/revision,
unsuccessful or incomplete jobs and changed stored/original digests. Runner time
is the sum of executed job intervals; it is distinct from workflow wall time.
Concurrency uses half-open intervals and excludes skipped jobs.

Pre-start delay is `started_at - created_at`. These API fields cannot distinguish
waiting for a runner from dependency or scheduling delay; this is not a precise
runner-queue measurement. The competing PR/main/release campaigns observed during
the investigation are additional contention, not included in this successful
campaign's runner consumption.

Step timings separately report setup/cleanup, artifact transfer, explicit
archive/unpack steps and explicitly isolated construction builds. Compilation
inside `go test`, native-script subprocesses and combined build/interruption
steps cannot be separated from checks using these records. No compilation or
transfer saving is inferred for that unattributed time. Step durations can leave
gaps and therefore need not sum to complete job intervals.

The redesign targets at most 200 job starts and 401.275 macOS runner-minutes,
without losing obligations or buying capacity. Final evaluation uses the median
of three comparable warm-cache campaigns, with pre-start delay and environment
differences reported separately. This baseline alone does not prove a speedup.
