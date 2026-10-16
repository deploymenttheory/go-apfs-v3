# HFS+ catalog node-map growth profile

This local Go-only profile retains the real 120,000-file HFS+ case, both UDRO
and UDZO encodings, and the complete existing assertions. It passed in 440.948
seconds under Go 1.27.1 on Darwin/arm64 with `GOMEMLIMIT=1GiB`. No Apple disk
creation, attachment, filesystem checker, snapshot or mutation tool was used.

This is a diagnostic profile, not a CI campaign or a before/after benchmark.
Profiling and the explicit memory budget affect timing. The
[metadata](profile.json) records the command, original production digest and
profile byte counts/hashes. The Git revision identifies the checkout; uncommitted
changes concerned qualification infrastructure, with filesystem implementation
and the profiled acceptance source unchanged.

The CPU profile contains 400.71 sampled CPU seconds:

| Path | Cumulative sampled CPU | Share |
| --- | ---: | ---: |
| HFS mutation through `Editor.Apply` | 314.02 s | 78.37% |
| File `ReadAt` calls | 226.15 s | 56.44% |
| Staged writes | 85.90 s | 21.44% |
| Full edited-state comparison | 6.79 s | 1.69% |
| `openNativeDiskArchive` | 0.40 s | 0.10% |

Rows overlap through their call stacks. Most mutation cost reaches file-system
read/write syscalls. The allocation profile records approximately 385 GiB of
cumulative allocation, principally repeated HFS node/name decoding and mutation;
this is allocation over the whole run, not peak resident memory.

Decoded-source reuse cannot materially reduce this particular case. Retain its
data and deadline; prioritize removing repeated capture, replay, setup and
transport. Any optimization of the HFS mutation implementation needs its own
correctness evidence and is separate from the harness refactor.

The original compressed profile bytes are retained in
[cpu.pprof](cpu.pprof) and [allocations.pprof](allocations.pprof). Inspect them
with Go's pprof command; on this installation it is available from the Go source
tree:

```sh
go run cmd/pprof -top cpu.pprof
go run cmd/pprof -top -cum cpu.pprof
go run cmd/pprof -top -alloc_space allocations.pprof
```

The separate decoded-input [microbenchmark metadata](decoded-input-benchmark.json)
and [raw output](decoded-input-benchmark.txt) measure the actual original 512 MiB
source disk, including original/decoded hash checks and post-use verification.
Three iterations per mode measured 527.9 ms for a new decode and 450.9 ms for
verified warm reuse, about 14.6% lower input-admission time on this host. Warm
reuse avoids creating another decoded disk. The Go heap allocation per operation
remained below 1 MiB, under an explicit `GOMEMLIMIT=512MiB`.

This small local microbenchmark measures neither complete filesystem mutation
nor runner time. Its source-file hashes identify the exact uncommitted cache
implementation used; its [executed sources](decoded-input-sources.tar.gz) retain
every original source byte, including the controls before a later additional
source-mutation test. The original CPU/allocation profiles above remain unchanged;
their finding that mutation dominates the full boundary case still applies.
