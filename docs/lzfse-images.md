# LZFSE disk images

The disk-image reader accepts LZFSE UDIF chunks (`0x80000007`), including
borrowed `io.SectionReader` views of stored ZIP members. Stored and decoded
chunks retain the existing 64 MiB limits. Decoding requires one complete stream,
an end marker at the end of the advertised stored range, and exactly the
advertised logical byte count. Failed decoding exposes and caches no partial
output. The existing filesystem LZFSE prefix decoder keeps its prior behavior.

`diskimage/testdata/lzfse-compressed.lzfse` is synthetic, produced by the pinned
Apple C encoder. Its JSON companion records the generation formula, revision
and original digests. The tests also build synthetic UDIF block lists for valid,
truncated, corrupt, overlong and oversized chunks. Native ULFO filesystem and
repack qualification remains separate from this reader change.

## Bounded public-image proof

The reproduction in [issue #146](https://github.com/deploymenttheory/go-apfs-v3/issues/146)
uses the stored member `038-03664-370.dmg` of Apple's iPhone12,1 iOS 14.0 restore
archive. The baseline reproduces the unsupported-codec refusal. The patched
reader opens the same member as UDIF/GPT and decodes its first 4,096 logical
bytes. Both runs together fetched 648,112 bytes in five HTTP range requests;
the patched run needed no additional requests. This proves bounded opening and
prefix decoding; complete filesystem traversal and full image hashes are
outside that probe's scope.

The original harness, request receipts, result metadata, source hashes and
production diff are retained unchanged inside
[`lzfse-public-probe.tar.gz`](../diskimage/testdata/lzfse-public-probe.tar.gz),
SHA-256 `374e464ac8dac508cc241ef9bdf160ad8d318ea92179cd5a5124c8fb31ddb1a1`.
The archive contains no firmware bytes. Its manifest binds each original file;
only the enclosing tar/gzip metadata is normalized. The recorded worktree diff
and source hashes identify the exact patched implementation included here.
Original absolute paths describe the capture environment; reproduction
uses isolated checkouts and one shared bounded range cache as documented in the
archive.

## Complete public iOS 15 archive opening

On 2026-10-22, a separate read-only probe used the exact
[iPhone12,1 iOS 15.0 build 19A346 Apple restore archive](https://updates.cdn-apple.com/2021FallFCS/fullrestores/002-02965/E21A0F85-CE8B-410B-96E1-E367D5619112/iPhone11,8,iPhone12,1_15.0_19A346_Restore.ipsw).
Its 6,959,737,743 bytes independently hashed to SHA-256
`13d574566eec7be3b9e23ec93c2374cabf7f150be63aafd7f8479d7d162480e0`,
the same digest recorded by the [go-ios-vm qualification](https://github.com/deploymenttheory/go-ios-vm/issues/11).
The [read-only probe source](../diskimage/testdata/udif-member-probe.go) locates
stored ZIP member `018-80101-001.dmg`, borrows exactly its 6,544,616,394 bytes
through `io.SectionReader`, and calls `diskimage.New` followed by `apfs.Open` on
the selected partition. It writes only JSON metadata and hashes. Run it from
the repository root with a local verified IPSW path:

```sh
go run ./diskimage/testdata/udif-member-probe.go "$IPSW" 018-80101-001.dmg
```

The [captured result](../diskimage/testdata/public-udif-local-open.json) has
SHA-256 `0afe89abd964cb2cf639d44c96baef0c4a258f8b3dd903861f4c325b4ba6f613`.
`diskimage.New` returned UDIF/GPT with one partition, a 9,251,497,472-byte
logical disk, and a 4,096-byte decoded prefix whose SHA-256 is
`b88c41d37754961da1bb10b273b7d13f78107a106c2ab2d369cca2bc45b7f281`.
`apfs.Open` reached a 4,096-byte APFS block size and one volume. This verifies
opening and bounded structural reads from that complete archive; it does not
hash every decoded sector, traverse all filesystem content, or demonstrate a
bootable VM. The earlier iOS 14 proof above remains a bounded remote probe
because its complete managed cache object was pruned before this trial.
