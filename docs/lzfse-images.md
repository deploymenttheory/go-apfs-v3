# LZFSE disk images

The disk-image reader accepts LZFSE UDIF chunks (`0x80000007`), including
borrowed `io.SectionReader` views of stored ZIP members. Stored and decoded
chunks retain the existing 64 MiB limits. Decoding requires one complete stream,
an end marker at the end of the advertised stored range, and exactly the
advertised logical byte count. Failed decoding exposes and caches no partial
output. The existing filesystem LZFSE prefix decoder keeps its prior behavior.

`diskimage/testdata/lzfse-compressed.lzfse` is synthetic, produced by the pinned
Apple C encoder. Its JSON companion records the generation formula, revision
and original digests. `acceptance/recipes/lzfse-images.json` captures independent
Apple ULFO images for APFS, case-sensitive APFS, HFS+ and HFSX. The required
reader and repack families compare their decoded sectors and filesystem contents
with native observations.

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
and source hashes identify the exact patched implementation, now committed in
`99a52ea`. Original absolute paths describe the capture environment; reproduction
uses isolated checkouts and one shared bounded range cache as documented in the
archive.
