package diskimage

import (
	"bytes"
	"testing"
)

// Small metadata reads in UDRO use a bounded cache, just like UDZO. Native
// acceptance supplies filesystem semantics; this control measures backing I/O.
func TestUDIFRawMetadataCacheAndLargeRunStreaming(t *testing.T) {
	for _, size := range []int{4096, maxCachedRawChunk + 512} {
		payload := bytes.Repeat([]byte("raw metadata bytes\x00\xff"), size/20+1)[:size]
		source := &countingChunkSource{Reader: bytes.NewReader(payload)}
		u := &udif{source: source, size: int64(size), chunks: []chunk{{kind: 1, size: int64(size), storedSize: int64(size)}}}
		for repeat := 0; repeat < 2; repeat++ {
			data := make([]byte, 23)
			if _, err := u.ReadAt(data, 7); err != nil || !bytes.Equal(data, payload[7:30]) {
				t.Fatal("raw cache changed bytes", size, err)
			}
		}
		if size > maxCachedRawChunk {
			if source.reads != 2 || len(u.cache) != 0 {
				t.Fatal("large raw run was buffered", source.reads, len(u.cache))
			}
		} else {
			if source.reads != 1 || len(u.cache) != 1 || u.cacheSize != int64(size) {
				t.Fatal("small raw metadata reread backing store", source.reads, len(u.cache))
			}
			retained := u.cache[0].data
			u.clearCache()
			if !bytes.Equal(retained, make([]byte, size)) {
				t.Fatal("eviction retained plaintext")
			}
		}
	}
}

func TestUDIFRawReadAcrossCacheRegions(t *testing.T) {
	payload := make([]byte, rawCacheRegion*2)
	for i := range payload {
		payload[i] = byte(i / 7)
	}
	source := &countingChunkSource{Reader: bytes.NewReader(payload)}
	u := &udif{source: source, size: int64(len(payload)), chunks: []chunk{{kind: 1, size: int64(len(payload)), storedSize: int64(len(payload))}}}
	for repeat := 0; repeat < 2; repeat++ {
		data := make([]byte, 23)
		if _, err := u.ReadAt(data, rawCacheRegion-7); err != nil || !bytes.Equal(data, payload[rawCacheRegion-7:rawCacheRegion+16]) {
			t.Fatal("region boundary bytes", err)
		}
	}
	if source.reads != 2 || u.cacheSize != int64(len(payload)) {
		t.Fatal("boundary regions not reused", source.reads, u.cacheSize)
	}
}
