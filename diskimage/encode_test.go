package diskimage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

func TestEncodeRejectsTruncationAndTrailingInput(t *testing.T) {
	for _, n := range []int{511, 513} {
		var out bytes.Buffer
		if err := Encode(context.Background(), &out, bytes.NewReader(make([]byte, n)), 512, "UDZO"); err == nil {
			t.Fatal("accepted source size mismatch", n)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	if err := Encode(ctx, &out, bytes.NewReader(make([]byte, 512)), 512, "UDRO"); !errors.Is(err, context.Canceled) || out.Len() != 0 {
		t.Fatal(err)
	}
}
func TestEncodeNativeChunkBoundAndChecksums(t *testing.T) {
	raw := bytes.Repeat([]byte("compressible\x00"), 700000)
	raw = append(raw, make([]byte, 512-len(raw)%512)...)
	raw = append(raw, make([]byte, 8<<20)...)
	var encoded bytes.Buffer
	if err := Encode(context.Background(), &encoded, bytes.NewReader(raw), int64(len(raw)), "UDZO"); err != nil {
		t.Fatal(err)
	}
	source := bytes.NewReader(encoded.Bytes())
	u, err := openUDIF(source, encoded.Bytes()[encoded.Len()-512:])
	if err != nil {
		t.Fatal(err)
	}
	zeros := 0
	for _, c := range u.chunks {
		if c.kind == 2 {
			t.Fatal("native verify excludes ignored sectors from CRCs; use zero-fill records")
		}
		if c.kind == 0 {
			zeros++
		}
		if c.size > 4<<20 {
			t.Fatal("Apple rejects chunks over 4 MiB")
		}
	}
	if zeros == 0 {
		t.Fatal("missing full zero chunk control")
	}
	got := make([]byte, len(raw))
	if _, err = u.ReadAt(got, 0); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatal("encoded disk bytes changed")
	}
}
