package copyfile

import (
	"encoding/binary"
	"errors"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"testing"
	"unicode/utf16"
)

func streamRecord(name string) []byte {
	units := utf16.Encode([]rune(name))
	b := make([]byte, 24+2*len(units))
	binary.LittleEndian.PutUint32(b[4:], uint32(2*len(units)))
	for i, u := range units {
		binary.LittleEndian.PutUint16(b[24+2*i:], u)
	}
	return b
}
func TestWindowsStreamInventoryDistinguishesNoNamedStreamsFromEmptyForeignStreams(t *testing.T) {
	unnamed := streamRecord("::$DATA")
	if got, err := namedHostStreams(unnamed); err != nil || got {
		t.Fatal("default data stream invented a metadata stream", got, err)
	}
	named := streamRecord(":empty:$DATA")
	if got, err := namedHostStreams(named); err != nil || !got {
		t.Fatal("empty named stream disappeared", got, err)
	}
	first := make([]byte, 40)
	copy(first, unnamed)
	binary.LittleEndian.PutUint32(first, 40)
	if got, err := namedHostStreams(append(first, named...)); err != nil || !got {
		t.Fatal("linked stream inventory lost a stream", got, err)
	}
	for _, bad := range [][]byte{nil, unnamed[:23], unnamed[:len(unnamed)-1], append(append([]byte(nil), first...), unnamed...)} {
		// The last input repeats the unnamed stream, an ambiguous inventory.
		if _, err := namedHostStreams(bad); !errors.Is(err, filesystem.ErrCorrupt) {
			t.Fatal("malformed stream inventory admitted", err)
		}
	}
}
