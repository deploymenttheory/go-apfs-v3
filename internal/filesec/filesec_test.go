package filesec

import (
	"bytes"
	"errors"
	"math"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

func TestFilesecRejectsTruncationAndCountOverflow(t *testing.T) {
	value := make([]byte, MaxSize)
	be.PutUint32(value, Magic)
	be.PutUint32(value[36:], 128)
	for n := 0; n < len(value); n++ {
		if err := Validate(value[:n]); !errors.Is(err, filesystem.ErrCorrupt) {
			t.Fatal("truncated filesec admitted", n, err)
		}
	}
	if err := Validate(value); err != nil {
		t.Fatal(err)
	}
	be.PutUint32(value[36:], 129)
	if err := Validate(value); !errors.Is(err, filesystem.ErrCorrupt) {
		t.Fatal(err)
	}
	be.PutUint32(value[36:], math.MaxUint32)
	if err := Validate(value[:44]); err != nil {
		t.Fatal(err)
	}
	if err := Validate(value); !errors.Is(err, filesystem.ErrCorrupt) {
		t.Fatal("NOACL with trailing entries", err)
	}
}

func TestInheritedFilesecRetainsOpaqueRightsAndSource(t *testing.T) {
	parent := make([]byte, 44+24)
	be.PutUint32(parent, Magic)
	be.PutUint32(parent[36:], 1)
	be.PutUint32(parent[40:], 0x1234)
	for n := 4; n < 36; n++ {
		parent[n] = byte(n)
	}
	copy(parent[44:], bytes.Repeat([]byte{0xab}, 16))
	be.PutUint32(parent[60:], 1|File|Directory|Only|Limit)
	be.PutUint32(parent[64:], 0xdeadbeef)
	saved := bytes.Clone(parent)
	result, err := Inherit(parent, true)
	if err != nil || !bytes.Equal(parent, saved) {
		t.Fatal("inheritance modified source", err)
	}
	if !bytes.Equal(result[4:36], make([]byte, 32)) || be.Uint32(result[40:]) != 0 ||
		be.Uint32(result[60:]) != 1|Inherited || be.Uint32(result[64:]) != 0xdeadbeef ||
		!bytes.Equal(result[44:60], saved[44:60]) {
		t.Fatal("limited inheritance or opaque identity/rights changed", result)
	}
	result[44] = 0
	if !bytes.Equal(parent, saved) {
		t.Fatal("inherited value aliases parent")
	}
}

func FuzzFilesecBounds(f *testing.F) {
	value := make([]byte, 44)
	be.PutUint32(value, Magic)
	f.Add(value, false)
	f.Add([]byte{0xff}, true)
	f.Fuzz(func(t *testing.T, value []byte, directory bool) {
		result, err := Inherit(value, directory)
		if err == nil && result != nil {
			if err = Validate(result); err != nil {
				t.Fatal("invalid inherited record", err)
			}
		}
	})
}
