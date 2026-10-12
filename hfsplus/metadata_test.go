package hfsplus

import "testing"

// getbsdattr's legacy lock reconciliation must also govern offline reads and
// mutations. Looking only at BSDInfo hid the native PR32 immutable mismatch.
func TestCatalogImmutableFlags(t *testing.T) {
	for _, tc := range []struct {
		name             string
		record, locked   uint16
		stored, expected uint32
	}{
		{"unlocked file clears stale user immutable", 2, 0, 2, 0},
		{"unlocked file clears stale system immutable", 2, 0, 0x20000, 0},
		{"legacy locked file supplies user immutable", 2, 1, 0, 2},
		{"system immutable remains system immutable", 2, 1, 0x20000, 0x20000},
		{"directory immutable has no file lock", 1, 0, 2, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := make([]byte, 248)
			be.PutUint16(b, tc.record)
			be.PutUint16(b[2:], tc.locked)
			b[40], b[41] = byte(tc.stored>>16), byte(tc.stored)
			if got := catalogBSDFlags(b); got != tc.expected {
				t.Fatalf("native lock reconciliation: got %#x, want %#x", got, tc.expected)
			}
		})
	}
	for _, kind := range []uint16{1, 2} {
		b := make([]byte, 248)
		be.PutUint16(b, kind)
		be.PutUint16(b[2:], 0x34) // thread, attributes and another unrelated bit
		setCatalogBSDFlags(b, 0x8007)
		want := uint16(0x34)
		if kind == 2 {
			want |= 1
		}
		if be.Uint16(b[2:]) != want || catalogBSDFlags(b) != 0x8007 {
			t.Fatal("immutable/hidden storage does not survive catalog reconstruction")
		}
		setCatalogBSDFlags(b, 0)
		if be.Uint16(b[2:]) != 0x34 || catalogBSDFlags(b) != 0 {
			t.Fatal("clearing user flags leaves a lock or changes unrelated record flags")
		}
	}
}
