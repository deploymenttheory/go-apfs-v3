package hfsplus

import "testing"

func FuzzTreeRecords(f *testing.F) {
	f.Add(make([]byte, 512))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			return
		}
		_, _ = nodeRecords(b, 2)
		_, _ = unicodeName(b)
	})
}
