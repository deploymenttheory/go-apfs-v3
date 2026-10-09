package apfs

import "testing"

func FuzzFilesystemRecords(f *testing.F) {
	f.Add(make([]byte, 4096), true)
	f.Fuzz(func(t *testing.T, b []byte, root bool) {
		if len(b) > 65536 {
			return
		}
		_, _ = variableRecords(b, root)
		_ = extendedFields(b, func(byte, []byte) error { return nil })
	})
}

func TestRejectOverlappingRecordStorage(t *testing.T) {
	b := make([]byte, 4096)
	le.PutUint32(b[36:], 2)
	le.PutUint16(b[42:], 16)
	for n := range 2 {
		toc := b[56+n*8:]
		le.PutUint16(toc, uint16(n*8))
		le.PutUint16(toc[2:], 8)
		le.PutUint16(toc[4:], 8)
		le.PutUint16(toc[6:], 8)
		le.PutUint64(b[72+n*8:], uint64(n+2)|3<<60)
	}
	if _, err := variableRecords(b, false); err == nil {
		t.Fatal("two entries aliasing the same value were accepted")
	}
}
