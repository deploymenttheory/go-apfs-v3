package fixture

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"
)

func TestMemoryVolumeKeepsHostPathResourceForkSeparateFromData(t *testing.T) {
	root := filepath.Join(t.TempDir(), "volume")
	volume := NewMemoryVolume(root)
	file := filepath.Join(root, "file")
	fork := filepath.Join(file, "..namedfork", "rsrc")
	data, resource := []byte("data fork"), []byte("resource fork\x00\xff")
	if err := volume.WriteFile(file, data, true); err != nil {
		t.Fatal(err)
	}
	if err := volume.WriteFile(fork, resource, false); err != nil {
		t.Fatal("write host-path resource fork", err)
	}
	check := func(wantData, wantResource []byte) {
		t.Helper()
		got, err := volume.Pread(file, 0, len(wantData))
		if err != nil || !bytes.Equal(got, wantData) {
			t.Fatal("data fork differs", got, err)
		}
		got, err = volume.Getxattr(file, "com.apple.ResourceFork", true)
		if err != nil || !bytes.Equal(got, wantResource) {
			t.Fatal("resource fork differs", got, err)
		}
		for path, want := range map[string][]byte{file: wantData, fork: wantResource} {
			sum := sha256.Sum256(want)
			hash, size, err := volume.Hash(path)
			if err != nil || size != int64(len(want)) || hash != hex.EncodeToString(sum[:]) {
				t.Fatal("fork hash differs", path, hash, size, err)
			}
		}
	}
	check(data, resource)
	data = []byte("replacement data")
	if err := volume.WriteFile(file, data, false); err != nil {
		t.Fatal(err)
	}
	check(data, resource)
}
