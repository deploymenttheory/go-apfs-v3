package filesec

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"testing"
)

func TestHostFilesecConvertsOnlyIntegerByteOrderAndOwnsItsResult(t *testing.T) {
	// kauth_filesec header + one ACE: opaque owner/group/GUID bytes must not
	// be byte-swapped. The expected network-order representation is explicit.
	input, _ := hex.DecodeString("6dc12c01000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0100000078563412a0a1a2a3a4a5a6a7a8a9aaabacadaeaf31010000efbeadde")
	want, _ := hex.DecodeString("012cc16d000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0000000112345678a0a1a2a3a4a5a6a7a8a9aaabacadaeaf00000131deadbeef")
	saved := bytes.Clone(input)
	result, err := HostToDisk(input, binary.LittleEndian)
	if err != nil || !bytes.Equal(result, want) || !bytes.Equal(input, saved) {
		t.Fatal("host filesec conversion changed opaque identity or rights", err, result)
	}
	result[4] ^= 0xff
	if !bytes.Equal(input, saved) {
		t.Fatal("converted filesec aliases its native input")
	}
	for _, count := range []uint32{0, ^uint32(0)} {
		b := make([]byte, 44)
		binary.LittleEndian.PutUint32(b, Magic)
		binary.LittleEndian.PutUint32(b[36:], count)
		got, err := HostToDisk(b, binary.LittleEndian)
		if err != nil || be.Uint32(got[36:]) != count {
			t.Fatal("empty/NOACL distinction lost", count, err)
		}
	}
	for _, bad := range [][]byte{nil, saved[:len(saved)-1], append(bytes.Clone(saved), 0), bytes.Repeat([]byte{0xff}, MaxSize+1)} {
		if _, err := HostToDisk(bad, binary.LittleEndian); !errors.Is(err, filesystem.ErrCorrupt) {
			t.Fatal("malformed host filesec admitted", len(bad), err)
		}
	}
}
