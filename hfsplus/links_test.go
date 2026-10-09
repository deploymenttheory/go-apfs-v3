package hfsplus

import (
	"context"
	"errors"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

func TestHardLinkRequiresCreationDate(t *testing.T) {
	v := &Volume{rootCreated: 10, privateID: 30, privateCreated: 20}
	b := make([]byte, 248)
	be.PutUint16(b, 2)
	be.PutUint32(b[12:], 99)
	copy(b[48:], "hlnkhfs+")
	got, err := v.resolveLink(context.Background(), b)
	if err != nil || &got[0] != &b[0] {
		t.Fatal("ordinary Finder type mistaken for hard link", err)
	}
	be.PutUint32(b[12:], 10)
	if _, err := v.resolveLink(context.Background(), b); !errors.Is(err, filesystem.ErrCorrupt) {
		t.Fatal("zero link reference accepted", err)
	}
	copy(b[48:], "fdrpMACS")
	be.PutUint16(b[2:], 0x20)
	if _, err := v.resolveLink(context.Background(), b); !errors.Is(err, filesystem.ErrUnsupported) {
		t.Fatal("directory hard link silently treated as file", err)
	}
}
