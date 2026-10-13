package filesec

import (
	"bytes"
	"errors"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

func TestCopyACLRejectsCombinedOverflowWithoutChangingInputs(t *testing.T) {
	source := make([]byte, MaxSize)
	be.PutUint32(source, Magic)
	be.PutUint32(source[36:], 128)
	destination := make([]byte, 68)
	be.PutUint32(destination, Magic)
	be.PutUint32(destination[36:], 1)
	be.PutUint32(destination[60:], Inherited)
	savedSource, savedDestination := bytes.Clone(source), bytes.Clone(destination)
	if _, err := CopyACL(source, destination); !errors.Is(err, filesystem.ErrLimit) {
		t.Fatal("combined ACL limit", err)
	}
	if !bytes.Equal(source, savedSource) || !bytes.Equal(destination, savedDestination) {
		t.Fatal("failed ACL composition changed borrowed input")
	}
}

func TestCopyACLKeepsExplicitEmptyDistinctFromAbsent(t *testing.T) {
	absent, err := CopyACL(nil, nil)
	if err != nil || absent != nil {
		t.Fatal("absent ACL", err)
	}
	inherited := make([]byte, 68)
	be.PutUint32(inherited, Magic)
	be.PutUint32(inherited[36:], 1)
	be.PutUint32(inherited[60:], Inherited)
	empty, err := CopyACL(inherited, nil)
	if err != nil || len(empty) != 44 || be.Uint32(empty[36:]) != 0 {
		t.Fatal("filtered source ACL must remain explicitly empty", err)
	}
	if err := Validate(empty); err != nil {
		t.Fatal(err)
	}
}
