package apfs

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

func TestCloneCreationSharesPhysicalStreamsAndKeepsIndependentMetadata(t *testing.T) {
	ctx := context.Background()
	disk := newCloneMutationDisk(builtContainer(t, nil))
	_, err := Modify(ctx, disk, []Change{{Path: "/source", Data: bytes.NewReader(cloneData)}, {Path: "/source", ResourceFork: true, Data: bytes.NewReader(cloneFork)}, {Operation: "xattr", Path: "/source", Attribute: "org.go-apfs.large", Data: bytes.NewReader(cloneAttribute)}}, builtClock)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Modify(ctx, disk, []Change{{Operation: "clone", Path: "/source", Destination: "/copy", ActorUID: filesystem.Observed(uint32(0))}, {Operation: "clone", Path: "/source", Destination: "/untouched", ActorUID: filesystem.Observed(uint32(0))}}, builtClock)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateMutation(ctx, disk); err != nil {
		t.Fatal("clone ownership/accounting", err)
	}
	m, err := openMutation(ctx, disk)
	if err != nil {
		t.Fatal(err)
	}
	source, _ := m.lookupEntry("/source")
	clone, _ := m.lookupEntry("/copy")
	sr, _ := m.inodeRecord(source.id)
	cr, _ := m.inodeRecord(clone.id)
	sourceStream, _ := inodeDataStreamID(sr.value)
	cloneStream, _ := inodeDataStreamID(cr.value)
	if source.id == clone.id || sourceStream == 0 || sourceStream != cloneStream {
		t.Fatal("clone did not create a distinct inode with shared data descriptor")
	}
	for _, name := range []string{filesystem.ResourceFork, "org.go-apfs.large"} {
		a, _ := m.fs.get(buildXattr(source.id, name, nil, 2).key)
		b, _ := m.fs.get(buildXattr(clone.id, name, nil, 2).key)
		if le.Uint64(a.value[4:]) == le.Uint64(b.value[4:]) {
			t.Fatal("attribute streams did not receive independent stream identities", name)
		}
		left, right := m.fs.records(le.Uint64(a.value[4:]), 8), m.fs.records(le.Uint64(b.value[4:]), 8)
		if len(left) == 0 || len(left) != len(right) {
			t.Fatal("missing shared attribute physical ranges", name)
		}
		for i := range left {
			if !bytes.Equal(left[i].key[8:], right[i].key[8:]) || !bytes.Equal(left[i].value, right[i].value) {
				t.Fatal("clone attribute copied bytes into new physical storage", name)
			}
		}
	}
	_, err = Modify(ctx, disk, []Change{{Operation: "ln", Path: "/copy", Destination: "/copy-alias"}, {Path: "/copy", Data: bytes.NewReader([]byte("private data"))}, {Path: "/copy", ResourceFork: true, Data: bytes.NewReader([]byte("private fork"))}, {Operation: "xattr", Path: "/copy", Attribute: "org.go-apfs.large", Data: bytes.NewReader([]byte("private attribute"))}, {Operation: "rm", Path: "/source"}}, builtClock)
	if err != nil {
		t.Fatal(err)
	}
	if got := cloneContents(t, disk, "/copy-alias", ""); string(got) != "private data" {
		t.Fatal("alias data", string(got))
	}
	if got := cloneContents(t, disk, "/copy-alias", filesystem.ResourceFork); string(got) != "private fork" {
		t.Fatal("alias fork", string(got))
	}
	if got := cloneContents(t, disk, "/untouched", ""); !bytes.Equal(got, cloneData) {
		t.Fatal("source removal changed shared survivor data")
	}
	if got := cloneContents(t, disk, "/untouched", filesystem.ResourceFork); !bytes.Equal(got, cloneFork) {
		t.Fatal("source removal changed shared survivor fork")
	}
	if got := cloneContents(t, disk, "/untouched", "org.go-apfs.large"); !bytes.Equal(got, cloneAttribute) {
		t.Fatal("source removal changed shared survivor attribute")
	}
	if err := ValidateMutation(ctx, disk); err != nil {
		t.Fatal("post-clone ownership/accounting", err)
	}
}

func TestCloneCreationPreservesDescriptorlessCompressionWithoutOwningPrivateIDHint(t *testing.T) {
	ctx := context.Background()
	disk := newCloneMutationDisk(descriptorlessCloneImage(t, true))
	before := cloneContents(t, disk, "/unowned-hint", "")
	if _, err := Modify(ctx, disk, []Change{{Operation: "clone", Path: "/unowned-hint", Destination: "/new-compressed"}}, builtClock); err != nil {
		t.Fatal(err)
	}
	if got := cloneContents(t, disk, "/new-compressed", ""); !bytes.Equal(got, before) {
		t.Fatal("compressed clone lost logical data")
	}
	if _, err := Modify(ctx, disk, []Change{{Operation: "rm", Path: "/unowned-hint"}, {Path: "/new-compressed", Data: bytes.NewReader([]byte("private replacement"))}}, builtClock); err != nil {
		t.Fatal(err)
	}
	if got := cloneContents(t, disk, "/owner", ""); !bytes.Equal(got, cloneData) {
		t.Fatal("descriptor-less clone owned another inode's hinted stream")
	}
	if err := ValidateMutation(ctx, disk); err != nil {
		t.Fatal(err)
	}
}

func TestCloneCreationRefusesExistingDestinationAndPropagatesCommitFailure(t *testing.T) {
	ctx := context.Background()
	source := cloneMutationImage(t)
	disk := newCloneMutationDisk(source)
	if _, err := Modify(ctx, disk, []Change{{Operation: "clone", Path: "/source", Destination: "/clone-a"}}, builtClock); !errors.Is(err, fs.ErrExist) || disk.writes != 0 {
		t.Fatal("existing clone destination was changed", err, disk.writes)
	}
	probe := newCloneMutationDisk(source)
	if _, err := Modify(ctx, probe, []Change{{Operation: "clone", Path: "/source", Destination: "/new"}}, builtClock); err != nil {
		t.Fatal(err)
	}
	if probe.writes < 2 {
		t.Fatal("missing checkpoint publication writes")
	}
	for _, at := range []int{1, probe.writes} {
		disk := newCloneMutationDisk(source)
		disk.failAt = at
		if _, err := Modify(ctx, disk, []Change{{Operation: "clone", Path: "/source", Destination: "/new"}}, builtClock); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal("clone checkpoint failure lost", at, err)
		}
		if got := cloneContents(t, disk, "/source", ""); !bytes.Equal(got, cloneData) {
			t.Fatal("failed clone changed selected source checkpoint")
		}
	}
}
