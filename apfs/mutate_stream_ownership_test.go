package apfs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// This declared synthetic layout reproduces the descriptor-less private-ID
// alias observed on the retained Apple apfs-clones compressed controls. A
// private-ID hint alone does not own a data stream. Empty ordinary files may
// also omit the descriptor. The independent attribute streams remain real
// allocated streams; their contents come from the committed codec payloads.
func descriptorlessCloneImage(t *testing.T, compressed bool) []byte {
	t.Helper()
	ctx := context.Background()
	disk := newCloneMutationDisk(builtContainer(t, nil))
	changes := []Change{
		{Path: "/source", Data: bytes.NewReader(nil)},
		{Path: "/clone", Data: bytes.NewReader(nil)},
		{Path: "/unowned-hint", Data: bytes.NewReader(nil)},
		{Path: "/owner", Data: bytes.NewReader(cloneData)},
	}
	var attribute []byte
	if compressed {
		var err error
		attribute, err = os.ReadFile(filepath.Join("..", "acceptance", "recipes", "payloads", "decmpfs-type-4.attr"))
		if err != nil {
			t.Fatal(err)
		}
		resource, err := os.ReadFile(filepath.Join("..", "acceptance", "recipes", "payloads", "rsrc-type-4.fork"))
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"/source", "/clone", "/unowned-hint"} {
			changes = append(changes, Change{Path: name, ResourceFork: true, Data: bytes.NewReader(resource)})
		}
	}
	if _, err := Modify(ctx, disk, changes, builtClock); err != nil {
		t.Fatal(err)
	}
	m, err := openMutation(ctx, disk)
	if err != nil {
		t.Fatal(err)
	}
	source, _ := m.lookupEntry("/source")
	owner, _ := m.lookupEntry("/owner")
	or, _ := m.inodeRecord(owner.id)
	for _, name := range []string{"/source", "/clone", "/unowned-hint"} {
		entry, _ := m.lookupEntry(name)
		r, _ := m.inodeRecord(entry.id)
		if err := m.fs.put(buildKey(le.Uint64(r.value[8:]), 6, 0), nil); err != nil {
			t.Fatal(err)
		}
		value, err := removeInodeField(r.value, 8)
		if err != nil {
			t.Fatal(err)
		}
		le.PutUint64(value[8:], source.id)
		if name == "/unowned-hint" {
			le.PutUint64(value[8:], le.Uint64(or.value[8:]))
		}
		if compressed {
			le.PutUint32(value[68:], le.Uint32(value[68:])|0x20)
			le.PutUint64(value[48:], le.Uint64(value[48:])|0x40000)
			le.PutUint64(value[84:], le.Uint64(attribute[8:]))
			attr := buildXattr(entry.id, filesystem.Decmpfs, attribute, 2)
			if err := m.fs.put(attr.key, attr.value); err != nil {
				t.Fatal(err)
			}
		}
		if err := m.fs.put(r.key, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.commit(uint64(builtClock.UnixNano())); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMutation(ctx, disk); err != nil {
		t.Fatal("descriptor-less fixture must be fully accounted", err)
	}
	return bytes.Clone(disk.data)
}

func TestAPFSCloneReplacementDoesNotOwnDescriptorlessPrivateID(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty", true: "compressed"}[compressed], func(t *testing.T) {
			source := descriptorlessCloneImage(t, compressed)
			digest := sha256.Sum256(source)
			disk := newCloneMutationDisk(source)
			original := cloneContents(t, disk, "/source", "")
			payload := bytes.Repeat([]byte("private replacement data"), 500)
			apply := func(changes ...Change) {
				t.Helper()
				if _, err := Modify(context.Background(), disk, changes, builtClock); err != nil {
					t.Fatal(err)
				}
				if err := ValidateMutation(context.Background(), disk); err != nil {
					t.Fatal(err)
				}
			}
			apply(Change{Path: "/clone", Data: bytes.NewReader(payload)})
			if !bytes.Equal(cloneContents(t, disk, "/clone", ""), payload) || !bytes.Equal(cloneContents(t, disk, "/source", ""), original) {
				t.Fatal("descriptor-less clone replacement changed its sibling")
			}
			apply(Change{Operation: "rm", Path: "/source"})
			if !bytes.Equal(cloneContents(t, disk, "/clone", ""), payload) || !bytes.Equal(cloneContents(t, disk, "/owner", ""), cloneData) || sha256.Sum256(source) != digest {
				t.Fatal("descriptor-less source unlink changed another stream or original input")
			}
		})
	}
}

func TestAPFSUnlinkDoesNotReleaseDescriptorlessPrivateIDHint(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty", true: "compressed"}[compressed], func(t *testing.T) {
			source := descriptorlessCloneImage(t, compressed)
			digest := sha256.Sum256(source)
			disk := newCloneMutationDisk(source)
			if _, err := Modify(context.Background(), disk, []Change{{Operation: "rm", Path: "/unowned-hint"}}, builtClock); err != nil {
				t.Fatal(err)
			}
			if err := ValidateMutation(context.Background(), disk); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(cloneContents(t, disk, "/owner", ""), cloneData) || sha256.Sum256(source) != digest {
				t.Fatal("private-ID hint retired another inode's stream or changed original input")
			}
		})
	}
}
