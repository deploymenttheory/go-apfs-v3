package apfs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

type cloneMutationDisk struct {
	*bytes.Reader
	data           []byte
	writes, failAt int
}

func newCloneMutationDisk(data []byte) *cloneMutationDisk {
	b := bytes.Clone(data)
	return &cloneMutationDisk{Reader: bytes.NewReader(b), data: b}
}
func (d *cloneMutationDisk) WriteAt(data []byte, offset int64) (int, error) {
	d.writes++
	if d.failAt != 0 && d.writes == d.failAt {
		return 0, io.ErrClosedPipe
	}
	if offset < 0 || offset > int64(len(d.data)) || int64(len(data)) > int64(len(d.data))-offset {
		return 0, fs.ErrInvalid
	}
	return copy(d.data[offset:], data), nil
}

var cloneData = bytes.Repeat([]byte("original data."), 631)
var cloneFork = bytes.Repeat([]byte("original resource."), 747)
var cloneAttribute = bytes.Repeat([]byte("original attribute."), 433)

// This declared synthetic fixture isolates the two independent reference
// domains: three inodes share one data/attribute stream, while three distinct
// resource streams share physical blocks. It constructs those records directly;
// it does not call the clone edit/detach/release implementation under test.
// Apple-created plaintext controls separately qualify actual native profiles.
func cloneMutationImage(t *testing.T) []byte {
	t.Helper()
	ctx := context.Background()
	disk := newCloneMutationDisk(builtContainer(t, nil))
	_, err := Modify(ctx, disk, []Change{
		{Path: "/source", Data: bytes.NewReader(cloneData)},
		{Path: "/clone-a", Data: bytes.NewReader(nil)},
		{Path: "/clone-b", Data: bytes.NewReader(nil)},
		{Path: "/independent", Data: bytes.NewReader(cloneData)},
		{Path: "/source", ResourceFork: true, Data: bytes.NewReader(cloneFork)},
		{Operation: "xattr", Path: "/source", Attribute: "org.go-apfs.large", Data: bytes.NewReader(cloneAttribute)},
		{Operation: "xattr", Path: "/source", Attribute: "org.go-apfs.inline", Data: bytes.NewReader([]byte("original"))},
		{Operation: "ln", Path: "/clone-a", Destination: "/clone-alias"},
	}, builtClock)
	if err != nil {
		t.Fatal(err)
	}
	m, err := openMutation(ctx, disk)
	if err != nil {
		t.Fatal(err)
	}
	source, _ := m.lookupEntry("/source")
	sr, _ := m.inodeRecord(source.id)
	var descriptor []byte
	if err := extendedFields(sr.value[92:], func(kind byte, value []byte) error {
		if kind == 8 {
			descriptor = bytes.Clone(value)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	shared := le.Uint64(sr.value[8:])
	rc := make([]byte, 4)
	le.PutUint32(rc, 3)
	if err := m.fs.put(buildKey(shared, 6, 0), rc); err != nil {
		t.Fatal(err)
	}
	fork, _ := m.fs.get(buildXattr(source.id, filesystem.ResourceFork, nil, 2).key)
	for _, extent := range m.fs.records(le.Uint64(fork.value[4:]), 8) {
		key := buildKey(le.Uint64(extent.value[8:]), 2, 0)
		r, ok := m.extents.get(key)
		if !ok {
			t.Fatal("synthetic fork extent is not a distinct physical record")
		}
		value := bytes.Clone(r.value)
		le.PutUint32(value[16:], 3)
		if err := m.extents.put(key, value); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"/clone-a", "/clone-b"} {
		entry, _ := m.lookupEntry(name)
		r, _ := m.inodeRecord(entry.id)
		value := bytes.Clone(r.value)
		if err := m.fs.put(buildKey(le.Uint64(value[8:]), 6, 0), nil); err != nil {
			t.Fatal(err)
		}
		le.PutUint64(value[8:], shared)
		le.PutUint64(value[48:], le.Uint64(sr.value[48:])|0x10|0x400)
		value, err = replaceInodeField(value, 8, 0x20, descriptor)
		if err != nil {
			t.Fatal(err)
		}
		if err := m.fs.put(r.key, value); err != nil {
			t.Fatal(err)
		}
		for _, attr := range m.fs.records(source.id, 4) {
			attribute := bytes.Clone(attr.value)
			attrName := string(attr.key[10 : len(attr.key)-1])
			if le.Uint16(attribute)&1 != 0 {
				old := le.Uint64(attribute[4:])
				if attrName == filesystem.ResourceFork {
					id, err := m.nextFileID()
					if err != nil {
						t.Fatal(err)
					}
					le.PutUint64(attribute[4:], id)
					for _, extent := range m.fs.records(old, 8) {
						key := bytes.Clone(extent.key)
						le.PutUint64(key, id|uint64(8)<<60)
						if err := m.fs.put(key, extent.value); err != nil {
							t.Fatal(err)
						}
					}
				} else if err := m.fs.put(buildKey(old, 6, 0), rc); err != nil {
					t.Fatal(err)
				}
			}
			key := buildXattr(entry.id, attrName, nil, 2).key
			if err := m.fs.put(key, attribute); err != nil {
				t.Fatal(err)
			}
		}
	}
	value := bytes.Clone(sr.value)
	le.PutUint64(value[48:], le.Uint64(value[48:])|0x400)
	if err := m.fs.put(sr.key, value); err != nil {
		t.Fatal(err)
	}
	if err := m.commit(uint64(builtClock.UnixNano())); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMutation(ctx, disk); err != nil {
		t.Fatal("synthetic clone accounting/admission", err)
	}
	return bytes.Clone(disk.data)
}

func cloneContents(t *testing.T, disk *cloneMutationDisk, path, attribute string) []byte {
	t.Helper()
	c, err := Open(disk)
	if err != nil {
		t.Fatal(err)
	}
	v := &c.Volumes[0]
	id, err := filesystem.LookupExact(context.Background(), v, path)
	if err != nil {
		t.Fatal(path, err)
	}
	var value filesystem.Value
	if attribute == "" {
		value, err = v.OpenData(context.Background(), id)
	} else {
		value, err = v.OpenAttribute(context.Background(), id, attribute)
	}
	if err != nil {
		t.Fatal(path, attribute, err)
	}
	b := make([]byte, value.Size())
	_, err = value.ReadAt(b, 0)
	closeErr := value.Close()
	if err != nil && !errors.Is(err, io.EOF) || closeErr != nil {
		t.Fatal(err, closeErr)
	}
	return b
}

func cloneStreamState(t *testing.T, disk *cloneMutationDisk, path string) (uint64, []buildRecord) {
	t.Helper()
	m, err := openMutation(context.Background(), disk)
	if err != nil {
		t.Fatal(err)
	}
	e, err := m.lookupEntry(path)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := m.inodeRecord(e.id)
	id := le.Uint64(r.value[8:])
	return id, m.fs.records(id, 8)
}

func TestAPFSCloneEditsKeepSiblingDataForkAttributesAndHardLinksIndependent(t *testing.T) {
	ctx := context.Background()
	source := cloneMutationImage(t)
	digest := sha256.Sum256(source)
	disk := newCloneMutationDisk(source)
	shared, extents := cloneStreamState(t, disk, "/source")
	for _, path := range []string{"/clone-a", "/clone-b", "/clone-alias"} {
		id, _ := cloneStreamState(t, disk, path)
		if id != shared || !bytes.Equal(cloneContents(t, disk, path, ""), cloneData) || !bytes.Equal(cloneContents(t, disk, path, filesystem.ResourceFork), cloneFork) {
			t.Fatal("declared source sharing differs", path)
		}
	}
	apply := func(changes ...Change) {
		t.Helper()
		if _, err := Modify(ctx, disk, changes, builtClock); err != nil {
			t.Fatal(err)
		}
		if err := ValidateMutation(ctx, disk); err != nil {
			t.Fatal("changed clone state is not fully accounted", err)
		}
	}
	apply(Change{Operation: "chmod", Path: "/clone-a", Mode: "0600"}, Change{Operation: "xattr", Path: "/clone-alias", Attribute: "org.go-apfs.inline", Data: bytes.NewReader([]byte("clone-only"))})
	if id, records := cloneStreamState(t, disk, "/clone-a"); id != shared || len(records) != len(extents) || !bytes.Equal(records[0].value, extents[0].value) {
		t.Fatal("metadata-only clone edit flattened sharing")
	}
	if !bytes.Equal(cloneContents(t, disk, "/source", "org.go-apfs.inline"), []byte("original")) || !bytes.Equal(cloneContents(t, disk, "/clone-b", "org.go-apfs.inline"), []byte("original")) {
		t.Fatal("clone metadata changed siblings")
	}
	newData := bytes.Repeat([]byte("private data"), 425)
	newFork := bytes.Repeat([]byte("private fork"), 357)
	newAttribute := bytes.Repeat([]byte("private attribute"), 257)
	apply(Change{Path: "/clone-alias", Data: bytes.NewReader(newData)}, Change{Path: "/clone-a", ResourceFork: true, Data: bytes.NewReader(newFork)}, Change{Operation: "xattr", Path: "/clone-a", Attribute: "org.go-apfs.large", Data: bytes.NewReader(newAttribute)})
	if id, _ := cloneStreamState(t, disk, "/clone-a"); id == shared {
		t.Fatal("changed data retained a shared stream ID")
	}
	for _, path := range []string{"/clone-a", "/clone-alias"} {
		if !bytes.Equal(cloneContents(t, disk, path, ""), newData) || !bytes.Equal(cloneContents(t, disk, path, filesystem.ResourceFork), newFork) || !bytes.Equal(cloneContents(t, disk, path, "org.go-apfs.large"), newAttribute) {
			t.Fatal("hard-link inode did not receive all private replacements", path)
		}
	}
	for _, path := range []string{"/source", "/clone-b"} {
		id, records := cloneStreamState(t, disk, path)
		if id != shared || !bytes.Equal(records[0].value, extents[0].value) || !bytes.Equal(cloneContents(t, disk, path, ""), cloneData) || !bytes.Equal(cloneContents(t, disk, path, filesystem.ResourceFork), cloneFork) || !bytes.Equal(cloneContents(t, disk, path, "org.go-apfs.large"), cloneAttribute) {
			t.Fatal("private clone replacement changed untouched sibling/sharing", path)
		}
	}
	apply(Change{Path: "/clone-b", Data: bytes.NewReader(nil)}, Change{Operation: "rm", Path: "/source"})
	if len(cloneContents(t, disk, "/clone-b", "")) != 0 || !bytes.Equal(cloneContents(t, disk, "/clone-b", filesystem.ResourceFork), cloneFork) || !bytes.Equal(cloneContents(t, disk, "/clone-b", "org.go-apfs.large"), cloneAttribute) {
		t.Fatal("source unlink retired surviving clone fork/attribute")
	}
	apply(Change{Operation: "rm", Path: "/clone-a"})
	if !bytes.Equal(cloneContents(t, disk, "/clone-alias", ""), newData) {
		t.Fatal("nonfinal hard-link removal retired clone storage")
	}
	apply(Change{Operation: "rm", Path: "/clone-alias"}, Change{Operation: "rm", Path: "/clone-b"}, Change{Path: "/reused", Data: bytes.NewReader(bytes.Repeat([]byte("new allocation"), 5000))})
	if !bytes.Equal(cloneContents(t, disk, "/independent", ""), cloneData) || sha256.Sum256(source) != digest {
		t.Fatal("independent bytes or immutable source changed")
	}
}

func TestAPFSCloneFailedCheckpointAndFullDiskKeepSelectedSharedData(t *testing.T) {
	source := cloneMutationImage(t)
	digest := sha256.Sum256(source)
	changes := []Change{{Path: "/clone-a", Data: bytes.NewReader(bytes.Repeat([]byte("new"), 5000))}}
	completed := newCloneMutationDisk(source)
	if _, err := Modify(context.Background(), completed, changes, builtClock); err != nil {
		t.Fatal(err)
	}
	for fail := 1; fail < completed.writes; fail++ {
		disk := newCloneMutationDisk(source)
		disk.failAt = fail
		if _, err := Modify(context.Background(), disk, changes, builtClock); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal("interrupted clone mutation lost the write failure", fail, err)
		}
		for _, name := range []string{"/source", "/clone-a", "/clone-alias", "/clone-b"} {
			if !bytes.Equal(cloneContents(t, disk, name, ""), cloneData) {
				t.Fatal("unpublished clone edit overwrote selected data", fail, name)
			}
		}
	}
	disk := newCloneMutationDisk(source)
	if _, err := Modify(context.Background(), disk, []Change{{Path: "/clone-a", Data: bytes.NewReader(make([]byte, len(source)))}}, builtClock); !errors.Is(err, filesystem.ErrLimit) {
		t.Fatal("clone allocation did not fail on disk capacity", err)
	}
	for _, name := range []string{"/source", "/clone-a", "/clone-alias", "/clone-b"} {
		if !bytes.Equal(cloneContents(t, disk, name, ""), cloneData) {
			t.Fatal("full-disk clone edit overwrote selected shared data", name)
		}
	}
	if sha256.Sum256(source) != digest {
		t.Fatal("clone failures changed original source")
	}
}

func TestAPFSClonePhysicalReleaseSplitsOnlyFinalReferenceIntervals(t *testing.T) {
	disk := newCloneMutationDisk(cloneMutationImage(t))
	m, err := openMutation(context.Background(), disk)
	if err != nil {
		t.Fatal(err)
	}
	e, _ := m.lookupEntry("/source")
	attr, _ := m.fs.get(buildXattr(e.id, filesystem.ResourceFork, nil, 2).key)
	extents := m.fs.records(le.Uint64(attr.value[4:]), 8)
	if len(extents) != 1 {
		t.Fatal("interval control requires one source fork extent")
	}
	address := le.Uint64(extents[0].value[8:])
	blocks := (le.Uint64(extents[0].value) & ((1 << 56) - 1)) / 4096
	if blocks < 4 {
		t.Fatal("interval control requires prefix, middle and suffix")
	}
	for remaining := int64(2); remaining >= 0; remaining-- {
		if err := m.releaseExtent(address+1, 2); err != nil {
			t.Fatal(err)
		}
		var got []storageExtent
		for _, record := range m.extents.all() {
			start := prefix(record.key).id
			if start >= address && start < address+blocks {
				if le.Uint64(record.value[8:]) != e.id {
					t.Fatal("split changed original physical owner hint")
				}
				got = append(got, storageExtent{start, start + (le.Uint64(record.value) & objectMask), int64(int32(le.Uint32(record.value[16:])))})
			}
		}
		want := []storageExtent{{address, address + 1, 3}}
		if remaining != 0 {
			want = append(want, storageExtent{address + 1, address + 3, remaining})
		}
		want = append(want, storageExtent{address + 3, address + blocks, 3})
		if !reflect.DeepEqual(got, want) || remaining != 0 && m.freed != 0 || remaining == 0 && m.freed != 2 {
			t.Fatal("shared interval split/reclamation differs", remaining, got, want, m.freed)
		}
	}
}

func TestAPFSCloneCorruptReferencesAreRefusedBeforeWrites(t *testing.T) {
	for _, physical := range []bool{false, true} {
		source := cloneMutationImage(t)
		digest := sha256.Sum256(source)
		disk := &storageFaultSource{Source: bytes.NewReader(source), patches: map[uint64][]byte{}}
		c, err := Open(disk)
		if err != nil {
			t.Fatal(err)
		}
		checker, err := newStorageChecker(context.Background(), c)
		if err != nil {
			t.Fatal(err)
		}
		if err := checker.check(); err != nil {
			t.Fatal(err)
		}
		v := checker.volumes[0]
		if physical {
			patchStorageRecord(t, disk, v.extents, func(r buildRecord) bool { return le.Uint32(r.value[16:]) == 3 }, func(r buildRecord) { le.PutUint32(r.value[16:], 2) })
		} else {
			patchStorageRecord(t, disk, v.fs, func(r buildRecord) bool { return prefix(r.key).kind == 6 && le.Uint32(r.value) == 3 }, func(r buildRecord) { le.PutUint32(r.value, 2) })
		}
		_, err = Modify(context.Background(), disk, []Change{{Path: "/clone-a", Data: bytes.NewReader([]byte("must not write"))}}, builtClock)
		if !errors.Is(err, filesystem.ErrCorrupt) || disk.writes != 0 || sha256.Sum256(source) != digest {
			t.Fatal("corrupt clone references reached writes or changed source", physical, err, disk.writes)
		}
	}
}

func TestAPFSCloneFinalPhysicalOwnerDoesNotRequireOriginalInodeOrCloneFlags(t *testing.T) {
	ctx := context.Background()
	source := cloneMutationImage(t)
	digest := sha256.Sum256(source)
	disk := newCloneMutationDisk(source)
	m, err := openMutation(ctx, disk)
	if err != nil {
		t.Fatal(err)
	}
	original, _ := m.lookupEntry("/source")
	if _, err := Modify(ctx, disk, []Change{{Operation: "rm", Path: "/source"}, {Operation: "rm", Path: "/clone-a"}, {Operation: "rm", Path: "/clone-alias"}}, builtClock); err != nil {
		t.Fatal(err)
	}
	m, err = openMutation(ctx, disk)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := m.fs.get(buildKey(original.id, 3, 0)); present {
		t.Fatal("original physical owner inode survived source removal")
	}
	stale := false
	for _, record := range m.extents.all() {
		if le.Uint32(record.value[16:]) != 1 {
			t.Fatal("final-owner control retained a shared physical count")
		}
		stale = stale || le.Uint64(record.value[8:]) == original.id
	}
	if !stale {
		t.Fatal("final-owner control lost its original physical owner hint")
	}
	// Clone marker persistence is not an ownership premise. This declared
	// overlay leaves fully reconciled single-owner streams and physical counts
	// while clearing historical markers, without changing any native evidence.
	e, _ := m.lookupEntry("/clone-b")
	r, _ := m.inodeRecord(e.id)
	value := bytes.Clone(r.value)
	le.PutUint64(value[48:], le.Uint64(value[48:])&^uint64(0x10|0x400))
	if err := m.fs.put(r.key, value); err != nil {
		t.Fatal(err)
	}
	if err := m.commit(uint64(builtClock.UnixNano())); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMutation(ctx, disk); err != nil {
		t.Fatal("valid final-owner profile depended on historical flags", err)
	}
	for _, attribute := range []string{"", filesystem.ResourceFork, "org.go-apfs.large"} {
		var change Change
		change.Path, change.Data = "/clone-b", bytes.NewReader(bytes.Repeat([]byte("new final owner"), 300))
		if attribute == filesystem.ResourceFork {
			change.ResourceFork = true
		} else if attribute != "" {
			change.Operation, change.Attribute = "xattr", attribute
		}
		if _, err := Modify(ctx, disk, []Change{change}, builtClock); err != nil {
			t.Fatal("final owner replacement", attribute, err)
		}
		if err := ValidateMutation(ctx, disk); err != nil {
			t.Fatal("final owner replacement accounting", attribute, err)
		}
	}
	if _, err := Modify(ctx, disk, []Change{{Operation: "rm", Path: "/clone-b"}}, builtClock); err != nil {
		t.Fatal("final owner reclamation", err)
	}
	if err := ValidateMutation(ctx, disk); err != nil || sha256.Sum256(source) != digest {
		t.Fatal("final owner leaked allocation or changed original input", err)
	}
}
