package apfs

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

type storageFaultSource struct {
	block.Source
	patches map[uint64][]byte
	writes  int
}

func (s *storageFaultSource) ReadAt(data []byte, offset int64) (int, error) {
	n, err := s.Source.ReadAt(data, offset)
	for address, patch := range s.patches {
		at := int64(address) * 4096
		start, end := max(offset, at), min(offset+int64(n), at+int64(len(patch)))
		if start < end {
			copy(data[start-offset:end-offset], patch[start-at:end-at])
		}
	}
	return n, err
}
func (s *storageFaultSource) WriteAt([]byte, int64) (int, error) {
	s.writes++
	return 0, fs.ErrPermission
}

func nativeStorage(t *testing.T, name string) (*storageChecker, *storageFaultSource) {
	t.Helper()
	image, err := diskimage.Open("../acceptance/testdata/apfs-lifecycle/macos-15/" + name + ".dmg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := image.Close(); err != nil {
			t.Error(err)
		}
	})
	for _, part := range image.Partitions {
		source, err := image.Partition(part.Index)
		if err != nil {
			t.Fatal(err)
		}
		header := make([]byte, 36)
		if err = block.ReadFull(source, header, 0); err != nil {
			t.Fatal(err)
		}
		if string(header[32:]) != "NXSB" {
			continue
		}
		disk := &storageFaultSource{Source: source, patches: map[uint64][]byte{}}
		container, err := Open(disk)
		if err != nil {
			t.Fatal(err)
		}
		storage, err := newStorageChecker(context.Background(), container)
		if err != nil {
			t.Fatal(err)
		}
		if err = storage.check(); err != nil {
			t.Fatal(err)
		}
		return storage, disk
	}
	t.Fatal("native APFS partition missing")
	return nil, nil
}

// Native bytes supply the baseline. Each overlay is an explicitly declared
// semantic corruption with a repaired checksum, never a replacement oracle.
func patchStorageRecord(t *testing.T, disk *storageFaultSource, tree *cowTree, match func(buildRecord) bool, change func(buildRecord)) {
	t.Helper()
	for _, node := range tree.nodes {
		if node.level != 0 {
			continue
		}
		for _, r := range node.records {
			if !match(r) {
				continue
			}
			change(r)
			original := make([]byte, 4096)
			if err := block.ReadFull(disk, original, int64(node.address)*4096); err != nil {
				t.Fatal(err)
			}
			data := tree.nodeBytes(node, node == tree.rootNode)
			sealObject(data, le.Uint64(original[8:]), le.Uint64(original[16:]), le.Uint32(original[24:]), le.Uint32(original[28:]))
			disk.patches[node.address] = data
			return
		}
	}
	t.Fatal("native corruption target missing")
}

func TestStorageRejectsNativeReferenceCorruptionBeforeWriting(t *testing.T) {
	for _, fault := range []string{"physical count", "stream count", "unknown extent kind", "missing historical mapping"} {
		t.Run(fault, func(t *testing.T) {
			name := "apfs-clone-shared"
			if fault == "missing historical mapping" {
				name = "snapshot-apfs-retained"
			}
			storage, disk := nativeStorage(t, name)
			volume := storage.volumes[0]
			want := filesystem.ErrCorrupt
			switch fault {
			case "physical count":
				patchStorageRecord(t, disk, volume.extents, func(r buildRecord) bool { return le.Uint32(r.value[16:]) > 1 }, func(r buildRecord) { le.PutUint32(r.value[16:], le.Uint32(r.value[16:])+1) })
			case "stream count":
				patchStorageRecord(t, disk, volume.fs, func(r buildRecord) bool { return prefix(r.key).kind == 6 && le.Uint32(r.value) > 1 }, func(r buildRecord) { le.PutUint32(r.value, le.Uint32(r.value)+1) })
			case "unknown extent kind":
				want = filesystem.ErrUnsupported
				patchStorageRecord(t, disk, volume.extents, func(buildRecord) bool { return true }, func(r buildRecord) { le.PutUint64(r.value, 3<<60|le.Uint64(r.value)&objectMask) })
			case "missing historical mapping":
				oldest := volume.views[0].fs.rootNode
				patchStorageRecord(t, disk, volume.omap, func(r buildRecord) bool {
					return le.Uint64(r.key) == oldest.oid && le.Uint64(r.value[8:]) == oldest.address
				}, func(r buildRecord) { le.PutUint32(r.value, 1) })
			}
			report, err := InspectStorage(context.Background(), disk)
			if !errors.Is(err, want) || report != (StorageReport{}) {
				t.Fatal("bad native references admitted", report, err)
			}
			_, err = Modify(context.Background(), disk, []Change{{Path: "/Fixture/data", Data: io.NewSectionReader(disk, 0, 1)}}, time.Unix(1749283750, 0))
			if err == nil || disk.writes != 0 {
				t.Fatal("refused ownership attempted a write", disk.writes, err)
			}
		})
	}
}
