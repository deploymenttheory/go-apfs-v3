package apfs

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/block"
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

// builtStorage accounts a fresh Go-built container as the baseline. Clone,
// snapshot and retained-checkpoint ownership need Apple-produced images and
// belong to the acceptance tier.
func builtStorage(t *testing.T) (*storageChecker, *storageFaultSource) {
	t.Helper()
	disk := &storageFaultSource{Source: bytes.NewReader(builtContainer(t, stageFixture(t))), patches: map[uint64][]byte{}}
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

// Each overlay is an explicitly declared semantic corruption with a repaired
// checksum, never a replacement oracle.
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
	t.Fatal("corruption target missing")
}

func TestStorageRejectsReferenceCorruptionBeforeWriting(t *testing.T) {
	for _, fault := range []string{"physical count", "stream count", "unknown extent kind"} {
		t.Run(fault, func(t *testing.T) {
			storage, disk := builtStorage(t)
			volume := storage.volumes[0]
			want := filesystem.ErrCorrupt
			switch fault {
			case "physical count":
				patchStorageRecord(t, disk, volume.extents, func(r buildRecord) bool { return le.Uint32(r.value[16:]) == 1 }, func(r buildRecord) { le.PutUint32(r.value[16:], 2) })
			case "stream count":
				patchStorageRecord(t, disk, volume.fs, func(r buildRecord) bool { return prefix(r.key).kind == 6 && le.Uint32(r.value) == 1 }, func(r buildRecord) { le.PutUint32(r.value, 2) })
			case "unknown extent kind":
				want = filesystem.ErrUnsupported
				patchStorageRecord(t, disk, volume.extents, func(buildRecord) bool { return true }, func(r buildRecord) { le.PutUint64(r.value, 3<<60|le.Uint64(r.value)&objectMask) })
			}
			report, err := InspectStorage(context.Background(), disk)
			if !errors.Is(err, want) || report != (StorageReport{}) {
				t.Fatal("bad references admitted", report, err)
			}
			_, err = Modify(context.Background(), disk, []Change{{Path: "/Fixture/data", Data: io.NewSectionReader(disk, 0, 1)}}, time.Unix(1749283750, 0))
			if err == nil || disk.writes != 0 {
				t.Fatal("refused ownership attempted a write", disk.writes, err)
			}
		})
	}
}

func TestStreamDescriptorsMustReconcileWithActualExtents(t *testing.T) {
	for _, fault := range []string{"unmatched descriptor", "unsupported stream crypto", "orphan reference"} {
		t.Run(fault, func(t *testing.T) {
			storage, disk := builtStorage(t)
			volume := storage.volumes[0]
			patchStorageRecord(t, disk, volume.views[0].fs, func(r buildRecord) bool {
				if prefix(r.key).kind != 3 {
					return false
				}
				found := false
				_ = extendedFields(r.value[92:], func(kind byte, _ []byte) error {
					found = found || kind == 8
					return nil
				})
				return found
			}, func(r buildRecord) {
				switch fault {
				case "unmatched descriptor":
					_ = extendedFields(r.value[92:], func(kind byte, data []byte) error {
						if kind == 8 {
							le.PutUint64(data[8:], le.Uint64(data[8:])+4096)
						}
						return nil
					})
				case "unsupported stream crypto":
					_ = extendedFields(r.value[92:], func(kind byte, data []byte) error {
						if kind == 8 {
							le.PutUint64(data[16:], 1)
						}
						return nil
					})
				case "orphan reference":
					le.PutUint64(r.value[8:], objectMask-1)
				}
			})
			_, err := InspectStorage(context.Background(), disk)
			want := filesystem.ErrCorrupt
			if fault == "unsupported stream crypto" {
				want = filesystem.ErrUnsupported
			}
			if !errors.Is(err, want) {
				t.Fatal("bad stream descriptor admitted", err)
			}
		})
	}
}

func TestStorageCancellationPrecedesDiskAccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := InspectStorage(ctx, &storageFaultSource{})
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled inspection accessed source", err)
	}
}
