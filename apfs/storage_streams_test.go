package apfs

import (
	"context"
	"errors"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

func TestNativeSharedStreamsCountInodesRatherThanDirectoryAliases(t *testing.T) {
	storage, _ := nativeStorage(t, "apfs-clone-shared")
	streams := storage.volumes[0].views[0].streams
	var shared bool
	for id, stream := range streams.streams {
		if stream.owners > 1 {
			shared = true
			if stream.attribute || streams.references[id] != stream.owners {
				t.Fatal("shared data stream owner count differs", id, stream)
			}
		}
	}
	if !shared {
		t.Fatal("native clone did not exercise shared data streams")
	}
}

func TestNativeSingleOwnerAttributeStreamsPermitImplicitReferenceOne(t *testing.T) {
	storage, _ := nativeStorage(t, "apfs-clone-final-owner")
	streams := storage.volumes[0].views[0].streams
	var implicit bool
	for id, stream := range streams.streams {
		if _, present := streams.references[id]; stream.attribute && !present && stream.allocated > 0 {
			implicit = true
			if stream.owners != 1 {
				t.Fatal("missing shared reference record accepted")
			}
		}
	}
	if !implicit {
		t.Fatal("native final-owner fork did not exercise implicit count")
	}
}

func TestSparseStreamCountersMustReconcileWithActualExtents(t *testing.T) {
	for _, fault := range []string{"incorrect sparse bytes", "missing sparse flag", "unmatched descriptor", "unsupported stream crypto", "orphan reference"} {
		t.Run(fault, func(t *testing.T) {
			storage, disk := nativeStorage(t, "snapshot-apfs-retained")
			volume := storage.volumes[0]
			patchStorageRecord(t, disk, volume.views[0].fs, func(r buildRecord) bool { return prefix(r.key).kind == 3 && le.Uint64(r.value[48:])&0x200 != 0 }, func(r buildRecord) {
				switch fault {
				case "missing sparse flag":
					le.PutUint64(r.value[48:], le.Uint64(r.value[48:])&^0x200)
				case "incorrect sparse bytes":
					extendedFields(r.value[92:], func(kind byte, data []byte) error {
						if kind == 13 {
							le.PutUint64(data, le.Uint64(data)+4096)
						}
						return nil
					})
				case "unmatched descriptor":
					extendedFields(r.value[92:], func(kind byte, data []byte) error {
						if kind == 8 {
							le.PutUint64(data[8:], le.Uint64(data[8:])+4096)
						}
						return nil
					})
				case "unsupported stream crypto":
					extendedFields(r.value[92:], func(kind byte, data []byte) error {
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
				t.Fatal("bad sparse/reference descriptor admitted", err)
			}
		})
	}
}
