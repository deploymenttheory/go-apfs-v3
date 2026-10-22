package apfs_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
)

func TestAPFSMutationCommitsGrowingFreeQueueWithFreeCapacity(t *testing.T) {
	ctx := context.Background()
	reader, options, _ := buildInput(t)
	when := time.Unix(1749283750, 0)
	options.Time, options.Capacity = when, 64<<20
	plan, err := apfs.Plan(ctx, reader, options)
	if err != nil {
		t.Fatal(err)
	}
	var built bytes.Buffer
	if err := plan.Write(ctx, &built); err != nil {
		t.Fatal(err)
	}
	disk := newMutationDisk(built.Bytes())
	changes := []apfs.Change{{Operation: "mkdir", Path: "/files"}}
	for i := range 512 {
		payload := bytes.Repeat([]byte{byte(i%251 + 1)}, 4096)
		changes = append(changes, apfs.Change{Path: fmt.Sprintf("/files/%04d", i), Data: bytes.NewReader(payload)})
	}
	if _, err := apfs.Modify(ctx, disk, changes, when); err != nil {
		t.Fatal("create separate data allocations: ", err)
	}
	if err := apfs.ValidateMutation(ctx, disk); err != nil {
		t.Fatal("created state: ", err)
	}
	created := bytes.Clone(disk.data)
	for _, count := range []int{96, 256} {
		t.Run(fmt.Sprint(count, "-alternating-files"), func(t *testing.T) {
			disk := newMutationDisk(created)
			before, err := apfs.InspectStorage(ctx, disk)
			if err != nil {
				t.Fatal(err)
			}
			if before.FreeBlocks*10 < before.Blocks*9 {
				t.Fatal("regression requires more than 90 percent free capacity", before.FreeBlocks, before.Blocks)
			}
			previous := selectedCapacityCheckpoint(t, disk)
			changes := make([]apfs.Change, count)
			for i := range count {
				changes[i] = apfs.Change{Operation: "rm", Path: fmt.Sprintf("/files/%04d", i*2)}
			}
			if _, err := apfs.Modify(ctx, disk, changes, when); err != nil {
				t.Fatalf("ordinary deletion failed with %d free blocks: %v", before.FreeBlocks, err)
			}
			if err := apfs.ValidateMutation(ctx, disk); err != nil {
				t.Fatal("deleted state accounting: ", err)
			}
			selected := selectedCapacityCheckpoint(t, disk)
			if selected.Transaction != previous.Transaction+1 {
				t.Fatal("deletion checkpoint was not published", previous, selected)
			}
			if count == 256 && (selected.Objects <= previous.Objects || selected.DataCount <= previous.DataCount) {
				t.Fatal("fragmented deletion did not grow the ephemeral free queue", previous, selected)
			}
			var continuedPayload []byte
			if count == 256 {
				// Keep committing after queue growth until checkpoint data wraps.
				// Every generation contains at least the four original objects.
				nx := disk.data[int(selected.Address)*4096:]
				steps := int(binary.LittleEndian.Uint32(nx[108:])/4) + 2
				wrapped := false
				for i := range steps {
					continuedPayload = fmt.Appendf(nil, "continued write %d", i)
					if _, err := apfs.Modify(ctx, disk, []apfs.Change{{Path: "/file", Data: bytes.NewReader(continuedPayload)}}, when); err != nil {
						t.Fatal("continued allocation after fragmented deletion", i, err)
					}
					next := selectedCapacityCheckpoint(t, disk)
					wrapped = wrapped || next.DataIndex < selected.DataIndex
					selected = next
				}
				if !wrapped {
					t.Fatal("continued commits did not exercise data-ring wrap")
				}
				if err := apfs.ValidateMutation(ctx, disk); err != nil {
					t.Fatal("continued allocation accounting: ", err)
				}
			}
			container, err := apfs.Open(disk)
			if err != nil {
				t.Fatal(err)
			}
			volume := &container.Volumes[0]
			if count == 256 {
				entry, err := volume.Lookup(ctx, volume.Root(), "file")
				if err != nil || !bytes.Equal(readCapacityFile(t, volume, entry.Object), continuedPayload) {
					t.Fatal("latest continued write was not retained", err)
				}
			}
			dir, err := volume.Lookup(ctx, volume.Root(), "files")
			if err != nil {
				t.Fatal(err)
			}
			for i := range 512 {
				entry, err := volume.Lookup(ctx, dir.Object, fmt.Sprintf("%04d", i))
				if i%2 == 0 && i/2 < count {
					if !errors.Is(err, fs.ErrNotExist) {
						t.Fatal("deleted file remains visible", i, err)
					}
					continue
				}
				if err != nil {
					t.Fatal("retained file missing", i, err)
				}
				if !bytes.Equal(readCapacityFile(t, volume, entry.Object), bytes.Repeat([]byte{byte(i%251 + 1)}, 4096)) {
					t.Fatal("retained file changed", i)
				}
			}
		})
	}
}

func readCapacityFile(t *testing.T, volume *apfs.Volume, object uint64) []byte {
	t.Helper()
	value, err := volume.OpenData(context.Background(), object)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, value.Size())
	_, err = value.ReadAt(data, 0)
	closeErr := value.Close()
	if err != nil && !errors.Is(err, io.EOF) || closeErr != nil {
		t.Fatal("read retained file", err, closeErr)
	}
	return data
}

func TestAPFSBuildCheckpointRingsRetainFourInitialGenerations(t *testing.T) {
	disk := newMutationDisk(mutationInput(t))
	initial := selectedCapacityCheckpoint(t, disk)
	nx := disk.data[int(initial.Address)*4096:]
	le := binary.LittleEndian
	if data, descriptors := le.Uint32(nx[108:]), le.Uint32(nx[104:]); data < 4*initial.DataCount || descriptors < 4*initial.DescriptorCount {
		t.Fatalf("rings cannot retain four initial checkpoints: data %d/%d, descriptors %d/%d", data, initial.DataCount, descriptors, initial.DescriptorCount)
	}
}

func selectedCapacityCheckpoint(t *testing.T, disk *mutationDisk) apfs.CheckpointInfo {
	t.Helper()
	report, err := apfs.InspectCheckpoints(context.Background(), disk)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range report.Candidates {
		if candidate.Transaction == report.SelectedTransaction && candidate.Address == report.SelectedAddress {
			return candidate
		}
	}
	t.Fatal("selected checkpoint is absent from inspection")
	return apfs.CheckpointInfo{}
}
