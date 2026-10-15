package apfs_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
)

type retirementOrderDisk struct {
	*mutationDisk
	t             *testing.T
	base, count   uint64
	selected      uint64
	selectedBytes []byte
	older         []uint64
	observed      bool
}

func (d *retirementOrderDisk) WriteAt(data []byte, offset int64) (int, error) {
	address := uint64(offset) / 4096
	if !d.observed && (address < d.base || address >= d.base+d.count) {
		d.observed = true
		for _, old := range d.older {
			if !bytes.Equal(d.data[old*4096:(old+1)*4096], make([]byte, 4096)) {
				d.t.Error("payload reuse preceded retirement of older checkpoint", old)
			}
		}
		if !bytes.Equal(d.data[d.selected*4096:(d.selected+1)*4096], d.selectedBytes) {
			d.t.Error("selected recovery checkpoint changed before payload")
		}
	}
	return d.mutationDisk.WriteAt(data, offset)
}

func TestCheckpointRetirementPrecedesPayloadReuseAndNoOpWritesNothing(t *testing.T) {
	ctx := context.Background()
	when := time.Unix(1749283750, 0)
	seed := newMutationDisk(mutationInput(t))
	for _, payload := range [][]byte{bytes.Repeat([]byte("retained"), 8192), []byte("small")} {
		if _, err := apfs.Modify(ctx, seed, []apfs.Change{{Path: "/file", Data: bytes.NewReader(payload)}}, when); err != nil {
			t.Fatal(err)
		}
	}
	report, err := apfs.InspectCheckpoints(ctx, seed)
	if err != nil {
		t.Fatal(err)
	}
	disk := &retirementOrderDisk{mutationDisk: newMutationDisk(seed.data), t: t, selected: uint64(report.SelectedAddress)}
	nx := disk.data[disk.selected*4096 : (disk.selected+1)*4096]
	disk.selectedBytes = bytes.Clone(nx)
	disk.base, disk.count = binary.LittleEndian.Uint64(nx[112:]), uint64(binary.LittleEndian.Uint32(nx[104:]))
	for _, candidate := range report.Candidates {
		if candidate.State == "valid" && uint64(candidate.Address) != disk.selected {
			disk.older = append(disk.older, uint64(candidate.Address))
		}
	}
	if len(disk.older) == 0 {
		t.Fatal("test did not retain an older recovery checkpoint")
	}
	before := bytes.Clone(disk.data)
	if _, err = apfs.Modify(ctx, disk, []apfs.Change{{Operation: "rm", Path: "/absent", Force: true}}, when); err != nil {
		t.Fatal(err)
	}
	if disk.writes != 0 || !bytes.Equal(before, disk.data) {
		t.Fatal("no-op retired a checkpoint")
	}
	if _, err = apfs.Modify(ctx, disk, []apfs.Change{{Path: "/file", Data: bytes.NewReader(bytes.Repeat([]byte("reuse"), 8192))}}, when); err != nil {
		t.Fatal(err)
	}
	if !disk.observed {
		t.Fatal("no payload/allocation write observed")
	}
	if err = apfs.ValidateMutation(ctx, disk); err != nil {
		t.Fatal("new checkpoint did not reconcile", err)
	}
}
