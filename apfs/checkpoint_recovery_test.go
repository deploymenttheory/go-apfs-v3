package apfs_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"syscall"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

type checkpointWrite struct {
	offset int64
	size   int
	stage  string
}

type checkpointFaultDisk struct {
	*mutationDisk
	calls         []checkpointWrite
	fail, partial int
	failure       error
	cancelAt      int
	cancel        context.CancelFunc
}

func (d *checkpointFaultDisk) WriteAt(data []byte, offset int64) (int, error) {
	stage := "data or allocation bitmap"
	if offset == 0 {
		stage = "block zero"
	} else if len(data) >= 36 && string(data[32:36]) == "NXSB" {
		stage = "checkpoint superblock"
	} else if len(data) >= 32 {
		kind := binary.LittleEndian.Uint32(data[24:])
		switch {
		case kind == 0x4000000c:
			stage = "checkpoint mapping"
		case kind&0xffff0000 == 0x80000000:
			stage = "stored ephemeral object"
		case kind&0xffff == 2 || kind&0xffff == 3 || kind&0xffff == 7 || kind&0xffff == 11 || kind&0xffff == 13:
			stage = "filesystem metadata"
		}
	}
	d.calls = append(d.calls, checkpointWrite{offset, len(data), stage})
	if len(d.calls) == d.fail {
		n := min(max(d.partial, 0), len(data))
		copy(d.data[offset:], data[:n])
		return n, d.failure
	}
	n, err := d.mutationDisk.WriteAt(data, offset)
	if d.cancel != nil && len(d.calls) == d.cancelAt {
		d.cancel()
	}
	return n, err
}

func checkpointFile(t *testing.T, source *checkpointFaultDisk) []byte {
	t.Helper()
	c, err := apfs.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	id, err := c.Volumes[0].Lookup(context.Background(), 2, "file")
	if err != nil {
		t.Fatal(err)
	}
	v, err := c.Volumes[0].OpenData(context.Background(), id.Object)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	data := make([]byte, v.Size())
	if _, err = v.ReadAt(data, 0); err != nil {
		t.Fatal(err)
	}
	return data
}

// Every actual write is interrupted with physical prefix writes, not a mock
// that returns a short count while leaving all disk bytes untouched. Recovery
// must validate a whole old/new filesystem, including allocation and deferred
// frees. A selected intact superblock must never expose a mixture of states.
func TestCheckpointRecoveryAtEveryTransactionWrite(t *testing.T) {
	ctx := context.Background()
	original := mutationInput(t)
	before := sha256.Sum256(original)
	when := time.Unix(1749283750, 0)
	payload := bytes.Repeat([]byte("new transaction\n"), 700)
	changes := func() []apfs.Change { return []apfs.Change{{Path: "/file", Data: bytes.NewReader(payload)}} }
	baseline := &checkpointFaultDisk{mutationDisk: newMutationDisk(original)}
	result, err := apfs.Modify(ctx, baseline, changes(), when)
	if err != nil {
		t.Fatal(err)
	}
	old, err := apfs.Open(bytes.NewReader(original))
	if err != nil {
		t.Fatal(err)
	}
	stages := map[string]bool{}
	for index, call := range baseline.calls {
		stages[call.stage] = true
		for _, fault := range []struct {
			name    string
			partial int
			err     error
		}{
			{"no bytes", 0, syscall.ENOSPC},
			{"short seven bytes", 7, nil},
			{"half write", call.size / 2, io.ErrClosedPipe},
			{"missing last byte", call.size - 1, io.ErrClosedPipe},
			{"complete write reported failed", call.size, io.ErrClosedPipe},
		} {
			t.Run(fmt.Sprintf("%02d %s/%s", index, call.stage, fault.name), func(t *testing.T) {
				disk := &checkpointFaultDisk{mutationDisk: newMutationDisk(original), fail: index + 1, partial: fault.partial, failure: fault.err}
				_, err := apfs.Modify(ctx, disk, changes(), when)
				wanted := fault.err
				if wanted == nil {
					wanted = io.ErrShortWrite
				}
				if !errors.Is(err, wanted) {
					t.Fatal("fault lost", err)
				}
				recovered, err := apfs.RecoverCheckpoint(ctx, disk)
				if err != nil || !recovered.FilesystemValidated {
					t.Fatal("interrupted filesystem did not recover", recovered, err)
				}
				want := []byte("original payload")
				if uint64(recovered.SelectedTransaction) == result.Transaction {
					want = payload
				} else if recovered.SelectedTransaction != old.XID {
					t.Fatal("unrelated transaction selected", recovered.SelectedTransaction)
				}
				if got := checkpointFile(t, disk); !bytes.Equal(got, want) {
					t.Fatal("mixed transaction contents")
				}
			})
		}
	}
	for _, stage := range []string{"data or allocation bitmap", "filesystem metadata", "stored ephemeral object", "checkpoint mapping", "checkpoint superblock", "block zero"} {
		if !stages[stage] {
			t.Fatal("transaction boundary was not exercised", stage)
		}
	}
	if sha256.Sum256(original) != before {
		t.Fatal("source evidence changed")
	}
}

func TestCheckpointRecoveryRefusesSelectedFilesystemDamage(t *testing.T) {
	original := mutationInput(t)
	disk := &checkpointFaultDisk{mutationDisk: newMutationDisk(original)}
	if _, err := apfs.Modify(context.Background(), disk, []apfs.Change{{Path: "/file", Data: bytes.NewReader([]byte("changed"))}}, time.Unix(1749283750, 0)); err != nil {
		t.Fatal(err)
	}
	for _, call := range disk.calls {
		if call.stage == "filesystem metadata" {
			disk.data[call.offset] ^= 1
			break
		}
	}
	before, calls := sha256.Sum256(disk.data), len(disk.calls)
	if _, err := apfs.RecoverCheckpoint(context.Background(), disk); !errors.Is(err, filesystem.ErrCorrupt) {
		t.Fatal("filesystem damage silently rolled back", err)
	}
	if sha256.Sum256(disk.data) != before || len(disk.calls) != calls {
		t.Fatal("failed admission wrote to disk")
	}
}

func TestCheckpointRecoveryDoesNotTrustDamagedLocatorGeometry(t *testing.T) {
	for _, offset := range []int{40, 72, 104, 108, 112, 120} {
		t.Run(fmt.Sprint(offset), func(t *testing.T) {
			disk := &checkpointFaultDisk{mutationDisk: newMutationDisk(mutationInput(t))}
			disk.data[offset] ^= 1 // No checksum repair; only a locator hint remains.
			before := sha256.Sum256(disk.data)
			if _, err := apfs.RecoverCheckpoint(context.Background(), disk); err == nil {
				t.Fatal("unverified locator geometry accepted")
			}
			if len(disk.calls) != 0 || sha256.Sum256(disk.data) != before {
				t.Fatal("invalid geometry recovery wrote")
			}
		})
	}
}

func TestCheckpointRecoveryAfterCancellationAtPublicationBoundaries(t *testing.T) {
	original := mutationInput(t)
	payload := []byte("new committed contents")
	changes := func() []apfs.Change { return []apfs.Change{{Path: "/file", Data: bytes.NewReader(payload)}} }
	when := time.Unix(1749283750, 0)
	baseline := &checkpointFaultDisk{mutationDisk: newMutationDisk(original)}
	if _, err := apfs.Modify(context.Background(), baseline, changes(), when); err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"data or allocation bitmap", "checkpoint mapping", "checkpoint superblock"} {
		t.Run(stage, func(t *testing.T) {
			at := 0
			for i, call := range baseline.calls {
				if call.stage == stage {
					at = i + 1
					break
				}
			}
			if at == 0 {
				t.Fatal("boundary absent")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			disk := &checkpointFaultDisk{mutationDisk: newMutationDisk(original), cancelAt: at, cancel: cancel}
			if _, err := apfs.Modify(ctx, disk, changes(), when); !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation lost", err)
			}
			if _, err := apfs.RecoverCheckpoint(context.Background(), disk); err != nil {
				t.Fatal(err)
			}
			wanted := []byte("original payload")
			if stage == "checkpoint superblock" {
				wanted = payload
			}
			if !bytes.Equal(checkpointFile(t, disk), wanted) {
				t.Fatal("cancellation selected wrong publication state")
			}
		})
	}
}

func TestCheckpointRecoveryRefusesShortRecoveryWrite(t *testing.T) {
	disk := &checkpointFaultDisk{mutationDisk: newMutationDisk(mutationInput(t)), fail: 1, partial: 7}
	disk.data[0] ^= 1 // A damaged checksum with intact independently corroborated geometry.
	if _, err := apfs.RecoverCheckpoint(context.Background(), disk); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal("short recovery write accepted", err)
	}
}
