package apfs

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// Structural corruption controls supplement Apple-produced interruption
// references. In particular a checksummed NXSB must not admit corrupt mappings,
// cross-transaction objects, aliased storage or an unsupported newer checkpoint.
func TestCheckpointCompletenessAndExplicitSelection(t *testing.T) {
	for _, control := range []struct {
		name string
		edit func(nx, mapping, object []byte)
	}{
		{"mapping checksum", func(_, m, _ []byte) { m[0] ^= 1 }},
		{"object checksum", func(_, _, o []byte) { o[0] ^= 1 }},
		{"mapping transaction", func(_, m, _ []byte) { le.PutUint64(m[16:], 3); seal(m) }},
		{"object transaction", func(_, _, o []byte) { le.PutUint64(o[16:], 3); seal(o) }},
		{"map termination", func(_, m, _ []byte) { le.PutUint32(m[32:], 0); seal(m) }},
		{"map physical identity", func(_, m, _ []byte) { le.PutUint64(m[8:], 1); seal(m) }},
		{"duplicate identity", func(_, m, _ []byte) { le.PutUint64(m[104:], 1024); seal(m) }},
		{"overlapping objects", func(_, m, _ []byte) { le.PutUint64(m[112:], 15); seal(m) }},
		{"unselected data", func(_, m, _ []byte) { le.PutUint64(m[72:], 9); seal(m) }},
		{"object subtype", func(_, _, o []byte) { le.PutUint32(o[28:], 9); seal(o) }},
		{"descriptor location", func(nx, _, _ []byte) { le.PutUint32(nx[136:], 5); seal(nx) }},
		{"overlapping rings", func(nx, _, _ []byte) { le.PutUint64(nx[120:], 1); seal(nx) }},
		{"missing root", func(nx, _, _ []byte) { le.PutUint64(nx[152:], 2048); seal(nx) }},
	} {
		t.Run(control.name, func(t *testing.T) {
			data := checkpointDisk()
			control.edit(data[8*4096:9*4096], data[7*4096:8*4096], data[15*4096:16*4096])
			before := bytes.Clone(data)
			if _, err := Open(bytes.NewReader(data)); !errors.Is(err, filesystem.ErrCorrupt) {
				t.Fatal("ordinary open must refuse incomplete latest checkpoint", err)
			}
			report, err := InspectCheckpoints(context.Background(), bytes.NewReader(data))
			if err != nil || report.SelectedTransaction != 3 || report.SelectedAddress != 4 || len(report.Candidates) != 4 || report.Candidates[0].State != "invalid" || report.Candidates[0].Reason == "" {
				t.Fatal("explicit inspection must report rejected newest checkpoint", report, err)
			}
			if !bytes.Equal(data, before) {
				t.Fatal("inspection modified source")
			}
		})
	}
}

func TestCheckpointUnsupportedNewestIsNotPermissionToRollBack(t *testing.T) {
	data := checkpointDisk()
	mapping := data[7*4096 : 8*4096]
	le.PutUint32(mapping[40:], 0xa0000005) // Unqualified no-header object storage.
	seal(mapping)
	if _, err := Open(bytes.NewReader(data)); !errors.Is(err, filesystem.ErrUnsupported) {
		t.Fatal(err)
	}
	report, err := InspectCheckpoints(context.Background(), bytes.NewReader(data))
	if err != nil || report.SelectedAddress != 0 || report.Candidates[0].State != "unsupported" || report.Candidates[1].State != "valid" {
		t.Fatal(report, err)
	}
	if _, err = ValidateCheckpointRecovery(context.Background(), bytes.NewReader(data)); !errors.Is(err, filesystem.ErrUnsupported) {
		t.Fatal("unsupported checkpoint fell back", err)
	}
}

func TestCheckpointUnknownSuperblockFlagsDoNotPermitRollback(t *testing.T) {
	data := checkpointDisk()
	nx := data[8*4096 : 9*4096]
	le.PutUint32(nx[24:], 0x90000001)
	seal(nx)
	if _, err := Open(bytes.NewReader(data)); !errors.Is(err, filesystem.ErrUnsupported) {
		t.Fatal(err)
	}
	report, err := InspectCheckpoints(context.Background(), bytes.NewReader(data))
	if err != nil || report.SelectedAddress != 0 || report.Candidates[0].State != "unsupported" {
		t.Fatal(report, err)
	}
	if _, err = ValidateCheckpointRecovery(context.Background(), bytes.NewReader(data)); !errors.Is(err, filesystem.ErrUnsupported) {
		t.Fatal(err)
	}
}

func TestCheckpointUnknownMappingFlagsDoNotPermitRollback(t *testing.T) {
	data := checkpointDisk()
	mapping := data[7*4096 : 8*4096]
	le.PutUint32(mapping[32:], 3)
	seal(mapping)
	report, err := InspectCheckpoints(context.Background(), bytes.NewReader(data))
	if err != nil || report.SelectedAddress != 0 || report.Candidates[0].State != "unsupported" {
		t.Fatal(report, err)
	}
	if _, err = ValidateCheckpointRecovery(context.Background(), bytes.NewReader(data)); !errors.Is(err, filesystem.ErrUnsupported) {
		t.Fatal(err)
	}
}

func TestBlockZeroOnlyLocatesTheDescriptorState(t *testing.T) {
	data := checkpointDisk()
	le.PutUint64(data[16:], 999)
	seal(data[:4096])
	c, err := Open(bytes.NewReader(data))
	if err != nil || c.XID != 4 || c.Checkpoint != 8 {
		t.Fatal("block-zero counters became filesystem state", c, err)
	}
	clear(data[4096 : 9*4096])
	if _, err = Open(bytes.NewReader(data)); !errors.Is(err, filesystem.ErrCorrupt) {
		t.Fatal("missing descriptor state accepted from block zero", err)
	}
}

func FuzzCheckpointInspection(f *testing.F) {
	f.Add(checkpointDisk())
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		_, _ = InspectCheckpoints(context.Background(), bytes.NewReader(data))
	})
}

func TestCheckpointInspectionHonorsCancellationAndLimits(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := InspectCheckpoints(ctx, bytes.NewReader(checkpointDisk())); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	data := checkpointDisk()
	nx := data[8*4096 : 9*4096]
	le.PutUint32(nx[108:], 0x80000008)
	seal(nx)
	report, err := InspectCheckpoints(context.Background(), bytes.NewReader(data))
	if err != nil || report.SelectedAddress != 0 || report.Candidates[0].State != "unsupported" {
		t.Fatal(report, err)
	}
}
