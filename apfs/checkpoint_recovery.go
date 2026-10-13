package apfs

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

type CheckpointRecoveryReport struct {
	CheckpointReport
	DiscardedDescriptors []PhysicalAddress `json:"discardedDescriptors"`
	RewrittenBlockZero   bool              `json:"rewrittenBlockZero"`
	FilesystemValidated  bool              `json:"filesystemValidated"`
	FreeBlocks           uint64            `json:"freeBlocks"`
}

// checkpointSource selects one checkpoint using a read-only overlay. This lets
// complete ownership admission precede every write and keeps all object-map,
// tree, extent and directory rules in the ordinary mutation validator.
type checkpointSource struct {
	block.Source
	selected []byte
	discard  map[PhysicalAddress]bool
}

func (s *checkpointSource) ReadAt(data []byte, offset int64) (int, error) {
	n, err := s.Source.ReadAt(data, offset)
	if n == 0 {
		return n, err
	}
	patch := func(at int64, value []byte) {
		start, end := max(offset, at), min(offset+int64(n), at+int64(len(value)))
		if start < end {
			copy(data[start-offset:end-offset], value[start-at:end-at])
		}
	}
	patch(0, s.selected)
	for address := range s.discard {
		start := int64(address) * int64(len(s.selected))
		first, last := max(offset, start), min(offset+int64(n), start+int64(len(s.selected)))
		if first < last {
			clear(data[first-offset : last-offset])
		}
	}
	return n, err
}

// ValidateCheckpointRecovery validates an explicit recovery without writing.
// Only structurally incomplete checkpoints permit considering an earlier XID.
// Unsupported checkpoints and damage in the selected filesystem are refusals.
func ValidateCheckpointRecovery(ctx context.Context, source block.Source) (CheckpointRecoveryReport, error) {
	report, _, err := prepareCheckpointRecovery(ctx, source)
	return report, err
}

func prepareCheckpointRecovery(ctx context.Context, source block.Source) (CheckpointRecoveryReport, *checkpointSource, error) {
	var report CheckpointRecoveryReport
	inspection, _, candidates, err := inspectCheckpoints(ctx, source)
	report.CheckpointReport = inspection
	if err != nil {
		return report, nil, err
	}
	if inspection.SelectedAddress == 0 {
		for _, candidate := range inspection.Candidates {
			if candidate.State == "unsupported" {
				return report, nil, candidate.err
			}
		}
		return report, nil, fmt.Errorf("no complete APFS checkpoint: %w", filesystem.ErrCorrupt)
	}
	var selected []byte
	for i, candidate := range candidates {
		info := inspection.Candidates[i]
		if candidate.address == inspection.SelectedAddress {
			selected = candidate.data
		}
		if info.State == "valid" && info.Transaction == inspection.SelectedTransaction && info.Address != inspection.SelectedAddress {
			return report, nil, corrupt("ambiguous checkpoint transaction", int64(info.Address)*int64(inspection.BlockSize))
		}
		if info.Transaction >= inspection.SelectedTransaction && info.State == "invalid" {
			report.DiscardedDescriptors = append(report.DiscardedDescriptors, info.Address)
		}
	}
	if selected == nil {
		return report, nil, corrupt("selected checkpoint missing", 0)
	}
	view := &checkpointSource{Source: source, selected: selected, discard: map[PhysicalAddress]bool{}}
	for _, address := range report.DiscardedDescriptors {
		view.discard[address] = true
	}
	// Recovery has the same bounded plaintext ownership profile as mutation.
	// Failure here must not trigger fallback through other filesystem trees.
	m, err := openMutation(ctx, readOnlyMutation{view})
	if err != nil {
		return report, nil, err
	}
	report.FreeBlocks = m.space.free
	report.FilesystemValidated = true
	zero := make([]byte, inspection.BlockSize)
	if err = block.ReadFull(source, zero, 0); err != nil {
		return report, nil, err
	}
	report.RewrittenBlockZero = !bytes.Equal(zero, selected)
	return report, view, nil
}

// RecoverCheckpoint operates only on an exclusively owned unpublished copy.
// It disables rejected newer descriptors and refreshes block zero from the
// selected complete checkpoint. It creates no new transaction, changes no file
// records and never writes the original image. Discard this copy after errors.
func RecoverCheckpoint(ctx context.Context, disk MutableSource) (CheckpointRecoveryReport, error) {
	report, view, err := prepareCheckpointRecovery(ctx, disk)
	if err != nil {
		return report, err
	}
	write := func(data []byte, offset int64) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		n, e := disk.WriteAt(data, offset)
		if n != len(data) && e == nil {
			e = io.ErrShortWrite
		}
		return e
	}
	zero := make([]byte, report.BlockSize)
	for _, address := range report.DiscardedDescriptors {
		if err = write(zero, int64(address)*int64(report.BlockSize)); err != nil {
			return report, err
		}
	}
	if report.RewrittenBlockZero {
		if err = write(view.selected, 0); err != nil {
			return report, err
		}
	}
	if err = ValidateMutation(ctx, disk); err != nil {
		return report, err
	}
	return report, nil
}
