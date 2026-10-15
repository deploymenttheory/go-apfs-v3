package apfs

import (
	"fmt"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// A complete descriptor/mapping sequence is not proof of the health of its old
// filesystem. Conservatively retain every deferred range whose retirement XID
// can still be reached by such a checkpoint. No historical free bitmap is used
// to infer that a block is available in the selected transaction.
func (s *storageChecker) checkpointLifetimes() error {
	report, _, _, err := inspectCheckpoints(s.ctx, s.c.source)
	if err != nil {
		return err
	}
	if report.SelectedAddress != s.c.Checkpoint || report.SelectedTransaction != s.c.XID {
		return corrupt("storage checkpoint selection changed", 0)
	}
	seen := map[XID]bool{}
	floor := s.c.XID
	for _, candidate := range report.Candidates {
		switch candidate.State {
		case "unsupported":
			return fmt.Errorf("retained checkpoint: %w", filesystem.ErrUnsupported)
		case "valid":
			if seen[candidate.Transaction] {
				return corrupt("ambiguous retained checkpoint transaction", 0)
			}
			seen[candidate.Transaction] = true
			floor = min(floor, candidate.Transaction)
			s.report.RetainedCheckpoints++
		}
	}
	s.reader.space.checkpointFloor = floor
	return nil
}
