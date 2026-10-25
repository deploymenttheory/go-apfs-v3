package fixture

import (
	"fmt"
	"slices"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// AttachmentCleanupCommand preserves a command's original local transcript
// ordinal. Commands are never rebased when a cleanup packet is retained.
type AttachmentCleanupCommand struct {
	Ordinal int
	Command schema.Command
}

// AttachmentCleanupEvidence is an immutable snapshot of a busy detach receipt
// and its original command anchors. ReceiptJSON contains the exact original
// bytes, including unchanged local ordinals. Commands returns defensive copies.
type AttachmentCleanupEvidence struct {
	receiptJSON    string
	receiptSHA256  string
	startCommand   int
	receiptCommand int
	commands       []AttachmentCleanupCommand
}

func (e AttachmentCleanupEvidence) ReceiptJSON() string   { return e.receiptJSON }
func (e AttachmentCleanupEvidence) ReceiptSHA256() string { return e.receiptSHA256 }
func (e AttachmentCleanupEvidence) StartCommand() int     { return e.startCommand }
func (e AttachmentCleanupEvidence) ReceiptCommand() int   { return e.receiptCommand }
func (e AttachmentCleanupEvidence) Commands() []AttachmentCleanupCommand {
	commands := slices.Clone(e.commands)
	for i := range commands {
		commands[i].Command.Argv = slices.Clone(commands[i].Command.Argv)
	}
	return commands
}

// AttachmentCleanupRetentionError distinguishes failure to retain completed
// native cleanup evidence from an image/filesystem capability verdict.
type AttachmentCleanupRetentionError struct{ Cause error }

func (e *AttachmentCleanupRetentionError) Error() string {
	return fmt.Sprintf("retain attachment cleanup evidence: %v", e.Cause)
}
func (e *AttachmentCleanupRetentionError) Unwrap() error { return e.Cause }

// Keep the exact owner/action span plus only independently valid references to
// successful unmounts in this same transcript. Older transcript references stay
// explicitly prior/unknown in the original JSON and are never silently rebound.
func (c *attachmentDiagnostics) cleanupEvidence(receipt int) (AttachmentCleanupEvidence, error) {
	commands := c.disk.T.Commands
	if c.startCommand < 0 || c.startCommand > receipt || receipt >= len(commands) {
		return AttachmentCleanupEvidence{}, fmt.Errorf("cleanup command span %d..%d is invalid", c.startCommand, receipt)
	}
	var anchors []int
	for _, prior := range c.priorUnmounts {
		if prior.UnmountTranscript != "current" {
			continue
		}
		ordinal := prior.UnmountCommand
		if ordinal < 0 || ordinal >= c.startCommand || commands[ordinal].Label != "unmount" || commands[ordinal].Status != "0" {
			return AttachmentCleanupEvidence{}, fmt.Errorf("current prior-unmount command %d is not a valid original anchor", ordinal)
		}
		anchors = append(anchors, ordinal)
	}
	slices.Sort(anchors)
	anchors = slices.Compact(anchors)
	for ordinal := c.startCommand; ordinal <= receipt; ordinal++ {
		anchors = append(anchors, ordinal)
	}
	kept := make([]AttachmentCleanupCommand, len(anchors))
	for i, ordinal := range anchors {
		command := commands[ordinal]
		command.Argv = slices.Clone(command.Argv)
		kept[i] = AttachmentCleanupCommand{Ordinal: ordinal, Command: command}
	}
	original := commands[receipt]
	return AttachmentCleanupEvidence{receiptJSON: original.StdoutText, receiptSHA256: original.StdoutSHA256, startCommand: c.startCommand, receiptCommand: receipt, commands: kept}, nil
}
