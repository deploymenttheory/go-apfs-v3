package fixture

import (
	"context"
	"time"
)

// Detach actions and later probes share the same bounded raw-stream receipt.
// Command is a local transcript ordinal; ReceiptCommand anchors it if a native
// continuation subsequently merges several transcripts.
type detachOperationEvidence struct {
	Command  int
	Status   int
	Started  string
	Returned string
	Error    string `json:",omitempty"`
	Stdout   attachmentDiagnosticStream
	Stderr   attachmentDiagnosticStream
}

type detachOperationCommander struct {
	delegate Commander
	evidence *attachmentDiagnostics
}

// Run returns the exact delegate Result. Observe only the existing detach
// action, before transcript hashing or a later command can reuse its buffers.
func (c *detachOperationCommander) Run(ctx context.Context, cmd Command) Result {
	if cmd.Label != "detach" {
		return c.delegate.Run(ctx, cmd)
	}
	started := time.Now()
	result := c.delegate.Run(ctx, cmd)
	returned := time.Now()
	if imageOperationBusy("detach", result) {
		c.evidence.busy = true
	}
	if c.evidence.busy {
		row := detachOperationEvidence{
			Command: len(c.evidence.disk.T.Commands), Status: result.Status,
			Started: started.UTC().Format(time.RFC3339Nano), Returned: returned.UTC().Format(time.RFC3339Nano),
			Stdout: c.evidence.stream(result.Stdout), Stderr: c.evidence.stream(result.Stderr),
		}
		if result.Err != nil {
			row.Error = result.Err.Error()
		}
		c.evidence.actions = append(c.evidence.actions, row)
	}
	return result
}

// Read-only log workers bypass this synchronous action observer; any underlying
// recorder publication remains bound to the caller's foreground merge.
func (c *detachOperationCommander) prepareDiagnosticRead() (Commander, func(Command, detachLogResult) error) {
	return prepareDiagnosticRead(c.delegate)
}

func (c *detachOperationCommander) imageBusyRecorded(ctx context.Context, cmd Command) {
	if c.evidence.disk.ObserveBusyEject && len(cmd.Argv) > 1 && cmd.Argv[1] == "detach" {
		c.evidence.startEjectTrace(ctx, len(c.evidence.disk.T.Commands)-1)
	}
}
