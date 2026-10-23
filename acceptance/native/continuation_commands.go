package native

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// continuationCommands follows the observer's transcript replacements. An
// observation is serialized before later continuation calls append to its
// transcript, so retaining observations alone loses the final close receipts.
type continuationCommands struct {
	current   *fixture.Transcript
	positions map[*fixture.Transcript]int
	commands  []schema.Command
}

func (c *continuationCommands) follow(t *fixture.Transcript) {
	c.flush()
	c.current = t
}

func (c *continuationCommands) flush() {
	if c.current != nil {
		c.commands = append(c.commands, c.current.Commands[c.positions[c.current]:]...)
		c.positions[c.current] = len(c.current.Commands)
	}
}

// recordContinuationCommands records existing calls without adding disk
// operations or changing their results. The returned function runs after the
// continuation's existing cleanup and preserves the original failure.
func (v *Verifier) recordContinuationCommands(work string) func(*error) {
	return v.recordNativeCommands(work, "continuation-commands.json", "retain complete continuation commands", false)
}

// recordNativeCommands follows transcript handoffs without changing native
// operations. Successful verdicts and the existing tracked-limit policy do not
// create a failure receipt.
func (v *Verifier) recordNativeCommands(work, filename, failure string, createWork bool) func(*error) {
	previous := v.continuationLog
	commands := &continuationCommands{positions: map[*fixture.Transcript]int{}}
	v.continuationLog = commands
	return func(resultErr *error) {
		v.continuationLog = previous
		if *resultErr == nil || onlyKnownLimit(*resultErr) {
			return
		}
		commands.flush()
		data, err := json.MarshalIndent(commands.commands, "", "  ")
		if err == nil && createWork {
			err = os.MkdirAll(work, 0o755)
		}
		if err == nil {
			err = os.WriteFile(filepath.Join(work, filename), append(data, '\n'), 0o644)
		}
		if err != nil {
			*resultErr = errors.Join(*resultErr, fmt.Errorf("%s: %w", failure, err))
		}
	}
}

// setTranscript keeps HostDisk's concrete type and records the same handoffs
// that observation already performs. No command is intercepted or repeated.
func (v *Verifier) setTranscript(t *fixture.Transcript) {
	if v.continuationLog != nil {
		v.continuationLog.follow(t)
	}
	if disk, ok := v.Disk.(fixture.TranscriptUser); ok {
		disk.SetTranscript(t)
	}
}
