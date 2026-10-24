package fixture

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// These are caller invocation/return bounds, not kernel event timestamps.
// Each pair brackets exactly one Commander.Run, excluding hashing/record work.
type discoveryInvocation struct{ Started, Returned time.Time }
type discoveryEntity struct{ Device, ContentHint string }
type attachmentDiscovery struct {
	Attach     discoveryInvocation
	FailedList discoveryInvocation
	Reported   []discoveryEntity
}

// Only a private HostDisk copy uses this forwarding observer. It returns every
// original Result unchanged; the last invocation is the successful attach.
type discoveryAttachCommander struct {
	Commander
	interval *discoveryInvocation
}

func (c discoveryAttachCommander) Run(ctx context.Context, cmd Command) Result {
	started := time.Now().UTC()
	result := c.Commander.Run(ctx, cmd)
	returned := time.Now().UTC()
	*c.interval = discoveryInvocation{Started: started, Returned: returned}
	return result
}

type attachmentDiscoveryEvidence struct {
	Schema                            int
	SourceRevision, RunID, RunAttempt string
	Image, Device                     string
	Timing                            attachmentDiscovery
	OriginalCommand                   int
	Original                          schema.Command
	OriginalStdout, OriginalStderr    attachmentDiagnosticStream
	OriginalError                     string
	ReceiptCommand                    int
	Probes                            []attachmentDiagnosticProbe
	Error                             string `json:",omitempty"`
}

// A failed INITIAL attach-discovery list remains fatal. Independent evidence
// cannot promote an attachment to ready or authorize any cleanup action.
func (d *HostDisk) recordDiscoveryEvidence(ctx context.Context, a *Attachment, timing attachmentDiscovery, index int, cmd Command, original Result, failure error) error {
	collector := newAttachmentDiagnostics(d, a)
	// Freeze raw failure bytes before another Commander invocation can reuse a
	// buffer. The original transcript entry and returned error stay untouched.
	stdout, stderr := collector.stream(original.Stdout), collector.stream(original.Stderr)
	originalCommand := d.T.Commands[index]
	probeCtx, cancel := context.WithTimeout(ctx, busyEvidenceTimeout)
	defer cancel()
	collector.run(probeCtx, "discovery-failure-framework", false, nil, "hdiutil", "info", "-plist")
	for _, scope := range []struct {
		label string
		argv  []string
	}{
		{"discovery-failure-modern", imageRegistryArgs},
		{"discovery-failure-legacy", legacyRegistryArgs},
		{"discovery-failure-media", mediaRegistryArgs},
	} {
		collector.run(probeCtx, scope.label, false, nil, scope.argv...)
	}
	// This is one later observation, NEVER a discovery/verdict retry. Its status
	// and bytes are retained even if successful; no result is written into a.
	collector.run(probeCtx, "discovery-failure-post-list", cmd.Sudo, cmd.Stdin, cmd.Argv...)
	packet := attachmentDiscoveryEvidence{Schema: 1, SourceRevision: os.Getenv("GITHUB_SHA"), RunID: os.Getenv("GITHUB_RUN_ID"), RunAttempt: os.Getenv("GITHUB_RUN_ATTEMPT"), Image: a.Image, Device: a.Dev, Timing: timing, OriginalCommand: index, Original: originalCommand, OriginalStdout: stdout, OriginalStderr: stderr, OriginalError: failure.Error(), ReceiptCommand: len(d.T.Commands), Probes: collector.probes}
	if collector.err != nil {
		packet.Error = collector.err.Error()
	}
	data, err := json.Marshal(packet)
	collector.err = errors.Join(collector.err, err)
	_ = d.T.RecordFS("attachment-discovery-evidence", []string{"diagnostic", "initial-volume-discovery"}, collector.err, "record")
	entry := &d.T.Commands[len(d.T.Commands)-1]
	entry.StdoutSHA256 = fmt.Sprintf("%x", sha256.Sum256(data))
	entry.StdoutText = string(data)
	return collector.err
}
