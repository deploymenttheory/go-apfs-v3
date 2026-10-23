package fixture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	busyEvidenceTimeout     = 30 * time.Second
	busyProbeTimeout        = 10 * time.Second
	busyEvidenceTargets     = 16
	busyEvidenceStreamLimit = 8 << 20
	busyEvidenceTotalLimit  = 64 << 20
)

// Raw streams are JSON byte strings (base64), so malformed XML, NUL and invalid
// UTF-8 survive the normal transcript's textual rendering. These are bounded
// diagnostic observations, never ownership or successful-cleanup verdicts.
type attachmentDiagnosticStream struct {
	Bytes        int
	SHA256       string
	StoredSHA256 string
	Data         []byte
}

type attachmentDiagnosticProbe struct {
	Command int
	Started string
	Error   string `json:",omitempty"`
	Stdout  attachmentDiagnosticStream
	Stderr  attachmentDiagnosticStream
}

type attachmentDiagnosticMount struct {
	Device   string
	Command  int
	Started  string
	WallNS   int64
	Identity mountIdentity
	Error    string `json:",omitempty"`
}

type attachmentDiagnostics struct {
	disk       *HostDisk
	attachment *Attachment
	err        error
	stored     int
	probes     []attachmentDiagnosticProbe
	mounts     []attachmentDiagnosticMount
}

func newAttachmentDiagnostics(d *HostDisk, a *Attachment) *attachmentDiagnostics {
	return &attachmentDiagnostics{disk: d, attachment: a}
}

func (c *attachmentDiagnostics) stream(raw []byte) attachmentDiagnosticStream {
	keep := min(len(raw), busyEvidenceStreamLimit, busyEvidenceTotalLimit-c.stored)
	data := bytes.Clone(raw[:keep])
	c.stored += keep
	if keep != len(raw) {
		c.err = errors.Join(c.err, fmt.Errorf("busy attachment diagnostic stream exceeded bounds: retained %d of %d bytes", keep, len(raw)))
	}
	return attachmentDiagnosticStream{Bytes: len(raw), SHA256: fmt.Sprintf("%x", sha256.Sum256(raw)), StoredSHA256: fmt.Sprintf("%x", sha256.Sum256(data)), Data: data}
}

func (c *attachmentDiagnostics) run(ctx context.Context, label string, sudo bool, stdin []byte, argv ...string) Result {
	cmd := Command{Label: label, Argv: argv, Sudo: sudo, Stdin: stdin, Timeout: busyProbeTimeout, Expected: "record"}
	started := time.Now().UTC().Format(time.RFC3339Nano)
	var result Result
	if err := ctx.Err(); err != nil {
		result = Result{Status: -1, Err: fmt.Errorf("diagnostic not attempted: %w", err)}
	} else {
		result = c.disk.C.Run(ctx, cmd)
	}
	index := len(c.disk.T.Commands)
	err := errors.Join(c.disk.T.Record(cmd, result), ctx.Err())
	probe := attachmentDiagnosticProbe{Command: index, Started: started, Stdout: c.stream(result.Stdout), Stderr: c.stream(result.Stderr)}
	if err != nil {
		probe.Error = err.Error()
		c.err = errors.Join(c.err, err)
	}
	c.probes = append(c.probes, probe)
	return result
}

func (c *attachmentDiagnostics) collect(ctx context.Context) {
	// Retain every independent scope before interpretation. An unknown global
	// binding must not erase the archive that explains why it was unknown.
	c.run(ctx, "busy-detach-image-inventory", false, nil, "hdiutil", "info", "-plist")
	for _, scope := range []struct {
		label string
		argv  []string
	}{
		{"busy-detach-modern-inventory", imageRegistryArgs},
		{"busy-detach-legacy-inventory", legacyRegistryArgs},
		{"busy-detach-media-inventory", mediaRegistryArgs},
		{"busy-detach-bsd-ancestry", []string{"/usr/sbin/ioreg", "-a", "-l", "-p", "IOService", "-r", "-k", "BSD Name", "-t"}},
	} {
		c.run(ctx, scope.label, false, nil, scope.argv...)
	}
	nodes, _, err := c.binding(ctx)
	if err != nil {
		c.err = errors.Join(c.err, err)
		return
	}
	for _, node := range nodes {
		fresh, _, err := c.binding(ctx)
		if err != nil || !slices.Contains(fresh, node) {
			c.err = errors.Join(c.err, fmt.Errorf("related-device evidence lost its fresh image binding for %s", node), err)
			continue
		}
		result := c.run(ctx, "busy-detach-device", false, nil, "diskutil", "info", "-plist", node)
		info, err := c.plist(ctx, result)
		if err != nil {
			c.err = errors.Join(c.err, err)
			continue
		}
		if info["DeviceNode"] != node {
			c.err = errors.Join(c.err, fmt.Errorf("related-device identity changed for %s", node))
			continue
		}
		if mounted, _ := info["Mounted"].(bool); mounted {
			pin, _ := info["MountPoint"].(string)
			c.mountedHolders(ctx, node, pin)
		}
	}
	// Re-derive the entire selection immediately before the holder probe. Stale
	// Attachment.Container/Volumes/Mount values never authorize extra queries.
	nodes, pid, err := c.binding(ctx)
	if err != nil {
		c.err = errors.Join(c.err, err)
		return
	}
	paths := []string{c.attachment.Image}
	for _, node := range nodes {
		paths = append(paths, node, strings.Replace(node, "/dev/disk", "/dev/rdisk", 1))
	}
	c.run(ctx, "busy-detach-open-files", true, nil, append([]string{"/usr/sbin/lsof", "-nP", "-F0pcufDin", "-f", "--"}, paths...)...)
	if pid > 0 {
		// This identifies the expected image backend, not an ejection blocker.
		_, freshPID, err := c.binding(ctx)
		if err != nil || freshPID != pid {
			c.err = errors.Join(c.err, errors.New("image backend identity changed before process observation"), err)
		} else {
			c.run(ctx, "busy-detach-backend-identity", false, nil, "/bin/ps", "-p", strconv.Itoa(pid), "-o", "pid=,ppid=,lstart=,comm=")
		}
	}
}

func (c *attachmentDiagnostics) plist(ctx context.Context, result Result) (map[string]any, error) {
	if result.Err != nil || result.Status != 0 {
		return nil, errors.Join(fmt.Errorf("diagnostic inventory unavailable: status %d", result.Status), result.Err)
	}
	if len(result.Stdout) == 0 || len(result.Stdout) > busyEvidenceStreamLimit {
		return nil, errors.New("diagnostic inventory outside interpretation bounds")
	}
	converted := c.run(ctx, "busy-detach-plist", false, result.Stdout, "plutil", "-convert", "json", "-o", "-", "-")
	if converted.Err != nil || converted.Status != 0 {
		return nil, errors.Join(fmt.Errorf("diagnostic plist conversion failed: status %d", converted.Status), converted.Err)
	}
	if len(converted.Stdout) > busyEvidenceStreamLimit {
		return nil, errors.New("converted diagnostic inventory outside interpretation bounds")
	}
	var out map[string]any
	err := json.Unmarshal(converted.Stdout, &out)
	return out, err
}

func (c *attachmentDiagnostics) binding(ctx context.Context) ([]string, int, error) {
	r := c.run(ctx, "busy-detach-fresh-binding", false, nil, "hdiutil", "info", "-plist")
	info, err := c.plist(ctx, r)
	if err != nil {
		return nil, 0, err
	}
	images, ok := info["images"].([]any)
	if !ok {
		return nil, 0, errors.New("busy diagnostic image list is missing")
	}
	var owner map[string]any
	for _, raw := range images {
		image, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		entities, _ := image["system-entities"].([]any)
		for _, raw := range entities {
			entity, ok := raw.(map[string]any)
			if !ok || entity["dev-entry"] != c.attachment.Dev {
				continue
			}
			if owner != nil {
				return nil, 0, errors.New("busy diagnostic target has ambiguous native owners")
			}
			owner = image
		}
	}
	if owner == nil {
		return nil, 0, errors.New("busy diagnostic target has no fresh framework binding; related holder scope unknown")
	}
	path, _ := owner["image-path"].(string)
	match, err := c.disk.imagePathsMatch(path, c.attachment.Image)
	if err != nil || !match {
		return nil, 0, errors.Join(errors.New("busy diagnostic target belongs to another or unknown image"), err)
	}
	entities, _ := owner["system-entities"].([]any)
	if len(entities) == 0 || len(entities) > busyEvidenceTargets {
		return nil, 0, errors.New("busy diagnostic related-device count outside bounds")
	}
	nodes := make([]string, 0, len(entities))
	for _, raw := range entities {
		entity, ok := raw.(map[string]any)
		if !ok {
			return nil, 0, errors.New("busy diagnostic related device is malformed")
		}
		node, _ := entity["dev-entry"].(string)
		if !strings.HasPrefix(node, "/dev/disk") || !registryBSDName(strings.TrimPrefix(node, "/dev/")) || slices.Contains(nodes, node) {
			return nil, 0, errors.New("busy diagnostic related device is invalid or duplicated")
		}
		nodes = append(nodes, node)
	}
	pid := 0
	if number, ok := owner["hdid-pid"].(float64); ok && number > 0 && number <= 1<<31-1 && float64(int(number)) == number {
		pid = int(number)
	}
	return nodes, pid, nil
}

func (c *attachmentDiagnostics) mountedHolders(ctx context.Context, node, pin string) {
	started := time.Now()
	probe := c.disk.mountProbe
	if probe == nil {
		probe = mountedFilesystem
	}
	type answer struct {
		identity mountIdentity
		err      error
	}
	// A statfs on a failing filesystem can itself block. Only the observation
	// runs in this bounded goroutine; it cannot append to the transcript later.
	done := make(chan answer, 1)
	go func() {
		if !filepath.IsAbs(pin) || strings.ContainsRune(pin, 0) {
			done <- answer{err: errors.New("native mount point is not an absolute host path")}
			return
		}
		identity, err := probe(pin)
		done <- answer{identity, err}
	}()
	var identity mountIdentity
	var err error
	select {
	case result := <-done:
		identity, err = result.identity, result.err
	case <-ctx.Done():
		err = ctx.Err()
	}
	if err == nil && (pin == "" || identity.MountPoint != pin || identity.Source != node || identity.FSID == [2]int32{}) {
		err = errors.New("busy diagnostic mount no longer identifies the freshly bound volume")
	}
	row := attachmentDiagnosticMount{Device: node, Command: len(c.disk.T.Commands), Started: started.UTC().Format(time.RFC3339Nano), WallNS: time.Since(started).Nanoseconds(), Identity: identity}
	if err != nil {
		row.Error = err.Error()
		c.err = errors.Join(c.err, err)
	}
	c.mounts = append(c.mounts, row)
	data, marshalErr := json.Marshal(row)
	c.err = errors.Join(c.err, marshalErr)
	_ = c.disk.T.RecordFS("busy-detach-mount-identity", []string{"statfs", pin}, err, "record")
	entry := &c.disk.T.Commands[len(c.disk.T.Commands)-1]
	entry.StdoutSHA256, entry.StdoutText = digestAndText(data)
	entry.WallNS = row.WallNS
	if err != nil {
		return
	}
	nodes, _, err := c.binding(ctx)
	if err != nil || !slices.Contains(nodes, node) {
		c.err = errors.Join(c.err, errors.New("mounted holder scope lost native image binding"), err)
		return
	}
	// Use the verified mounted-on DEVICE, never the old private pin. If it has
	// just unmounted, lsof +f can refuse it rather than selecting the host root.
	c.run(ctx, "busy-detach-filesystem-holders", true, nil, "/usr/sbin/lsof", "-nP", "-F0pcufDin", "+f", "--", node)
}

func (c *attachmentDiagnostics) finish() error {
	// Reconstruct from the busy-detach-evidence command's StdoutText JSON.
	// Decode each stream's Data as base64 and verify its StoredSHA256; when its
	// length equals Bytes, verify SHA256 too. ReceiptCommand and Probe.Command
	// are local transcript ordinals. In a merged continuation transcript, add
	// (the receipt's actual ordinal - ReceiptCommand) to every Probe.Command.
	// The original commands retain argv, status and elapsed time independently.
	receipt := struct {
		SourceRevision  string
		RunID           string
		RunAttempt      string
		Image           string
		RequestedDevice string
		ReceiptCommand  int
		Probes          []attachmentDiagnosticProbe
		Mounts          []attachmentDiagnosticMount
		Error           string `json:",omitempty"`
	}{SourceRevision: os.Getenv("GITHUB_SHA"), RunID: os.Getenv("GITHUB_RUN_ID"), RunAttempt: os.Getenv("GITHUB_RUN_ATTEMPT"), Image: c.attachment.Image, RequestedDevice: c.attachment.Dev, ReceiptCommand: len(c.disk.T.Commands), Probes: c.probes, Mounts: c.mounts}
	if c.err != nil {
		receipt.Error = c.err.Error()
	}
	data, err := json.Marshal(receipt)
	c.err = errors.Join(c.err, err)
	_ = c.disk.T.RecordFS("busy-detach-evidence", []string{"diagnostic", "attachment-cleanup"}, c.err, "record")
	entry := &c.disk.T.Commands[len(c.disk.T.Commands)-1]
	entry.StdoutSHA256 = fmt.Sprintf("%x", sha256.Sum256(data))
	entry.StdoutText = string(data)
	return c.err
}
