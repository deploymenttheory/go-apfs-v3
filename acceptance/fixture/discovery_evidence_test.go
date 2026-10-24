package fixture

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

const discoveryOriginalSHA = "8c48a49c72dc78f9b671b4a1f03eb196e11a52ca491c8123743ede267731fa32"

func discoveryOriginals(t *testing.T) ([]schema.Command, map[string]json.RawMessage) {
	t.Helper()
	load := func(name string) []byte {
		raw, err := os.ReadFile(filepath.Join("testdata", "attachment-discovery", name))
		if err != nil {
			t.Fatal(err)
		}
		r, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(io.LimitReader(r, 1<<20))
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		return data
	}
	data := load("macos27-directory-statistics.commands.json.gz")
	if fmt.Sprintf("%x", sha256.Sum256(data)) != discoveryOriginalSHA {
		t.Fatal("original native command evidence changed")
	}
	var rows []schema.Command
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	var converted map[string]json.RawMessage
	if err := json.Unmarshal(load("macos27-directory-statistics.plist-projection.json.gz"), &converted); err != nil {
		t.Fatal(err)
	}
	return rows, converted
}

type discoveryEvidenceCommander struct {
	t                                                                  *testing.T
	rows                                                               []schema.Command
	converted                                                          map[string]json.RawMessage
	position                                                           int
	probes                                                             []Command
	postReady                                                          bool
	probeError, cleanupError                                           error
	cancel                                                             context.CancelFunc
	cancelList, cancelProbe, foreignCleanup                            bool
	firstHealthy, laterFailure, plistFailure, infoFailure, apfsFailure bool
	lists                                                              int
	mutateOriginal                                                     bool
	originalBuffer                                                     []byte
}

func (c *discoveryEvidenceCommander) Run(_ context.Context, cmd Command) Result {
	if strings.HasPrefix(cmd.Label, "discovery-failure-") {
		c.probes = append(c.probes, cmd)
		if c.mutateOriginal && len(c.probes) == 1 {
			for i := range c.originalBuffer {
				c.originalBuffer[i] = 0xff
			}
		}
		if c.cancelProbe && len(c.probes) == 1 {
			c.cancel()
		}
		if cmd.Label == "discovery-failure-post-list" && c.postReady {
			return Result{Stdout: []byte(`<plist><dict><key>AllDisks</key><array><string>disk7</string></array></dict></plist>`)}
		}
		if c.probeError != nil {
			return Result{Status: -1, Err: c.probeError}
		}
		// Deliberately synthetic scope observations; no interpretation may promote
		// them into readiness or cleanup permission.
		return Result{Status: 1, Stdout: []byte("synthetic scope observation")}
	}
	if cmd.Label == "plutil" {
		if c.plistFailure && bytes.Equal(cmd.Stdin, []byte("healthy-list")) {
			return Result{Status: 1, Stderr: []byte("conversion refused")}
		}
		raw, ok := c.converted[fmt.Sprintf("%x", sha256.Sum256(cmd.Stdin))]
		if !ok {
			c.t.Fatal("unrecorded plist projection", string(cmd.Stdin))
		}
		return Result{Stdout: raw}
	}
	if cmd.Label == "list" && (c.firstHealthy || c.laterFailure || c.plistFailure || c.infoFailure || c.apfsFailure) {
		c.lists++
		if c.laterFailure && c.lists > 1 {
			return c.result(c.rows[1])
		}
		body := `{"AllDisksAndPartitions":[]}`
		if c.infoFailure || c.apfsFailure {
			body = `{"AllDisksAndPartitions":[{"DeviceIdentifier":"disk7"}]}`
		}
		c.converted[fmt.Sprintf("%x", sha256.Sum256([]byte("healthy-list")))] = json.RawMessage(body)
		return Result{Stdout: []byte("healthy-list")}
	}
	if cmd.Label == "info" {
		if c.infoFailure {
			return Result{Status: 1, Stderr: []byte("info refused")}
		}
		c.converted[fmt.Sprintf("%x", sha256.Sum256([]byte("APFS-info")))] = json.RawMessage(`{"APFSContainerReference":"disk8","Content":"Apple_APFS"}`)
		return Result{Stdout: []byte("APFS-info")}
	}
	if cmd.Label == "apfs-list" {
		return Result{Status: 1, Stderr: []byte("APFS listing refused")}
	}
	if c.position >= len(c.rows) {
		c.t.Fatal("unrecorded native operation", cmd.Label, cmd.Argv)
	}
	row := c.rows[c.position]
	// Healthy/later-error synthetic controls do not consume the original failed
	// list row; cleanup still uses fresh ownership and one normal detach.
	if c.position == 1 && (c.firstHealthy || c.laterFailure || c.plistFailure || c.infoFailure || c.apfsFailure) {
		c.position++
		row = c.rows[c.position]
	}
	if cmd.Label != row.Label || !slices.Equal(cmd.Argv, row.Argv) {
		c.t.Fatal("native command changed", cmd.Label, cmd.Argv, row.Label, row.Argv)
	}
	c.position++
	if cmd.Label == "list" && c.cancelList {
		c.cancel()
	}
	if cmd.Label == "hdiutil-info" && c.foreignCleanup {
		data := []byte("synthetic-foreign-owner")
		c.converted[fmt.Sprintf("%x", sha256.Sum256(data))] = json.RawMessage(`{"images":[{"image-path":"/synthetic/foreign.raw","system-entities":[{"dev-entry":"/dev/disk7"}]}]}`)
		return Result{Stdout: data}
	}
	if cmd.Label == "detach" && c.cleanupError != nil {
		return Result{Status: -1, Err: c.cleanupError}
	}
	result := c.result(row)
	if cmd.Label == "list" {
		c.originalBuffer = result.Stdout
	}
	return result
}
func (c *discoveryEvidenceCommander) result(row schema.Command) Result {
	status, err := strconv.Atoi(row.Status)
	if err != nil {
		c.t.Fatal(err)
	}
	return Result{Status: status, Stdout: []byte(row.StdoutText), Stderr: []byte(row.StderrText), Duration: time.Duration(row.WallNS)}
}
func newDiscoveryReplay(t *testing.T) (*HostDisk, *discoveryEvidenceCommander, string) {
	t.Helper()
	rows, converted := discoveryOriginals(t)
	image := rows[0].Argv[len(rows[0].Argv)-1]
	c := &discoveryEvidenceCommander{t: t, rows: rows, converted: converted}
	d := &HostDisk{C: c, T: &Transcript{}, imagePathResolver: func(p string) (string, error) {
		switch p {
		case image:
			return "/declared-original-image", nil
		case "/synthetic/foreign.raw":
			return "/declared-foreign-image", nil
		default:
			return "", fmt.Errorf("undeclared image %q", p)
		}
	}}
	return d, c, image
}
func discoveryPacket(t *testing.T, d *HostDisk) attachmentDiscoveryEvidence {
	t.Helper()
	for _, row := range d.T.Commands {
		if row.Label == "attachment-discovery-evidence" {
			var p attachmentDiscoveryEvidence
			if err := json.Unmarshal([]byte(row.StdoutText), &p); err != nil {
				t.Fatal(err)
			}
			if fmt.Sprintf("%x", sha256.Sum256([]byte(row.StdoutText))) != row.StdoutSHA256 {
				t.Fatal("packet digest differs")
			}
			return p
		}
	}
	t.Fatal("missing discovery evidence")
	return attachmentDiscoveryEvidence{}
}

func TestRecordedInitialDiscoveryFailureKeepsOriginalVerdictAndFiveTimedObservations(t *testing.T) {
	d, c, image := newDiscoveryReplay(t)
	c.postReady = true
	att, err := d.Attach(context.Background(), image, AttachOptions{Raw: true, ReadOnly: true})
	if att != nil || err == nil || !strings.Contains(err.Error(), "diskutil list -plist /dev/disk7: exit 1, expected 0") {
		t.Fatal("later diagnostic success repaired original refusal", att, err)
	}
	if c.position != 4 || len(c.probes) != 5 || len(d.T.Commands) != 10 {
		t.Fatal("actions/probe count changed", c.position, len(c.probes), len(d.T.Commands))
	}
	for i, index := range []int{0, 1, 8, 9} {
		got, want := d.T.Commands[index], c.rows[i]
		if !reflect.DeepEqual(got, want) {
			t.Fatal("original command/result rewritten", i, got, want)
		}
	}
	packet := discoveryPacket(t, d)
	if packet.OriginalCommand != 1 || packet.ReceiptCommand != 7 || len(packet.Probes) != 5 || packet.Original.Status != "1" || packet.OriginalError != err.Error() {
		t.Fatal("original error/ordinals changed", packet)
	}
	if !bytes.Equal(packet.OriginalStdout.Data, []byte(c.rows[1].StdoutText)) || packet.OriginalStdout.SHA256 != c.rows[1].StdoutSHA256 {
		t.Fatal("original failure stream changed")
	}
	labels := []string{"discovery-failure-framework", "discovery-failure-modern", "discovery-failure-legacy", "discovery-failure-media", "discovery-failure-post-list"}
	for i, probe := range packet.Probes {
		if probe.Command != i+2 || c.probes[i].Label != labels[i] || c.probes[i].Expected != "record" || c.probes[i].Timeout != busyProbeTimeout {
			t.Fatal("scope contract changed", i, probe, c.probes[i])
		}
		started, e1 := time.Parse(time.RFC3339Nano, probe.Started)
		returned, e2 := time.Parse(time.RFC3339Nano, probe.Returned)
		if e1 != nil || e2 != nil || returned.Before(started) || started.Before(packet.Timing.FailedList.Returned) {
			t.Fatal("invalid caller timestamps", probe, e1, e2)
		}
	}
	if packet.Timing.Attach.Started.IsZero() || packet.Timing.Attach.Returned.Before(packet.Timing.Attach.Started) || packet.Timing.FailedList.Started.Before(packet.Timing.Attach.Returned) {
		t.Fatal("attach/list caller intervals not ordered", packet.Timing)
	}
	if !slices.Equal(c.probes[4].Argv, c.rows[1].Argv) {
		t.Fatal("post-failure query differs from original")
	}
}

func TestDiscoveryEvidencePreservesProbeCancellationAndCleanupCauses(t *testing.T) {
	for _, mode := range []string{"probe error", "cleanup error", "foreign cleanup", "cancelled list", "cancelled probe"} {
		t.Run(mode, func(t *testing.T) {
			d, c, image := newDiscoveryReplay(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c.cancel = cancel
			cause := errors.New("distinct evidence/cleanup cause")
			switch mode {
			case "probe error":
				c.probeError = cause
			case "cleanup error":
				c.cleanupError = cause
			case "foreign cleanup":
				c.foreignCleanup = true
			case "cancelled list":
				c.cancelList = true
			case "cancelled probe":
				c.cancelProbe = true
			}
			_, err := d.Attach(ctx, image, AttachOptions{Raw: true, ReadOnly: true})
			if err == nil || !strings.Contains(err.Error(), "diskutil list -plist /dev/disk7: exit 1, expected 0") {
				t.Fatal("original error lost", err)
			}
			packet := discoveryPacket(t, d)
			if len(packet.Probes) != 5 {
				t.Fatal("failed scope short-circuited independent observations")
			}
			switch mode {
			case "probe error", "cleanup error":
				if !errors.Is(err, cause) {
					t.Fatal("distinct cause lost", err)
				}
			case "foreign cleanup":
				var refusal *AttachmentOwnershipError
				if !errors.As(err, &refusal) || refusal.State != OwnershipForeign || c.position != 3 {
					t.Fatal("diagnostic observations authorized foreign action", err, c.position)
				}
			case "cancelled list", "cancelled probe":
				if !errors.Is(err, context.Canceled) || c.position != 2 {
					t.Fatal("cancelled failure lost cancellation or issued cleanup", err, c.position)
				}
				want := 0
				if mode == "cancelled probe" {
					want = 1
				}
				if len(c.probes) != want {
					t.Fatal("native probes issued after cancellation", len(c.probes))
				}
			}
		})
	}
}

func TestDiscoveryEvidenceIsInitialNonzeroListOnly(t *testing.T) {
	instantWaits(t)
	for _, mode := range []string{"healthy empty", "later list failure", "plist failure", "info failure", "APFS list failure", "standalone refresh"} {
		t.Run(mode, func(t *testing.T) {
			d, c, image := newDiscoveryReplay(t)
			switch mode {
			case "healthy empty":
				c.firstHealthy = true
			case "later list failure":
				c.laterFailure = true
			case "plist failure":
				c.plistFailure = true
			case "info failure":
				c.infoFailure = true
			case "APFS list failure":
				c.apfsFailure = true
			}
			if mode == "standalone refresh" {
				c.position = 1
				_ = d.Refresh(context.Background(), &Attachment{Dev: "/dev/disk7"})
			} else {
				att, err := d.Attach(context.Background(), image, AttachOptions{Raw: true, ReadOnly: true})
				if mode == "healthy empty" {
					if err != nil || att == nil {
						t.Fatal(err)
					}
				} else if err == nil {
					t.Fatal("noninitial discovery failure was waived")
				}
			}
			if len(c.probes) != 0 {
				t.Fatal("healthy/noninitial path collected diagnostic queries", c.probes)
			}
			for _, row := range d.T.Commands {
				if row.Label == "attachment-discovery-evidence" {
					t.Fatal("noninitial failure acquired evidence packet")
				}
			}
		})
	}
}

func TestDiscoveryTimingObserverReturnsExactResultsAndMeasuresFinalInvocation(t *testing.T) {
	interval := discoveryInvocation{}
	cause := errors.New("source result")
	want := Result{Status: 16, Stdout: []byte{0, 1, 2}, Stderr: []byte("original"), Err: cause, Duration: 24 * time.Hour}
	calls := 0
	delegate := discoveryCommandFunc(func(context.Context, Command) Result { calls++; return want })
	observer := discoveryAttachCommander{Commander: delegate, interval: &interval}
	for range 2 {
		before := time.Now()
		got := observer.Run(context.Background(), Command{})
		after := time.Now()
		if !reflect.DeepEqual(got, want) || interval.Started.Before(before) || interval.Returned.After(after) || interval.Returned.Before(interval.Started) {
			t.Fatal("result or exact invocation interval changed", got, interval)
		}
	}
	if calls != 2 {
		t.Fatal(calls)
	}
}

type discoveryCommandFunc func(context.Context, Command) Result

func (f discoveryCommandFunc) Run(ctx context.Context, cmd Command) Result { return f(ctx, cmd) }

func TestDiscoveryEvidenceFreezesOriginalBytesBeforeIndependentProbes(t *testing.T) {
	d, c, image := newDiscoveryReplay(t)
	c.mutateOriginal = true
	_, err := d.Attach(context.Background(), image, AttachOptions{Raw: true, ReadOnly: true})
	if err == nil {
		t.Fatal("original failure disappeared")
	}
	packet := discoveryPacket(t, d)
	original := []byte(c.rows[1].StdoutText)
	if !bytes.Equal(packet.OriginalStdout.Data, original) || bytes.Equal(c.originalBuffer, original) || packet.Original.StdoutSHA256 != c.rows[1].StdoutSHA256 {
		t.Fatal("reused commander buffers rewrote original evidence")
	}
}
