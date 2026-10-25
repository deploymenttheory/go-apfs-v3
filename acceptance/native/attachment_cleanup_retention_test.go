package native

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

type cleanupPacketSource struct {
	raw, digest string
	start, end  int
	commands    []fixture.AttachmentCleanupCommand
}

func (s cleanupPacketSource) ReceiptJSON() string                          { return s.raw }
func (s cleanupPacketSource) ReceiptSHA256() string                        { return s.digest }
func (s cleanupPacketSource) StartCommand() int                            { return s.start }
func (s cleanupPacketSource) ReceiptCommand() int                          { return s.end }
func (s cleanupPacketSource) Commands() []fixture.AttachmentCleanupCommand { return s.commands }

// This is a synthetic recorder packet, not a native filesystem observation.
// Whitespace and an uninterpreted malformed/truncated native outcome exercise
// exact byte retention independently of any native tool or expected verdict.
func cleanupPacket(t *testing.T, image string) cleanupPacketSource {
	t.Helper()
	raw, err := json.MarshalIndent(map[string]any{
		"SourceRevision": "checkout", "RunID": "current-run", "RunAttempt": "1", "Image": image,
		"StartCommand": 2, "ReceiptCommand": 5,
		"Actions": []any{map[string]any{"Command": 3, "Status": 16}, map[string]any{"Command": 4, "Status": 0}},
		"Error":   "native XML malformed; original stream retained only a bounded prefix",
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	s := cleanupPacketSource{raw: string(raw) + "\n", start: 2, end: 5}
	s.digest = fmt.Sprintf("%x", sha256.Sum256([]byte(s.raw)))
	s.commands = []fixture.AttachmentCleanupCommand{
		{Ordinal: 2, Command: schema.Command{Label: "hdiutil-info", Argv: []string{"hdiutil", "info", "-plist"}, Status: "0"}},
		{Ordinal: 3, Command: schema.Command{Label: "detach", Argv: []string{"hdiutil", "detach", "/dev/disk42"}, Status: "16"}},
		{Ordinal: 4, Command: schema.Command{Label: "detach", Argv: []string{"hdiutil", "detach", "-debug", "/dev/disk42"}, Status: "0"}},
		{Ordinal: 5, Command: schema.Command{Label: "busy-detach-evidence", Status: "0", StdoutText: s.raw, StdoutSHA256: s.digest}},
	}
	return s
}

type cleanupPacketFile struct {
	attachmentCleanupHeader
	ReceiptJSONBase64 string
	Commands          []fixture.AttachmentCleanupCommand
}

func readCleanupPacket(t *testing.T, path string) cleanupPacketFile {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	}()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	raw, readErr := io.ReadAll(io.LimitReader(z, 128<<20+1))
	if err := errors.Join(readErr, z.Close()); err != nil {
		t.Fatal(err)
	}
	var out cleanupPacketFile
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAttachmentCleanupPacketsPreserveOriginalBytesAndLocalReferences(t *testing.T) {
	source := cleanupPacket(t, "/native/source with snow-雪.raw")
	sink := newAttachmentCleanupSink(t.TempDir())
	if err := sink.write(source); err != nil {
		t.Fatal(err)
	}
	out := readCleanupPacket(t, filepath.Join(sink.root, source.digest+".json.gz"))
	raw, err := base64.StdEncoding.DecodeString(out.ReceiptJSONBase64)
	if err != nil || string(raw) != source.raw || fmt.Sprintf("%x", sha256.Sum256(raw)) != out.ReceiptSHA256 {
		t.Fatal("original receipt bytes, whitespace or digest changed", err)
	}
	if out.Schema != 1 || out.ReceiptBytes != len(raw) || out.StartCommand != 2 || out.ReceiptCommand != 5 || out.CommandIndexSpace != "original-local" || out.ReceiptStdoutField != "ReceiptJSONBase64" {
		t.Fatalf("packet lost its original-local ordinal/projection metadata: %+v", out.attachmentCleanupHeader)
	}
	if out.Commands[len(out.Commands)-1].Command.StdoutText != "" {
		t.Fatal("large original receipt body was encoded twice")
	}
	out.Commands[len(out.Commands)-1].Command.StdoutText = string(raw)
	if !reflect.DeepEqual(out.Commands, source.commands) || source.commands[len(source.commands)-1].Command.StdoutText != source.raw {
		t.Fatal("indexed commands cannot reconstruct original metadata or source was mutated")
	}
}

func TestAttachmentCleanupSinkIsInheritedAndDeduplicatedAcrossChildrenAndPhases(t *testing.T) {
	work := t.TempDir()
	parent := &Verifier{Work: work, attachmentCleanup: newAttachmentCleanupSink(work), observeBusyEject: true}
	child := parent.ForSubtest()
	sibling := parent.ForSubtest()
	child.Work = filepath.Join(work, "discarded-child-scratch")
	host, _ := child.hostImportVerifier("output", "windows")
	if parent.attachmentCleanup != child.attachmentCleanup || sibling.attachmentCleanup != parent.attachmentCleanup || host.attachmentCleanup != parent.attachmentCleanup || host.attachmentCleanup.root != filepath.Join(work, "native-attachment-cleanup") {
		t.Fatal("child/host observation redirected evidence into disposable scratch")
	}
	for _, current := range []*Verifier{child, sibling, host} {
		if !current.observeBusyEject || !current.Disk.(*fixture.HostDisk).ObserveBusyEject {
			t.Fatal("child/host observation lost its native job's explicit observer option")
		}
	}
	if (&Verifier{}).ForSubtest().Disk.(*fixture.HostDisk).ObserveBusyEject {
		t.Fatal("ordinary verifier enabled native observation implicitly")
	}
	source := cleanupPacket(t, "/native/source.raw")
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if err := host.attachmentCleanup.write(source); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	// A later workflow phase creates a fresh process/sink over the same job root.
	later := newAttachmentCleanupSink(work)
	if err := later.write(source); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(later.root)
	if err != nil || len(files) != 1 {
		t.Fatal("one original receipt was not retained idempotently", files, err)
	}
	changed := cleanupPacket(t, "/native/source.raw")
	changed.commands[0].Command.Argv = []string{"different-original-anchor"}
	if err := later.write(changed); err == nil {
		t.Fatal("duplicate receipt hash overwrote conflicting command provenance")
	}
}

func TestAttachmentCleanupSinkBoundsAreFatalWithoutPartialPackets(t *testing.T) {
	source := cleanupPacket(t, "/native/source.raw")
	for _, tc := range []struct {
		name string
		set  func(*attachmentCleanupLimits)
	}{
		{"original raw", func(v *attachmentCleanupLimits) { v.raw = 1 }},
		{"serialized raw", func(v *attachmentCleanupLimits) { v.raw = int64(len(source.raw)) + 1 }},
		{"gzip file", func(v *attachmentCleanupLimits) { v.file = 1 }},
		{"job bytes", func(v *attachmentCleanupLimits) { v.job = 1 }},
		{"job packet count", func(v *attachmentCleanupLimits) { v.files = 0 }},
		{"anchor count", func(v *attachmentCleanupLimits) { v.anchors = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := newAttachmentCleanupSink(t.TempDir())
			tc.set(&sink.limits)
			if err := sink.write(source); !errors.Is(err, errAttachmentCleanupLimit) {
				t.Fatal("retention bound was silently dropped or lost its cause", err)
			}
			files, err := filepath.Glob(filepath.Join(sink.root, "*.json.gz"))
			if err != nil || len(files) != 0 {
				t.Fatal("failed bounded retention published a partial packet", files, err)
			}
		})
	}
}

func TestAttachmentCleanupSinkCountsPriorPhaseFilesAndPreservesExistingEvidence(t *testing.T) {
	work := t.TempDir()
	first, second := cleanupPacket(t, "/native/first.raw"), cleanupPacket(t, "/native/second.raw")
	sink := newAttachmentCleanupSink(work)
	if err := sink.write(first); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sink.root, first.digest+".json.gz")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	later := newAttachmentCleanupSink(work)
	later.limits.job = int64(len(original))
	if err := later.write(first); err != nil {
		t.Fatal("identical receipt consumed quota twice", err)
	}
	if err := later.write(second); !errors.Is(err, errAttachmentCleanupLimit) {
		t.Fatal("new phase forgot its existing job byte budget", err)
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, original) {
		t.Fatal("exhausted job budget changed retained evidence", err)
	}
	if err := os.WriteFile(path, []byte("synthetic partial packet"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := sink.write(first); err == nil {
		t.Fatal("corrupt existing packet was overwritten or claimed idempotent")
	}
}

func TestAttachmentCleanupSinkRefusesBrokenBytesAndLocalAnchors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*cleanupPacketSource)
	}{
		{"digest mismatch", func(s *cleanupPacketSource) { s.digest = "not-the-original-digest" }},
		{"missing anchor", func(s *cleanupPacketSource) { s.commands = s.commands[1:] }},
		{"wrong receipt body", func(s *cleanupPacketSource) { s.commands[len(s.commands)-1].Command.StdoutText = "{}" }},
		{"reordered ordinals", func(s *cleanupPacketSource) { s.commands[0], s.commands[1] = s.commands[1], s.commands[0] }},
		{"wrong local span", func(s *cleanupPacketSource) { s.end++ }},
		{"malformed receipt JSON", func(s *cleanupPacketSource) {
			s.raw = "{"
			s.digest = fmt.Sprintf("%x", sha256.Sum256([]byte(s.raw)))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := cleanupPacket(t, "/native/source.raw")
			tc.change(&source)
			if err := newAttachmentCleanupSink(t.TempDir()).write(source); err == nil {
				t.Fatal("invalid evidence was silently accepted")
			}
		})
	}
}

func TestAttachmentCleanupRetentionIOFailureCannotBecomeATrackedLimit(t *testing.T) {
	work := t.TempDir()
	sink := newAttachmentCleanupSink(work)
	if err := os.WriteFile(sink.root, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cause := sink.write(cleanupPacket(t, "/native/source.raw"))
	if cause == nil {
		t.Fatal("real retention directory failure was ignored")
	}
	result := errors.Join(KnownLimit{Refusal: "original tracked limit"}, &fixture.AttachmentCleanupRetentionError{Cause: cause})
	v := &Verifier{Disk: &continuationCommandDisk{}}
	finish := v.recordContinuationCommands(work)
	v.setTranscript(&fixture.Transcript{})
	finish(&result)
	var typed *fixture.AttachmentCleanupRetentionError
	if onlyKnownLimit(result) || !errors.As(result, &typed) || !errors.Is(result, cause) {
		t.Fatal("tracked-limit policy hid a typed retention failure", result)
	}
	if _, err := os.Stat(filepath.Join(work, "continuation-commands.json")); err != nil {
		t.Fatal("tracked limit hid normal failure evidence", err)
	}
}

type cloneCleanupFailureVolume struct {
	fixture.Volume
	cause error
}

func (v cloneCleanupFailureVolume) Mkdir(string, uint32) error { return v.cause }

func TestCloneCopyWriterFailurePreservesAttachmentRetentionCause(t *testing.T) {
	writerCause, retentionCause := errors.New("clone continuation directory failed"), errors.New("cleanup evidence write failed")
	disk := &cleanupCauseDisk{detachErr: &fixture.AttachmentCleanupRetentionError{Cause: retentionCause}, detachAt: 2}
	out := schema.Output{Name: "clone-copy.UDZO.dmg", File: "ordinary-source", Operation: "edit", Source: schema.CaseRef{Recipe: "clone-copy", Profile: "apfs"}}
	v := &Verifier{Work: t.TempDir(), Disk: disk, Vol: cloneCleanupFailureVolume{cause: writerCause}}
	p := Paired{Output: out, Primary: "darwin", ByHost: map[string]schema.Output{"darwin": out}, Dirs: map[string]string{"darwin": t.TempDir()}}
	_, err := v.Continuation(context.Background(), p, schemaCase{})
	if !errors.Is(err, writerCause) || !errors.Is(err, retentionCause) || disk.detaches != 2 {
		t.Fatalf("clone-copy writer failure discarded a cleanup cause or repeated cleanup: %v (detaches=%d)", err, disk.detaches)
	}
}

func TestAttachmentCleanupRetentionTypeRemainsFatalForTrackedCauses(t *testing.T) {
	known := KnownLimit{Refusal: "original tracked input"}
	retention := &fixture.AttachmentCleanupRetentionError{Cause: known}
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"direct", retention},
		{"wrapped", fmt.Errorf("native close: %w", retention)},
		{"joined", errors.Join(known, retention)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var typed *fixture.AttachmentCleanupRetentionError
			if onlyKnownLimit(tc.err) || !errors.Is(tc.err, known) || !errors.As(tc.err, &typed) || typed != retention {
				t.Fatal("retention type became a tracked capability limit or lost its cause", tc.err)
			}
		})
	}
}
