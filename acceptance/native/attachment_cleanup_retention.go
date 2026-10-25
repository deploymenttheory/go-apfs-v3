package native

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
)

// These are diagnostic retention limits, not filesystem or retry limits.
// Existing packets count toward the job budget across its sequential phases.
type attachmentCleanupLimits struct {
	raw, file, job int64
	files, anchors int
}

var errAttachmentCleanupLimit = errors.New("attachment cleanup evidence exceeds retention bounds")

type attachmentCleanupSource interface {
	ReceiptJSON() string
	ReceiptSHA256() string
	StartCommand() int
	ReceiptCommand() int
	Commands() []fixture.AttachmentCleanupCommand
}

type attachmentCleanupSink struct {
	mu     sync.Mutex
	root   string
	limits attachmentCleanupLimits
}

func newAttachmentCleanupSink(work string) *attachmentCleanupSink {
	return &attachmentCleanupSink{
		root:   filepath.Join(work, "native-attachment-cleanup"),
		limits: attachmentCleanupLimits{raw: 128 << 20, file: 16 << 20, job: 64 << 20, files: 128, anchors: 512},
	}
}

func (s *attachmentCleanupSink) retain(e fixture.AttachmentCleanupEvidence) error {
	return s.write(e)
}

// The sole original receipt body is base64 streamed into the gzip JSON packet.
// The indexed receipt command keeps its original metadata/digest/local ordinal,
// with stdout reconstructed from ReceiptJSONBase64 rather than encoded twice.
// No other command fields or original receipt bytes are projected or rebased.
type attachmentCleanupHeader struct {
	Schema             int
	ReceiptBytes       int
	ReceiptSHA256      string
	StartCommand       int
	ReceiptCommand     int
	CommandIndexSpace  string
	ReceiptStdoutField string
}

func (s *attachmentCleanupSink) write(source attachmentCleanupSource) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, digest := source.ReceiptJSON(), source.ReceiptSHA256()
	if int64(len(raw)) > s.limits.raw {
		return errAttachmentCleanupLimit
	}
	commands, err := validateAttachmentCleanup(source, s.limits.anchors)
	if err != nil {
		return err
	}
	header := attachmentCleanupHeader{Schema: 1, ReceiptBytes: len(raw), ReceiptSHA256: digest, StartCommand: source.StartCommand(), ReceiptCommand: source.ReceiptCommand(), CommandIndexSpace: "original-local", ReceiptStdoutField: "ReceiptJSONBase64"}
	var compressed bytes.Buffer
	file := &attachmentCleanupLimitedWriter{w: &compressed, remaining: s.limits.file}
	z := gzip.NewWriter(file)
	uncompressed := &attachmentCleanupLimitedWriter{w: z, remaining: s.limits.raw}
	encodeErr := encodeAttachmentCleanup(uncompressed, header, raw, commands)
	if err := errors.Join(encodeErr, z.Close()); err != nil {
		return err
	}
	if err := os.MkdirAll(s.root, 0o755); err != nil {
		return err
	}
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return err
	}
	if len(entries) > s.limits.files {
		return errAttachmentCleanupLimit
	}
	name := digest + ".json.gz"
	var total int64
	var existing bool
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return err
		}
		stem, ok := strings.CutSuffix(entry.Name(), ".json.gz")
		decoded, decodeErr := hex.DecodeString(stem)
		if !ok || decodeErr != nil || len(decoded) != sha256.Size || stem != strings.ToLower(stem) || !info.Mode().IsRegular() {
			return fmt.Errorf("invalid retained attachment packet %q", entry.Name())
		}
		if info.Size() > s.limits.file || info.Size() > s.limits.job-total {
			return errAttachmentCleanupLimit
		}
		total += info.Size()
		if entry.Name() == name {
			data, err := os.ReadFile(filepath.Join(s.root, name))
			if err != nil {
				return err
			}
			if !bytes.Equal(data, compressed.Bytes()) {
				return errors.New("existing attachment packet differs from its original receipt")
			}
			existing = true
		}
	}
	if existing {
		return nil
	}
	if len(entries) == s.limits.files || int64(compressed.Len()) > s.limits.job-total {
		return errAttachmentCleanupLimit
	}
	path := filepath.Join(s.root, name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(compressed.Bytes())
	if err := errors.Join(writeErr, f.Close()); err != nil {
		return errors.Join(err, os.Remove(path))
	}
	return nil
}

type attachmentCleanupLimitedWriter struct {
	w         io.Writer
	remaining int64
}

func (w *attachmentCleanupLimitedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		return 0, errAttachmentCleanupLimit
	}
	n, err := w.w.Write(p)
	w.remaining -= int64(n)
	return n, err
}

func encodeAttachmentCleanup(w io.Writer, header attachmentCleanupHeader, raw string, commands []fixture.AttachmentCleanupCommand) error {
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return err
	}
	if _, err := w.Write(headerJSON[:len(headerJSON)-1]); err != nil {
		return err
	}
	if _, err := io.WriteString(w, `,"ReceiptJSONBase64":"`); err != nil {
		return err
	}
	b64 := base64.NewEncoder(base64.StdEncoding, w)
	_, copyErr := io.Copy(b64, strings.NewReader(raw))
	if err := errors.Join(copyErr, b64.Close()); err != nil {
		return err
	}
	if _, err := io.WriteString(w, `","Commands":[`); err != nil {
		return err
	}
	for i, anchor := range commands {
		if i != 0 {
			if _, err := io.WriteString(w, ","); err != nil {
				return err
			}
		}
		if anchor.Ordinal == header.ReceiptCommand {
			anchor.Command.StdoutText = ""
		}
		if err := json.NewEncoder(w).Encode(anchor); err != nil {
			return err
		}
	}
	_, err = io.WriteString(w, "]}\n")
	return err
}

func validateAttachmentCleanup(source attachmentCleanupSource, maxAnchors int) ([]fixture.AttachmentCleanupCommand, error) {
	raw := source.ReceiptJSON()
	hash := sha256.New()
	for rest := raw; rest != ""; {
		chunk := min(len(rest), 32<<10)
		_, _ = hash.Write([]byte(rest[:chunk]))
		rest = rest[chunk:]
	}
	if !utf8.ValidString(raw) || hex.EncodeToString(hash.Sum(nil)) != source.ReceiptSHA256() {
		return nil, errors.New("attachment receipt original bytes/digest do not match")
	}
	var refs struct {
		StartCommand, ReceiptCommand  int
		Actions, Probes, Mounts, Logs []struct{ Command int }
		PriorUnmounts                 []struct {
			Command, UnmountCommand int
			UnmountTranscript       string
		}
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	if err := decoder.Decode(&refs); err != nil {
		return nil, fmt.Errorf("invalid attachment receipt: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, errors.New("attachment receipt contains trailing JSON")
	}
	start, end := source.StartCommand(), source.ReceiptCommand()
	if start < 0 || end < start || refs.StartCommand != start || refs.ReceiptCommand != end || len(refs.Actions) == 0 {
		return nil, errors.New("attachment receipt has invalid original command bounds")
	}
	commands := source.Commands()
	if len(commands) == 0 || len(commands) > maxAnchors {
		return nil, errAttachmentCleanupLimit
	}
	indexes := map[int]fixture.AttachmentCleanupCommand{}
	last := -1
	for _, command := range commands {
		if command.Ordinal <= last || command.Ordinal > end {
			return nil, errors.New("attachment command anchors are duplicated, reordered or outside the original transcript")
		}
		last, indexes[command.Ordinal] = command.Ordinal, command
	}
	for ordinal := start; ordinal <= end; ordinal++ {
		if _, ok := indexes[ordinal]; !ok {
			return nil, errors.New("attachment receipt lacks its complete original cleanup span")
		}
	}
	receipt := indexes[end].Command
	if receipt.Label != "busy-detach-evidence" || receipt.StdoutText != raw || receipt.StdoutSHA256 != source.ReceiptSHA256() {
		return nil, errors.New("attachment receipt command does not retain the original payload")
	}
	for _, group := range [][]struct{ Command int }{refs.Actions, refs.Probes, refs.Mounts, refs.Logs} {
		for _, ref := range group {
			if _, ok := indexes[ref.Command]; !ok {
				return nil, errors.New("attachment receipt references an unretained local command")
			}
		}
	}
	for _, ref := range refs.PriorUnmounts {
		if _, ok := indexes[ref.Command]; !ok {
			return nil, errors.New("prior unmount observation lacks its current command anchor")
		}
		if ref.UnmountTranscript == "current" {
			if _, ok := indexes[ref.UnmountCommand]; !ok {
				return nil, errors.New("prior unmount lacks its original current-transcript command")
			}
		}
	}
	return commands, nil
}
