package pack_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/pack"
	"github.com/deploymenttheory/go-apfs-v3/session"
)

type lateFailureReader struct {
	filesystem.Reader
	opens int
	err   error
}

func (r *lateFailureReader) OpenRawData(ctx context.Context, id uint64) (filesystem.Value, error) {
	r.opens++
	if r.opens == 3 {
		return nil, r.err
	}
	return r.Reader.OpenRawData(ctx, id)
}

// A failure in a later volume must stop both streaming sides and leave nothing
// published, even after the first volume has already supplied its payload.
func TestContainerLaterVolumeFailure(t *testing.T) {
	s, o := inputFormat(t, "APFS")
	sentinel := errors.New("second volume source failed")
	r := &lateFailureReader{Reader: s, err: sentinel}
	volumes := []apfs.VolumeSpec{{Reader: s, Name: "First"}, {Reader: r, Name: "Second"}}
	options := pack.ContainerOptions{APFS: apfs.ContainerBuildOptions{Time: o.Volume.Time}}
	dir := t.TempDir()
	if _, err := pack.CreateContainer(context.Background(), filepath.Join(dir, "out.dmg"), volumes, options); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatal("partial multi-volume output leaked")
	}
	if r.opens != 3 {
		t.Fatal("failure did not occur during output", r.opens)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := pack.WriteContainer(cancelled, io.Discard, volumes, options); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := pack.WriteContainer(context.Background(), failureWriter{sentinel}, volumes, options); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
}

func input(t *testing.T) (*session.Session, pack.Options) { return inputFormat(t, "HFS+") }
func inputFormat(t *testing.T, format string) (*session.Session, pack.Options) {
	t.Helper()
	clock := time.Date(2025, 6, 7, 8, 9, 10, 0, time.UTC)
	s, err := session.Create(context.Background(), filepath.Join(t.TempDir(), "session"), session.Options{Names: filesystem.NameRules{Format: format, NormalizationInsensitive: true}, Time: &clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	host := filepath.Join(t.TempDir(), "input")
	if err = os.WriteFile(host, bytes.Repeat([]byte("payload"), 2000), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Copy(context.Background(), []string{host}, "/file", session.CopyOptions{FromHost: true}); err != nil {
		t.Fatal(err)
	}
	return s, pack.Options{Format: "UDZO", Volume: pack.VolumeOptions{Name: "Test", Time: clock}}
}
func TestPublishAndFailures(t *testing.T) {
	for _, format := range []string{"APFS", "HFS+"} {
		t.Run(format, func(t *testing.T) { testPublishAndFailures(t, format) })
	}
}
func testPublishAndFailures(t *testing.T, format string) {
	s, o := inputFormat(t, format)
	ctx := context.Background()
	dir := t.TempDir()
	destination := filepath.Join(dir, "out.dmg")
	o.Volume.Capacity = 4096
	if _, err := pack.Create(ctx, destination, s, o); !errors.Is(err, filesystem.ErrLimit) {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatal("failed planning left output or temporary files")
	}
	o.Volume.Capacity = 0
	if _, err := pack.Create(ctx, destination, s, o); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pack.Create(ctx, destination, s, o); !errors.Is(err, fs.ErrExist) {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(destination)
	if !bytes.Equal(original, after) {
		t.Fatal("existing output changed")
	}
	var repeated bytes.Buffer
	if _, err = pack.Write(ctx, &repeated, s, o); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, repeated.Bytes()) {
		t.Fatal("different bytes for identical inputs")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = pack.Create(cancelled, filepath.Join(dir, "cancelled.dmg"), s, o); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatal("failed build published or leaked a file")
	}
}

type failureWriter struct{ err error }

func (w failureWriter) Write([]byte) (int, error) { return 0, w.err }

type shortWriter struct{}

func (shortWriter) Write(b []byte) (int, error) { return len(b) / 2, nil }
func TestStreamingFailureTerminatesProducer(t *testing.T) {
	for _, format := range []string{"APFS", "HFS+"} {
		t.Run(format, func(t *testing.T) { testStreamingFailure(t, format) })
	}
}
func testStreamingFailure(t *testing.T, format string) {
	s, o := inputFormat(t, format)
	sentinel := errors.New("disk full")
	for _, tc := range []struct {
		writer io.Writer
		want   error
	}{{failureWriter{sentinel}, sentinel}, {shortWriter{}, io.ErrShortWrite}} {
		done := make(chan error, 1)
		go func() { _, err := pack.Write(context.Background(), tc.writer, s, o); done <- err }()
		select {
		case err := <-done:
			if !errors.Is(err, tc.want) {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("encoder failure left producer blocked")
		}
	}
}

type invalidReader struct{ filesystem.Reader }

func (r invalidReader) Stat(ctx context.Context, id uint64) (filesystem.Node, error) {
	n, e := r.Reader.Stat(ctx, id)
	n.Metadata.ModifyTime.Value = n.Metadata.ModifyTime.Value.Add(time.Nanosecond)
	return n, e
}
func TestUnrepresentableMetadataFailsBeforeOutput(t *testing.T) {
	s, o := input(t)
	var out bytes.Buffer
	if _, err := pack.Write(context.Background(), &out, invalidReader{s}, o); !errors.Is(err, filesystem.ErrUnsupported) {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatal("unsupported metadata emitted an image")
	}
}
