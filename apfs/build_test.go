package apfs_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/session"
)

func buildInput(t *testing.T) (*session.Session, apfs.BuildOptions, uint64) {
	t.Helper()
	ctx := context.Background()
	clock := time.Date(2025, 6, 7, 8, 9, 10, 123456789, time.UTC)
	s, err := session.Create(ctx, filepath.Join(t.TempDir(), "session"), session.Options{Names: filesystem.NameRules{Format: "APFS", NormalizationInsensitive: true}, Time: &clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	host := filepath.Join(t.TempDir(), "input")
	if err = os.WriteFile(host, []byte("original payload"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Copy(ctx, []string{host}, "/file", session.CopyOptions{FromHost: true}); err != nil {
		t.Fatal(err)
	}
	id, err := filesystem.LookupExact(ctx, s, "/file")
	if err != nil {
		t.Fatal(err)
	}
	return s, apfs.BuildOptions{Name: "Test", Time: clock}, id
}

type buildReader struct {
	filesystem.Reader
	stat  func(filesystem.Node) filesystem.Node
	data  func() (filesystem.Value, error)
	names []filesystem.DirEntry
}

func (r buildReader) Stat(ctx context.Context, id uint64) (filesystem.Node, error) {
	n, err := r.Reader.Stat(ctx, id)
	if err == nil && r.stat != nil {
		n = r.stat(n)
	}
	return n, err
}
func (r buildReader) OpenRawData(ctx context.Context, id uint64) (filesystem.Value, error) {
	if r.data != nil {
		return r.data()
	}
	return r.Reader.OpenRawData(ctx, id)
}
func (r buildReader) ReadDir(ctx context.Context, id uint64, yield func(filesystem.DirEntry) error) error {
	if r.names != nil {
		for _, e := range r.names {
			if err := yield(e); err != nil {
				return err
			}
		}
		return nil
	}
	return r.Reader.ReadDir(ctx, id, yield)
}

type buildValue struct {
	*bytes.Reader
	declared  int64
	readError error
	closed    *int
}

func (v buildValue) Size() int64 {
	if v.declared != 0 {
		return v.declared
	}
	return v.Reader.Size()
}
func (v buildValue) ReadAt(b []byte, off int64) (int, error) {
	if v.readError != nil {
		return 0, v.readError
	}
	return v.Reader.ReadAt(b, off)
}
func (v buildValue) Close() error {
	if v.closed != nil {
		*v.closed++
	}
	return nil
}

type buildFailWriter struct{ err error }

func (w buildFailWriter) Write(b []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	return len(b) / 2, nil
}

func TestBuildRejectsUnrepresentableInputs(t *testing.T) {
	s, o, id := buildInput(t)
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		change func(filesystem.Node) filesystem.Node
	}{
		{"unknown-metadata", func(n filesystem.Node) filesystem.Node { n.Metadata.UID.State = filesystem.Uncaptured; return n }},
		{"negative-time", func(n filesystem.Node) filesystem.Node {
			n.Metadata.BirthTime = filesystem.Observed(time.Unix(-1, 0))
			return n
		}},
		{"time-overflow", func(n filesystem.Node) filesystem.Node {
			n.Metadata.ModifyTime = filesystem.Observed(time.Date(2500, 1, 1, 0, 0, 0, 0, time.UTC))
			return n
		}},
		{"unknown-flags", func(n filesystem.Node) filesystem.Node { n.Metadata.BSDFlags.Value = 0x80000000; return n }},
		{"special-object", func(n filesystem.Node) filesystem.Node { n.Metadata.Mode.Value = 0020600; return n }},
		{"compression-inconsistent", func(n filesystem.Node) filesystem.Node { n.Metadata.BSDFlags.Value |= 32; return n }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := apfs.Plan(ctx, buildReader{Reader: s, stat: tc.change}, o); err == nil {
				t.Fatal("invalid source admitted")
			}
		})
	}
	for _, entries := range [][]filesystem.DirEntry{
		{{Name: "Name", Object: id}, {Name: "name", Object: id}},
		{{Name: "bad/name", Object: id}},
		{{Name: "cycle", Object: s.Root()}},
	} {
		if _, err := apfs.Plan(ctx, buildReader{Reader: s, names: entries}, o); err == nil {
			t.Fatal("invalid directory admitted", entries)
		}
	}
	o.CaseSensitive = true
	if _, err := apfs.Plan(ctx, s, o); !errors.Is(err, filesystem.ErrUnsupported) {
		t.Fatal("name-policy conversion admitted", err)
	}
}

func TestBuildCapacityFailsBeforeReadingPayload(t *testing.T) {
	s, o, id := buildInput(t)
	o.Capacity = 8 << 20
	reads := 0
	r := buildReader{Reader: s, stat: func(n filesystem.Node) filesystem.Node {
		if n.Identity.Object == id {
			n.Size = 64 << 20
		}
		return n
	}, data: func() (filesystem.Value, error) {
		reads++
		return buildValue{Reader: bytes.NewReader(nil), declared: 64 << 20, readError: errors.New("payload must not be read")}, nil
	}}
	if _, err := apfs.Plan(context.Background(), r, o); !errors.Is(err, filesystem.ErrLimit) {
		t.Fatal(err)
	}
	if reads != 1 {
		t.Fatal("capacity planning should open only to measure the payload", reads)
	}
}

func TestBuildPayloadLifetimeAndFailures(t *testing.T) {
	s, o, _ := buildInput(t)
	ctx := context.Background()
	closed := 0
	payload := []byte("original payload")
	r := buildReader{Reader: s, data: func() (filesystem.Value, error) {
		return buildValue{Reader: bytes.NewReader(payload), closed: &closed}, nil
	}}
	plan, err := apfs.Plan(ctx, r, o)
	if err != nil {
		t.Fatal(err)
	}
	if closed != 2 {
		t.Fatal("planning leaked a sized or hashed value", closed)
	}
	var original bytes.Buffer
	if err = plan.Write(ctx, &original); err != nil {
		t.Fatal(err)
	}
	if closed != 3 {
		t.Fatal("writing leaked a value", closed)
	}
	var repeat bytes.Buffer
	if err = plan.Write(ctx, &repeat); err != nil || !bytes.Equal(original.Bytes(), repeat.Bytes()) {
		t.Fatal("plan not repeatable", err)
	}
	sentinel := errors.New("output failed")
	if err = plan.Write(ctx, buildFailWriter{sentinel}); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	if err = plan.Write(ctx, buildFailWriter{}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err = plan.Write(cancelled, io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	payload = []byte("modified payload")
	if err = plan.Write(ctx, io.Discard); !errors.Is(err, filesystem.ErrConflict) {
		t.Fatal("changed source accepted", err)
	}
	if _, err = apfs.Plan(ctx, buildReader{Reader: s, data: func() (filesystem.Value, error) {
		return buildValue{Reader: bytes.NewReader(nil), declared: 16, readError: sentinel}, nil
	}}, o); !errors.Is(err, sentinel) {
		t.Fatal("source error lost", err)
	}
}
