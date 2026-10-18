package apfs

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/session"
)

var builtClock = time.Date(2026, 10, 10, 1, 2, 3, 0, time.UTC)

// builtContainer constructs a plaintext single-volume container from a session
// staged by populate. The product is both builder and subject; Apple-only state
// (snapshots, clones, directory statistics, encryption) is never present.
func builtContainer(t *testing.T, populate func(ctx context.Context, s *session.Session)) []byte {
	t.Helper()
	ctx := context.Background()
	s, err := session.Create(ctx, filepath.Join(t.TempDir(), "session"), session.Options{Names: filesystem.NameRules{Format: "APFS", NormalizationInsensitive: true}, Time: &builtClock})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if populate != nil {
		populate(ctx, s)
	}
	plan, err := Plan(ctx, s, BuildOptions{Name: "Built", Time: builtClock, Capacity: 8 << 20})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err = plan.Write(ctx, &out); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// stageFixture copies host bytes to /Fixture/data and links /Fixture/alias to it.
func stageFixture(t *testing.T) func(ctx context.Context, s *session.Session) {
	t.Helper()
	host := filepath.Join(t.TempDir(), "data")
	if err := os.WriteFile(host, []byte("built fixture payload\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return func(ctx context.Context, s *session.Session) {
		if _, err := s.Mkdir(ctx, []string{"/Fixture"}, session.MkdirOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Copy(ctx, []string{host}, "/Fixture/data", session.CopyOptions{FromHost: true}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Link(ctx, "/Fixture/data", "/Fixture/alias", session.LinkOptions{}); err != nil {
			t.Fatal(err)
		}
	}
}

func openBuilt(t *testing.T, data []byte) *Container {
	t.Helper()
	c, err := Open(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Volumes) != 1 {
		t.Fatal("built container volume count", len(c.Volumes))
	}
	return c
}
