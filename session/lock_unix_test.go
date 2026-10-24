//go:build darwin || linux

package session

import (
	"context"
	"errors"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"golang.org/x/sys/unix"
)

func TestCloseReleasesSessionLockWhileAnotherDescriptorRemainsOpen(t *testing.T) {
	ctx := context.Background()
	s, directory := newSession(t)
	// fork inherits the same open-file description until exec closes a
	// CLOEXEC descriptor. Dup retains it deterministically without timing a fork.
	fd, err := unix.Dup(int(s.lock.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	unix.CloseOnExec(fd)
	t.Cleanup(func() { _ = unix.Close(fd) })
	if opened, err := Open(ctx, directory); !errors.Is(err, filesystem.ErrConflict) {
		if opened != nil {
			_ = opened.Close()
		}
		t.Fatalf("a live session must retain its exclusive lock: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, directory)
	if err != nil {
		t.Fatalf("closed session retained its lock through another descriptor: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if opened, err := Open(ctx, directory); !errors.Is(err, filesystem.ErrConflict) {
		if opened != nil {
			_ = opened.Close()
		}
		t.Fatalf("repeated close or failed acquisition released the new owner's lock: %v", err)
	}
}
