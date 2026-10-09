package filesystem

import (
	"context"
	"fmt"
	"io/fs"
	"strings"
)

// Node describes a native object. Its identity is independent of its directory
// entry name. Size is the logical data-fork size, including sparse ranges.
type Node struct {
	Identity Identity            `json:"identity"`
	Metadata Metadata            `json:"metadata"`
	Size     uint64              `json:"size"`
	Links    Observation[uint32] `json:"links"`
}

type DirEntry struct {
	Name   string `json:"name"`
	Object uint64 `json:"object"`
}

// Reader borrows its image for its lifetime. Operations never follow symlinks
// implicitly. Enumeration is incremental and stops when yield returns an error.
// Opened values have independent lifetimes but still borrow the image.
// Extended attributes include the resource fork under its native name.
type Reader interface {
	Root() uint64
	Stat(context.Context, uint64) (Node, error)
	ReadDir(context.Context, uint64, func(DirEntry) error) error
	// Lookup compares one component using this volume's native name rules and
	// returns the stored spelling and object identity. It never follows symlinks.
	Lookup(context.Context, uint64, string) (DirEntry, error)
	OpenData(context.Context, uint64) (Value, error)
	ListAttributes(context.Context, uint64, func(string) error) error
	OpenAttribute(context.Context, uint64, string) (Value, error)
	Readlink(context.Context, uint64) (string, error)
}

const ResourceFork = "com.apple.ResourceFork"
const FinderInfo = "com.apple.FinderInfo"

func Observed[T any](value T) Observation[T] { return Observation[T]{State: Present, Value: value} }

// Lookup resolves a path using the volume's comparison rules, independently of
// the consumer host. Symlinks are returned only as final components.
func Lookup(ctx context.Context, r Reader, path string) (uint64, error) {
	if path == "/" || path == "." {
		return r.Root(), ctx.Err()
	}
	path = strings.TrimPrefix(path, "/")
	if !fs.ValidPath(path) {
		return 0, fmt.Errorf("path %q: %w", path, fs.ErrInvalid)
	}
	id := r.Root()
	for _, component := range strings.Split(path, "/") {
		entry, err := r.Lookup(ctx, id, component)
		if err != nil {
			return 0, fmt.Errorf("lookup %q: %w", path, err)
		}
		id = entry.Object
	}
	return id, nil
}

// LookupExact resolves the exact spelling returned by ReadDir. It deliberately
// does not implement a host's case folding, Unicode normalization or symlink
// traversal. Those policies must not accidentally differ between operating systems.
func LookupExact(ctx context.Context, r Reader, path string) (uint64, error) {
	if path == "/" || path == "." {
		return r.Root(), ctx.Err()
	}
	path = strings.TrimPrefix(path, "/")
	if !fs.ValidPath(path) {
		return 0, fmt.Errorf("path %q: %w", path, fs.ErrInvalid)
	}
	id := r.Root()
	for _, component := range strings.Split(path, "/") {
		var next uint64
		err := r.ReadDir(ctx, id, func(e DirEntry) error {
			if e.Name == component {
				if next != 0 {
					return fmt.Errorf("duplicate directory name: %w", ErrCorrupt)
				}
				next = e.Object
			}
			return nil
		})
		if err != nil {
			return 0, err
		}
		if next == 0 {
			return 0, fmt.Errorf("exact path %q: %w", path, fs.ErrNotExist)
		}
		id = next
	}
	return id, nil
}
