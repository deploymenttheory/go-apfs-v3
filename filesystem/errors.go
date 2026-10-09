// Package filesystem defines the contracts shared by Apple filesystem engines.
// It does not perform host authorization or infer missing macOS metadata.
package filesystem

import (
	"errors"
	"fmt"
)

var (
	ErrCorrupt        = errors.New("corrupt filesystem or image")
	ErrUnsupported    = errors.New("unsupported feature")
	ErrLimit          = errors.New("resource limit exceeded")
	ErrAuthentication = errors.New("authentication required or failed")
	ErrConflict       = errors.New("source changed or conflicting operation")
)

// Error retains the operation, on-disk structure and byte offset of a failure.
// Offset is relative to the source supplied to the failing engine.
type Error struct {
	Op        string
	Structure string
	Offset    int64
	Err       error
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s %s at %#x: %v", e.Op, e.Structure, e.Offset, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }
