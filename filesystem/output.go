package filesystem

import "fmt"

// PublishedOutputError means a completed output is already visible despite an
// error. Retain it; retrying publication at the same path cannot replace it.
// Persisted says all flushes supported by this host completed. Windows flushes
// the file; Unix also flushes the directory. It is not a hardware power-loss
// guarantee or a Windows directory-entry persistence guarantee.
type PublishedOutputError struct {
	Path      string
	Persisted bool
	Err       error
}

func (e *PublishedOutputError) Error() string {
	if !e.Persisted {
		return fmt.Sprintf("completed output published at %s; directory persistence not confirmed: %v", e.Path, e.Err)
	}
	return fmt.Sprintf("completed output published at %s; cleanup failed: %v", e.Path, e.Err)
}
func (e *PublishedOutputError) Unwrap() error { return e.Err }
