//go:build !windows

package corpus

import "os"

// Unix filesystems leave unwritten ranges unallocated without a flag.
func markSparse(*os.File) error { return nil }
