//go:build !windows

package block

import "os"

// Extending a newly created file provides zero-filled regions without writes.
func prepareStaging(f *os.File, size int64) (bool, error) {
	return true, f.Truncate(size)
}
