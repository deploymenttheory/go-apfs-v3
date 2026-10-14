//go:build !windows

package block

import "os"

// Extending a newly created file provides zero-filled regions without writes.
func prepareStaging(_ *os.File) (bool, error) {
	return true, nil
}

func extendStaging(f *os.File, _, to int64) error {
	return f.Truncate(to)
}
