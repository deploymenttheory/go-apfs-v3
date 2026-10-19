//go:build !unix

package fixture

import (
	"errors"
	"os"
)

// Pausing a process needs job-control signals, which only the unix hosts
// that run captures have; the package still compiles elsewhere for its
// portable unit tests.
func pauseProcess(*os.Process) error  { return errors.ErrUnsupported }
func resumeProcess(*os.Process) error { return errors.ErrUnsupported }
