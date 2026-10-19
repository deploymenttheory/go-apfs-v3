//go:build unix

package fixture

import (
	"os"
	"syscall"
)

// pauseProcess stops a running process so a volume state it is about to
// change can be pinned first; resumeProcess lets it continue.
func pauseProcess(p *os.Process) error  { return p.Signal(syscall.SIGSTOP) }
func resumeProcess(p *os.Process) error { return p.Signal(syscall.SIGCONT) }
