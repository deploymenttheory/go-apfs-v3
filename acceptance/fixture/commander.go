package fixture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// Command is one program invocation.
type Command struct {
	Label   string
	Argv    []string
	Stdin   []byte
	Sudo    bool
	Timeout time.Duration
	// Expected is "0", another exit status, or "record".
	Expected string
}

// Result is what the program did.
type Result struct {
	Status   int
	Stdout   []byte
	Stderr   []byte
	Err      error // timeout or launch failure
	Duration time.Duration
}

// Commander runs programs. The real implementation is Exec; tests use a
// fake. Every call is appended to the Transcript the interpreter owns.
type Commander interface {
	Run(ctx context.Context, cmd Command) Result
}

// DefaultTimeout bounds every command that does not declare its own.
const DefaultTimeout = 120 * time.Second

// programPaths resolves Apple programs that are not on PATH, especially
// under sudo's restricted search path.
var programPaths = map[string]string{
	"apfs.util":  "/System/Library/Filesystems/apfs.fs/Contents/Resources/apfs.util",
	"fsck_apfs":  "/System/Library/Filesystems/apfs.fs/Contents/Resources/fsck_apfs",
	"mount_apfs": "/System/Library/Filesystems/apfs.fs/Contents/Resources/mount_apfs",
	"newfs_hfs":  "/sbin/newfs_hfs",
	"newfs_apfs": "/sbin/newfs_apfs",
	"fsck_hfs":   "/sbin/fsck_hfs",
	"mount_hfs":  "/sbin/mount_hfs",
	"umount":     "/sbin/umount",
	"asr":        "/usr/sbin/asr",
}

// ResolveProgram returns the absolute path for a known Apple program.
func ResolveProgram(name string) string {
	if path, ok := programPaths[name]; ok {
		return path
	}
	return name
}

// Exec runs programs on the host.
type Exec struct{}

// Run executes the command with its deadline. Sudo prefixes sudo -n so a
// password prompt can never hang a capture.
func (Exec) Run(ctx context.Context, cmd Command) Result {
	timeout := cmd.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	argv := append([]string(nil), cmd.Argv...)
	argv[0] = ResolveProgram(argv[0])
	if cmd.Sudo {
		argv = append([]string{"sudo", "-n", "--preserve-env=GITHUB_ACTIONS,RUNNER_ENVIRONMENT,APFS_NATIVE_DISPOSABLE_VM"}, argv...)
	}
	c := exec.CommandContext(ctx, argv[0], argv[1:]...)
	if cmd.Stdin != nil {
		c.Stdin = bytes.NewReader(cmd.Stdin)
	}
	var stdout, stderr bytes.Buffer
	c.Stdout, c.Stderr = &stdout, &stderr
	start := time.Now()
	err := c.Run()
	result := Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), Duration: time.Since(start)}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		result.Status = 0
	case errors.As(err, &exitErr):
		result.Status = exitErr.ExitCode()
		if ctx.Err() != nil {
			result.Err = fmt.Errorf("timeout after %s", timeout)
		}
	default:
		result.Err = err
		result.Status = -1
	}
	return result
}

// Transcript accumulates every command of one case in order and refuses to
// continue after an unexpected outcome.
type Transcript struct {
	Commands []schema.Command
}

// Record converts a result into a transcript entry and reports whether the
// outcome matched the expectation.
func (t *Transcript) Record(cmd Command, result Result) error {
	entry := schema.Command{
		Label:    cmd.Label,
		Argv:     append([]string(nil), cmd.Argv...),
		Sudo:     cmd.Sudo,
		Expected: cmd.Expected,
		WallNS:   result.Duration.Nanoseconds(),
	}
	switch {
	case result.Err != nil && strings.HasPrefix(result.Err.Error(), "timeout"):
		entry.Status = "timeout"
	case result.Err != nil:
		entry.Status = "launch-failed"
	default:
		entry.Status = strconv.Itoa(result.Status)
	}
	stdoutLimit := retainedTextLimit
	if isAPFSListPlist(cmd.Argv) {
		stdoutLimit = retainedAPFSListingTextLimit
	}
	if isImageInventoryPlist(cmd.Argv) {
		stdoutLimit = retainedImageInventoryTextLimit
	}
	entry.StdoutSHA256, entry.StdoutText = digestAndTextLimit(result.Stdout, stdoutLimit)
	entry.StderrSHA256, entry.StderrText = digestAndText(result.Stderr)
	t.Commands = append(t.Commands, entry)
	if result.Err != nil {
		return fmt.Errorf("%s: %s: %w", strings.Join(cmd.Argv, " "), entry.Status, result.Err)
	}
	if cmd.Expected == "record" {
		return nil
	}
	want, err := strconv.Atoi(cmd.Expected)
	if err != nil {
		return fmt.Errorf("%s: invalid expectation %q", strings.Join(cmd.Argv, " "), cmd.Expected)
	}
	if result.Status != want {
		return fmt.Errorf("%s: exit %d, expected %d: %s", strings.Join(cmd.Argv, " "), result.Status, want, strings.TrimSpace(string(result.Stderr)))
	}
	return nil
}

// RecordFS appends a filesystem operation outcome, which has no program.
func (t *Transcript) RecordFS(label string, argv []string, err error, expected string) error {
	entry := schema.Command{Label: label, Argv: argv, Expected: expected, Status: "0"}
	if err != nil {
		entry.Status = "1"
		var errno syscall.Errno
		if errors.As(err, &errno) {
			entry.Errno = errnoName(errno)
		} else {
			entry.StderrText = err.Error()
		}
	}
	t.Commands = append(t.Commands, entry)
	switch expected {
	case "", "0":
		if err != nil {
			return fmt.Errorf("%s: %w", strings.Join(argv, " "), err)
		}
	case "record":
	default:
		if entry.Errno != expected {
			return fmt.Errorf("%s: got %s %v, expected %s", strings.Join(argv, " "), entry.Errno, err, expected)
		}
	}
	return nil
}

const retainedTextLimit = 16 << 10

// Global APFS inventories include concurrently attached containers and remain
// verdict evidence after the command returns. Keep their complete bounded text;
// truncation would leave a digest that no inventory reader could interpret.
const retainedAPFSListingTextLimit = 8 << 20

// Busy-detach ownership evidence must remain interpretable even when parallel
// native lanes make hdiutil's global image inventory larger than ordinary logs.
const retainedImageInventoryTextLimit = 8 << 20

func isImageInventoryPlist(argv []string) bool {
	return len(argv) == 3 && filepath.Base(argv[0]) == "hdiutil" && argv[1] == "info" && argv[2] == "-plist"
}

func isAPFSListPlist(argv []string) bool {
	return (len(argv) == 4 || len(argv) == 5) && filepath.Base(argv[0]) == "diskutil" && argv[1] == "apfs" && argv[2] == "list" && argv[3] == "-plist"
}

func digestAndText(data []byte) (string, string) {
	return digestAndTextLimit(data, retainedTextLimit)
}

func digestAndTextLimit(data []byte, limit int) (string, string) {
	if len(data) == 0 {
		return "", ""
	}
	sum := sha256.Sum256(data)
	if len(data) <= limit && utf8.Valid(data) && !bytes.ContainsRune(data, 0) {
		return hex.EncodeToString(sum[:]), string(data)
	}
	return hex.EncodeToString(sum[:]), ""
}
