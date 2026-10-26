package fixture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Fake command results reproduce the captured six busy detaches. Binary bytes
// and a reused buffer additionally test whether the action evidence is frozen
// before later ownership queries or failure probes can overwrite it.
type detachActionCommander struct {
	mu       sync.Mutex
	image    string
	calls    []Command
	actions  int
	buffer   []byte
	expected [][]byte
}

func (c *detachActionCommander) Run(_ context.Context, cmd Command) Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, cmd)
	for i := range c.buffer {
		c.buffer[i] = 0xee
	}
	if cmd.Label == "detach" {
		c.actions++
		c.buffer = bytes.Repeat([]byte{byte(c.actions), 0, 0xff, '\r', '\n'}, 4000)
		c.expected = append(c.expected, bytes.Clone(c.buffer))
		return Result{Status: 16, Stdout: c.buffer, Stderr: []byte(fmt.Sprintf("hdiutil: couldn't eject \"disk42\" - Resource busy (request %d)\r\n", c.actions)), Duration: 24 * time.Hour}
	}
	if cmd.Argv[0] == "plutil" {
		return Result{Stdout: bytes.Clone(cmd.Stdin)}
	}
	if cmd.Argv[0] == "/usr/sbin/ioreg" {
		return Result{Stdout: registryArchive()}
	}
	if cmd.Argv[0] == "/usr/sbin/lsof" {
		return Result{Status: 1}
	}
	if cmd.Argv[0] == "/bin/ps" {
		return Result{Stdout: []byte("123 1 synthetic-backend\n")}
	}
	if cmd.Argv[0] == "/usr/bin/log" {
		return Result{Stdout: []byte("{\"finished\":true}\n")}
	}
	var value any
	if cmd.Argv[0] == "diskutil" {
		value = map[string]any{"DeviceNode": cmd.Argv[len(cmd.Argv)-1], "Mounted": false, "MountPoint": ""}
	} else {
		owner := attachedImage(c.image, "/dev/disk42")
		owner["hdid-pid"] = 123
		value = map[string]any{"images": []any{owner}}
	}
	b, err := json.Marshal(value)
	return Result{Stdout: b, Err: err}
}

func TestBusyDetachRetainsEveryActionIncludingFinalNormalEject(t *testing.T) {
	instantWaits(t)
	image := detachImage(t, t.TempDir())
	c := &detachActionCommander{image: image}
	d := imageTestDisk(c)
	started := time.Now()
	err := d.Detach(context.Background(), &Attachment{Image: image, Dev: "/dev/disk42"})
	returned := time.Now()
	var busy *NotSettledError
	if !errors.As(err, &busy) || busy.Checks != 6 || c.actions != 6 || !strings.Contains(err.Error(), "request 6") {
		t.Fatalf("diagnostics changed the original six-request busy verdict: %v; requests=%d", err, c.actions)
	}
	var receipt struct {
		ReceiptCommand int
		Actions        []struct {
			Command, Status   int
			Started, Returned string
			Stdout, Stderr    attachmentDiagnosticStream
		}
	}
	last := d.T.Commands[len(d.T.Commands)-1]
	if last.Label != "busy-detach-evidence" || json.Unmarshal([]byte(last.StdoutText), &receipt) != nil {
		t.Fatal("busy diagnostic receipt cannot be reconstructed")
	}
	if len(receipt.Actions) != 6 {
		t.Fatalf("busy receipt retained %d action results; want all six original raw results before diagnostic probes", len(receipt.Actions))
	}
	for i, action := range receipt.Actions {
		command := d.T.Commands[action.Command]
		wantArgs := []string{"hdiutil", "detach", "/dev/disk42"}
		if i != 0 {
			wantArgs = []string{"hdiutil", "detach", "-debug", "/dev/disk42"}
		}
		if i == BusyWait.Attempts-1 {
			wantArgs = []string{"diskutil", "eject", "/dev/disk42"}
		}
		if !reflect.DeepEqual(command.Argv, wantArgs) || command.Status != "16" || action.Status != 16 {
			t.Fatalf("request %d changed action or status: %+v", i+1, command)
		}
		if !bytes.Equal(action.Stdout.Data, c.expected[i]) || action.Stdout.Bytes != len(c.expected[i]) || action.Stdout.SHA256 != command.StdoutSHA256 || action.Stdout.StoredSHA256 != action.Stdout.SHA256 {
			t.Fatalf("request %d lost binary bytes, full digest or buffer independence", i+1)
		}
		wantErr := []byte("hdiutil: couldn't eject \"disk42\" - Resource busy (request " + strconv.Itoa(i+1) + ")\r\n")
		if !bytes.Equal(action.Stderr.Data, wantErr) || action.Stderr.SHA256 != command.StderrSHA256 {
			t.Fatalf("request %d lost original busy stderr", i+1)
		}
		before, e1 := time.Parse(time.RFC3339Nano, action.Started)
		after, e2 := time.Parse(time.RFC3339Nano, action.Returned)
		if e1 != nil || e2 != nil || before.Before(started) || after.Before(before) || after.After(returned) {
			t.Fatalf("request %d does not record actual caller invocation/return bounds: %+v", i+1, action)
		}
	}
}
