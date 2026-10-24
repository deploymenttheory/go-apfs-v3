package fixture

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

const imageOperationAttachPlist = `<plist version="1.0"><dict><key>system-entities</key><array><dict><key>dev-entry</key><string>/dev/disk41</string><key>content-hint</key><string>Apple_APFS</string></dict></array></dict></plist>`

type imageOperationCommander struct {
	*fakeCommander
	commands []Command
	after    func(Command)
}

func (c *imageOperationCommander) Run(ctx context.Context, cmd Command) Result {
	copy := cmd
	copy.Argv, copy.Stdin = append([]string(nil), cmd.Argv...), bytes.Clone(cmd.Stdin)
	c.commands = append(c.commands, copy)
	var result Result
	switch cmd.Label {
	case "attach-retry-image-inventory":
		result = Result{Stdout: []byte(`<plist><dict><key>images</key><array/></dict></plist>`)}
	case "ioreg-attach-retry-image-ownership", "ioreg-attach-retry-legacy-image-ownership":
		result = Result{Stdout: registryArchive()}
	case "plutil":
		if bytes.Contains(cmd.Stdin, []byte("<key>images</key>")) {
			result = Result{Stdout: []byte(`{"images":[]}`)}
		} else {
			result = c.fakeCommander.Run(ctx, cmd)
		}
	default:
		result = c.fakeCommander.Run(ctx, cmd)
	}
	if c.after != nil {
		c.after(cmd)
	}
	return result
}

func newImageOperationCommander(results ...Result) *imageOperationCommander {
	return &imageOperationCommander{fakeCommander: &fakeCommander{
		sequence: map[string][]Result{"hdiutil": results},
		results:  map[string]Result{"plutil": {Stdout: []byte(`{"system-entities":[{"dev-entry":"/dev/disk41","content-hint":"Apple_APFS"}]}`)}},
	}}
}

func (c *imageOperationCommander) attachCommands() []Command {
	var result []Command
	for _, command := range c.commands {
		if command.Label == "attach" {
			result = append(result, command)
		}
	}
	return result
}

func TestAttachRetriesBusyWithJitterAndPreservesCredentialsAndArguments(t *testing.T) {
	for _, status := range []int{16, 1} {
		t.Run(fmt.Sprintf("status-%d", status), func(t *testing.T) {
			ceilings := instantWaits(t)
			busy := Result{Status: status, Stderr: []byte("hdiutil: attach failed - Resource busy\n")}
			c := newImageOperationCommander(busy, busy, Result{Stdout: []byte(imageOperationAttachPlist)})
			d := &HostDisk{C: c, T: &Transcript{}}
			path := filepath.Join(t.TempDir(), "source image.dmg")
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			password := []byte("fixture password\n")
			a, err := d.Attach(context.Background(), path, AttachOptions{Raw: true, ReadOnly: true, NoInventory: true, Password: password})
			if err != nil || a == nil || a.Image != path || a.Dev != "/dev/disk41" || a.RDev != "/dev/rdisk41" {
				t.Fatalf("busy attach followed by a valid plist did not succeed: attachment=%+v error=%v calls=%d", a, err, len(c.attachCommands()))
			}
			calls := c.attachCommands()
			wantArgv := []string{"hdiutil", "attach", "-plist", "-nobrowse", "-noautoopen", "-owners", "on", "-nomount", "-imagekey", "diskimage-class=CRawDiskImage", "-noautofsck", "-readonly", "-stdinpass", path}
			if len(calls) != 3 || len(*ceilings) != 2 || (*ceilings)[0] != BusyWait.Base || (*ceilings)[1] != min(BusyWait.Base*2, BusyWait.Max) {
				t.Fatal("attach did not use the bounded jitter schedule", len(calls), *ceilings)
			}
			for _, call := range calls {
				if !reflect.DeepEqual(call.Argv, wantArgv) || !bytes.Equal(call.Stdin, append(bytes.Clone(password), 0)) {
					t.Fatal("retry changed attach options or exact credential bytes", call.Argv)
				}
			}
			labels := []string{}
			lastOutput := ""
			for _, command := range d.T.Commands {
				if command.Label == "attach" || command.Label == "wait:attach-busy" {
					labels = append(labels, command.Label)
				}
				if command.Label == "attach" {
					lastOutput = command.StdoutText
				}
			}
			if !reflect.DeepEqual(labels, []string{"attach", "wait:attach-busy", "attach", "wait:attach-busy", "attach"}) || d.T.Commands[0].Status != strconv.Itoa(status) || lastOutput != imageOperationAttachPlist {
				t.Fatal("attach attempts, waits or original successful stdout were lost", labels)
			}
		})
	}
}

func TestAttachStopsAtItsBusyBudget(t *testing.T) {
	ceilings := instantWaits(t)
	queue := make([]Result, BusyWait.Attempts)
	for i := range queue {
		queue[i] = Result{Status: 16, Stderr: []byte("hdiutil: attach failed - Resource busy")}
	}
	queue = append(queue, Result{Stdout: []byte(imageOperationAttachPlist)})
	c := newImageOperationCommander(queue...)
	d := &HostDisk{C: c, T: &Transcript{}}
	a, err := d.Attach(context.Background(), detachImage(t, t.TempDir()), AttachOptions{NoInventory: true})
	var unsettled *NotSettledError
	wantCeilings := []time.Duration{250 * time.Millisecond, 500 * time.Millisecond, time.Second, 2 * time.Second, 2 * time.Second}
	if a != nil || !errors.As(err, &unsettled) || unsettled.Checks != 6 || !strings.Contains(err.Error(), "Resource busy") || len(c.attachCommands()) != 6 || !reflect.DeepEqual(*ceilings, wantCeilings) {
		t.Fatalf("busy attach did not stop at its declared budget: attachment=%+v error=%v calls=%d waits=%v", a, err, len(c.attachCommands()), *ceilings)
	}
}

func TestAttachCancellationPreventsCommandsAndPreservesPriorBusyFailure(t *testing.T) {
	t.Run("before command", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		c := newImageOperationCommander(Result{Stdout: []byte(imageOperationAttachPlist)})
		d := &HostDisk{C: c, T: &Transcript{}}
		a, err := d.Attach(ctx, detachImage(t, t.TempDir()), AttachOptions{NoInventory: true})
		if a != nil || !errors.Is(err, context.Canceled) || len(c.commands) != 0 {
			t.Fatalf("cancelled attach ran a native command or lost cancellation: attachment=%+v error=%v calls=%d", a, err, len(c.commands))
		}
	})
	t.Run("during busy wait", func(t *testing.T) {
		instantWaits(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		sleep = func(ctx context.Context, _ time.Duration) error { cancel(); return ctx.Err() }
		c := newImageOperationCommander(Result{Status: 16, Stderr: []byte("hdiutil: attach failed - Resource busy")}, Result{Stdout: []byte(imageOperationAttachPlist)})
		d := &HostDisk{C: c, T: &Transcript{}}
		a, err := d.Attach(ctx, detachImage(t, t.TempDir()), AttachOptions{NoInventory: true})
		if a != nil || !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "Resource busy") || len(c.attachCommands()) != 1 {
			t.Fatalf("wait cancellation retried or lost its original cause: attachment=%+v error=%v calls=%d", a, err, len(c.attachCommands()))
		}
	})
	t.Run("failed cancelled command", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		cause := errors.New("native command launch failed")
		c := newImageOperationCommander(Result{Status: -1, Err: cause})
		c.after = func(cmd Command) {
			if cmd.Label == "attach" {
				cancel()
			}
		}
		d := &HostDisk{C: c, T: &Transcript{}}
		a, err := d.Attach(ctx, detachImage(t, t.TempDir()), AttachOptions{NoInventory: true})
		if a != nil || !errors.Is(err, cause) || !errors.Is(err, context.Canceled) || len(c.attachCommands()) != 1 {
			t.Fatalf("cancelled failed attach lost a cause or retried: attachment=%+v error=%v", a, err)
		}
	})
}

func TestAttachNeverRetriesPermanentOrCommandFailures(t *testing.T) {
	cause := errors.New("launch failed: Resource busy")
	for name, failure := range map[string]Result{
		"no space":               {Status: 1, Stderr: []byte("hdiutil: attach failed - No space left on device")},
		"authentication":         {Status: 1, Stderr: []byte("hdiutil: attach failed - Authentication error")},
		"io mentioning busy":     {Status: 1, Stderr: []byte("hdiutil: attach failed - Input/output error (Resource busy)")},
		"launch mentioning busy": {Status: 16, Err: cause, Stderr: []byte("Resource busy")},
	} {
		t.Run(name, func(t *testing.T) {
			ceilings := instantWaits(t)
			c := newImageOperationCommander(failure, Result{Stdout: []byte(imageOperationAttachPlist)})
			d := &HostDisk{C: c, T: &Transcript{}}
			a, err := d.Attach(context.Background(), detachImage(t, t.TempDir()), AttachOptions{NoInventory: true})
			if a != nil || err == nil || len(c.attachCommands()) != 1 || len(*ceilings) != 0 || failure.Err != nil && !errors.Is(err, cause) {
				t.Fatal("permanent failure retried or lost its cause", a, err, len(c.attachCommands()), *ceilings)
			}
		})
	}
}

func TestAttachPartialOutputAndParserFailuresCannotReplayAnAttachment(t *testing.T) {
	t.Run("busy with possible attached device", func(t *testing.T) {
		ceilings := instantWaits(t)
		c := newImageOperationCommander(Result{Status: 16, Stdout: []byte(imageOperationAttachPlist), Stderr: []byte("hdiutil: attach failed - Resource busy")}, Result{Stdout: []byte(imageOperationAttachPlist)})
		d := &HostDisk{C: c, T: &Transcript{}}
		a, err := d.Attach(context.Background(), detachImage(t, t.TempDir()), AttachOptions{NoInventory: true})
		if a != nil || err == nil || len(c.attachCommands()) != 1 || len(*ceilings) != 0 || d.T.Commands[0].StdoutText != imageOperationAttachPlist {
			t.Fatal("partial attach result was replayed or its original evidence lost", a, err)
		}
	})
	t.Run("successful command with failed plist", func(t *testing.T) {
		ceilings := instantWaits(t)
		cause := errors.New("plist conversion failed: Resource busy")
		c := newImageOperationCommander(Result{Stdout: []byte("malformed original plist")}, Result{Stdout: []byte(imageOperationAttachPlist)})
		c.results["plutil"] = Result{Status: -1, Err: cause}
		d := &HostDisk{C: c, T: &Transcript{}}
		a, err := d.Attach(context.Background(), detachImage(t, t.TempDir()), AttachOptions{NoInventory: true})
		if a != nil || !errors.Is(err, cause) || len(c.attachCommands()) != 1 || len(*ceilings) != 0 {
			t.Fatal("parser failure repeated the successful native attach", a, err)
		}
	})
}
