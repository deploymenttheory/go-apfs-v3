package native

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

type hostImportObservationVolume struct {
	*fixture.MemoryVolume
	aclErr   error
	aclReads int
}

func (v *hostImportObservationVolume) ACL(name string) ([]byte, error) {
	v.aclReads++
	if filepath.Base(name) == "observed" && v.aclErr != nil {
		return nil, v.aclErr
	}
	return v.MemoryVolume.ACL(name)
}

// All disk methods below are fakes over ordinary bytes and MemoryVolume.
// The real observer and continuation run; no native program/device is used.
type hostImportObservationDisk struct {
	continuationCommandDisk
	root string
}

func (d *hostImportObservationDisk) Attach(_ context.Context, image string, _ fixture.AttachOptions) (*fixture.Attachment, error) {
	d.record("attach", "0")
	return &fixture.Attachment{Image: image, Dev: "/dev/host-observation", RDev: "/dev/host-observation-raw", Volumes: []*fixture.AttachedVolume{{Name: "Host Imports", Dev: "/dev/host-observation-volume", RDev: "/dev/host-observation-volume-raw", FS: "hfs", UUID: "HOST-OBSERVATION"}}}, nil
}

func (d *hostImportObservationDisk) Imageinfo(context.Context, string, []byte) (map[string]any, error) {
	d.record("imageinfo", "0")
	return map[string]any{}, nil
}

func (d *hostImportObservationDisk) Info(context.Context, string) (map[string]any, error) {
	d.record("info", "0")
	return map[string]any{"FilesystemType": "hfs", "FilesystemName": "HFS+", "VolumeName": "Host Imports", "VolumeUUID": "HOST-OBSERVATION", "TotalSize": 512}, nil
}

func (d *hostImportObservationDisk) List(context.Context, string) (map[string]any, error) {
	d.record("list", "0")
	return map[string]any{}, nil
}

func (d *hostImportObservationDisk) ReadRange(context.Context, string, int64, int) ([]byte, error) {
	d.record("read-header", "0")
	header := make([]byte, 512)
	copy(header, "H+")
	return header, nil
}

func (d *hostImportObservationDisk) Mount(_ context.Context, volume *fixture.AttachedVolume, _, _ string, _ bool) error {
	d.record("mount", "0")
	volume.Mount = d.root
	return nil
}

func (d *hostImportObservationDisk) Detach(context.Context, *fixture.Attachment) error {
	d.detaches++
	status := "0"
	if d.detachErr != nil {
		status = "1"
	}
	d.record("detach", status)
	return d.detachErr
}

func (d *hostImportObservationDisk) Fsck(context.Context, string, string) (string, error) {
	d.record("fsck", "0")
	return "ordinary fake checker receipt", nil
}

type hostImportObservationCommander struct{ volume *fixture.MemoryVolume }

func (c hostImportObservationCommander) Run(_ context.Context, command fixture.Command) fixture.Result {
	args := command.Argv
	var err error
	switch args[0] {
	case "ditto":
		source, destination := args[len(args)-2], args[len(args)-1]
		err = filepath.WalkDir(source, func(name string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			rel, err := filepath.Rel(source, name)
			if err != nil {
				return err
			}
			target := filepath.Join(destination, rel)
			if entry.IsDir() {
				return c.volume.MkdirAll(target)
			}
			data, err := os.ReadFile(name)
			if err != nil {
				return err
			}
			return c.volume.WriteFile(target, data, true)
		})
	case "ln":
		err = c.volume.Link(args[1], args[2])
	case "mv":
		err = c.volume.Rename(args[1], args[2])
	case "rm":
		err = c.removeTree(args[len(args)-1])
	default:
		err = fmt.Errorf("unexpected fake continuation command %v", args)
	}
	if err != nil {
		return fixture.Result{Status: 1, Err: err}
	}
	return fixture.Result{}
}

func (c hostImportObservationCommander) removeTree(name string) error {
	stat, err := c.volume.Lstat(name)
	if err != nil {
		return err
	}
	if stat.Kind != "dir" {
		return c.volume.Remove(name)
	}
	names, err := c.volume.Readdir(name)
	if err != nil {
		return err
	}
	for _, child := range names {
		if err := c.removeTree(filepath.Join(name, child)); err != nil {
			return err
		}
	}
	return c.volume.Rmdir(name)
}

func hostImportObservationControl(t *testing.T, aclErr, detachErr error) (*Verifier, *hostImportObservationDisk, *hostImportObservationVolume, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "in-memory-volume")
	volume := &hostImportObservationVolume{MemoryVolume: fixture.NewMemoryVolume(root), aclErr: aclErr}
	if err := volume.WriteFile(filepath.Join(root, "observed"), []byte("ordinary observation control"), true); err != nil {
		t.Fatal(err)
	}
	disk := &hostImportObservationDisk{root: root}
	disk.detachErr = detachErr
	verifier := &Verifier{Work: t.TempDir(), Disk: disk, Vol: &hostImportVolume{Volume: volume}, C: hostImportObservationCommander{volume.MemoryVolume}, Product: filepath.Join(t.TempDir(), "must-not-run")}
	return verifier, disk, volume, failedObservationInput(t)
}

func TestHostImportObservationNeverTurnsACLReadFailureIntoAbsence(t *testing.T) {
	for _, test := range []struct {
		name    string
		aclErr  error
		cleanup error
	}{
		{name: "known-absence"},
		{name: "failed-acl", aclErr: errors.New("no-follow native ACL read failed")},
		{name: "failed-acl-and-cleanup", aclErr: errors.New("no-follow native ACL read failed"), cleanup: errors.New("native release refused")},
	} {
		t.Run(test.name, func(t *testing.T) {
			v, disk, volume, image := hostImportObservationControl(t, test.aclErr, test.cleanup)
			observation, cleanup, err := v.observeImageWithCleanup(context.Background(), "host-import-readback", image, "raw", nil, schema.ObserveSpec{}, schema.Recipe{Name: "host-import"}, false)
			if disk.detaches != 1 || volume.aclReads != 1 || !errors.Is(cleanup, test.cleanup) {
				t.Fatalf("observation or checked normal release changed: aclReads=%d detaches=%d cleanup=%v", volume.aclReads, disk.detaches, cleanup)
			}
			if test.aclErr == nil {
				if err != nil || observation == nil || len(observation.Views) != 1 || len(observation.Views[0].Entries) != 1 || observation.Views[0].Entries[0].ACL != "" {
					t.Fatalf("actual ACL absence was refused: %v %+v", err, observation)
				}
				return
			}
			if observation != nil || !errors.Is(err, test.aclErr) || test.cleanup != nil && !errors.Is(err, test.cleanup) {
				t.Fatalf("failed ACL observation became absent or lost cleanup: observation=%+v error=%v", observation, err)
			}
			commands := recordedCommands(t, filepath.Join(v.Work, "observe", "host-import-readback", "observation-commands.json"))
			if len(commands) < 4 || commands[0].Label != "attach" || commands[len(commands)-1].Label != "detach" {
				t.Fatal("failed observation lost its real observer and cleanup receipts", commands)
			}
		})
	}
}

func TestHostImportContinuationACLFailureRetainsScratchAndCompleteCommands(t *testing.T) {
	cause := errors.New("native ACL read cannot establish absence")
	v, disk, volume, image := hostImportObservationControl(t, cause, nil)
	ref := schema.CaseRef{Producer: 26, Recipe: "workspace-edits", Profile: "hfsplus", Stage: "before"}
	output := schema.Output{Name: "observed-host.build.UDZO.dmg", File: filepath.Base(image), Source: ref, Format: "UDZO", Operation: "build"}
	v.Cases = map[string]corpus.Case{CaseKey(ref): {Observation: &schema.Observation{}}}
	pair := Paired{Name: output.Name, Output: output, Primary: "darwin", Dirs: map[string]string{"darwin": filepath.Dir(image)}, ByHost: map[string]schema.Output{"darwin": output}}
	observation, err := v.Continuation(context.Background(), pair, schemaCase{recipe: schema.Recipe{Name: "workspace-edits"}})
	if observation != nil || !errors.Is(err, cause) || strings.Contains(err.Error(), "product edit:") {
		t.Fatalf("continuation advanced beyond the failed ACL observation: observation=%+v error=%v", observation, err)
	}
	if volume.aclReads == 0 || disk.detaches != 4 {
		t.Fatalf("continuation did not reach actual observation or release all four attachments: ACL reads=%d detaches=%d", volume.aclReads, disk.detaches)
	}
	work := filepath.Join(v.Work, "continuation", sanitize(output.Name))
	if raw, err := os.ReadFile(filepath.Join(work, "writable.raw")); err != nil || len(raw) != 512 {
		t.Fatalf("failed continuation removed its private ordinary-byte control: %d bytes, %v", len(raw), err)
	}
	if _, err := os.Stat(filepath.Join(work, "go-payload")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("product continuation was prepared after an unqualified ACL observation", err)
	}
	commands := recordedCommands(t, filepath.Join(work, "continuation-commands.json"))
	labels := map[string]int{}
	for _, command := range commands {
		labels[command.Label]++
	}
	if len(commands) < 10 || commands[len(commands)-1].Label != "detach" || labels["attach"] != 4 || labels["detach"] != 4 || labels["fsck"] != 1 {
		t.Fatal("failed ACL read lost original continuation phase/close receipts", labels)
	}
}
