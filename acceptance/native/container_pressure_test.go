package native

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// containerPressureDisk makes the complete clean boundary a prerequisite for
// ordinary writes, without modeling or claiming APFS pending-free retirement.
type containerPressureDisk struct {
	fixture.Disk
	volume           *pressureProtocolVolume
	originals        []fixture.AttachedVolume
	events           []string
	fail             string
	changeAttachment func(*fixture.Attachment)
	changeRemount    func() error
	mounted          int
	closedVolumes    int
}

var containerPressureLifecycle = []string{
	"detach writable", "attach read-only", "fsck", "detach read-only", "attach writable",
	"mount Fresh Empty", "mount Empty", "mount Limited", "mount Reserved",
}

func newContainerPressureDisk(att *fixture.Attachment, volume *pressureProtocolVolume) *containerPressureDisk {
	att.Dev = "original"
	d := &containerPressureDisk{volume: volume}
	for _, vol := range att.Volumes {
		d.originals = append(d.originals, *vol)
	}
	return d
}

func (d *containerPressureDisk) step(event string) error {
	d.events = append(d.events, event)
	i := len(d.events) - 1
	if i >= len(containerPressureLifecycle) || containerPressureLifecycle[i] != event {
		return fmt.Errorf("unexpected lifecycle event %q at %d", event, i)
	}
	if event == d.fail {
		return syscall.EIO
	}
	return nil
}

func (d *containerPressureDisk) Unmount(context.Context, *fixture.AttachedVolume) error {
	return fmt.Errorf("pressure boundary used an individual unmount instead of a normal whole-image detach")
}

func (d *containerPressureDisk) Detach(_ context.Context, att *fixture.Attachment) error {
	mode := "writable"
	if att.Dev == "read-only" {
		mode = "read-only"
	} else {
		if !d.volume.quotaReached || !d.volume.pressureReached || !d.volume.protectedSynced || len(d.volume.pending) != 0 {
			return fmt.Errorf("clean close preceded required pressure and truncation checks")
		}
		for _, vol := range att.Volumes {
			if vol.Mount == "" {
				return fmt.Errorf("volume %q was closed before whole-image detach", vol.Name)
			}
		}
	}
	if err := d.step("detach " + mode); err != nil {
		return err
	}
	if mode == "writable" {
		for _, vol := range att.Volumes {
			vol.Mount = ""
			d.closedVolumes++
		}
	}
	return nil
}

func (d *containerPressureDisk) Attach(_ context.Context, path string, opts fixture.AttachOptions) (*fixture.Attachment, error) {
	if path != "writable.raw" || !opts.Raw || opts.Mount {
		return nil, fmt.Errorf("boundary changed image or attachment policy")
	}
	if opts.ReadOnly {
		if err := d.step("attach read-only"); err != nil {
			return nil, err
		}
		return &fixture.Attachment{Dev: "read-only", RDev: "read-only-rdev"}, nil
	}
	if err := d.step("attach writable"); err != nil {
		return nil, err
	}
	att := &fixture.Attachment{Image: path, Dev: "fresh", RDev: "fresh-rdev"}
	// Discovery order and device identifiers may change across attachments.
	for i := len(d.originals) - 1; i >= 0; i-- {
		volume := d.originals[i]
		volume.Mount, volume.Dev, volume.RDev = "", "fresh-"+volume.Name, "fresh-r"+volume.Name
		att.Volumes = append(att.Volumes, &volume)
	}
	if d.changeAttachment != nil {
		d.changeAttachment(att)
	}
	return att, nil
}

func (d *containerPressureDisk) Fsck(_ context.Context, fs, rdev string) (string, error) {
	if fs != "apfs" || rdev != "read-only-rdev" {
		return "", fmt.Errorf("filesystem check did not use the read-only raw device")
	}
	return "", d.step("fsck")
}

func (d *containerPressureDisk) Mount(_ context.Context, vol *fixture.AttachedVolume, options, dir string, readOnly bool) error {
	if options != "owners,noatime" || readOnly || !strings.HasPrefix(vol.Dev, "fresh-") || dir != filepath.Join("/container", vol.Name) {
		return fmt.Errorf("remount used stale volume or different mount policy")
	}
	if err := d.step("mount " + vol.Name); err != nil {
		return err
	}
	vol.Mount = dir
	d.mounted++
	if d.mounted == len(d.originals) {
		d.volume.boundaryComplete = true
		if d.changeRemount != nil {
			return d.changeRemount()
		}
	}
	return nil
}

func TestContainerPressureRequiresEveryCleanBoundaryOperation(t *testing.T) {
	for i, operation := range containerPressureLifecycle {
		t.Run(operation, func(t *testing.T) {
			v, att, out, volume := containerPressureProtocol(t)
			disk := v.Disk.(*containerPressureDisk)
			disk.fail = operation
			current, err := v.containerWrites(context.Background(), att, out, "writable.raw")
			if !errors.Is(err, syscall.EIO) || !strings.Contains(err.Error(), "pressure boundary") || volume.peerWrites != 0 {
				t.Fatalf("failed boundary reached peer writes or lost its cause: %v, peers=%d", err, volume.peerWrites)
			}
			// A failed fsck still requires one terminal read-only detach.
			end := i + 1
			if operation == "fsck" {
				end++
			}
			if !reflect.DeepEqual(disk.events, containerPressureLifecycle[:end]) {
				t.Fatalf("failed boundary retried or continued: %v", disk.events)
			}
			if operation == "detach writable" && (current != nil || disk.closedVolumes != 0) {
				t.Fatal("failed whole-image detach was treated as closed or eligible for another detach")
			}
		})
	}
}

func TestContainerPressureRejectsChangedVolumeIdentityBeforeRemount(t *testing.T) {
	for _, change := range []string{"missing", "duplicate name", "duplicate UUID", "empty UUID", "UUID", "name", "filesystem", "role", "locked"} {
		t.Run(change, func(t *testing.T) {
			v, att, out, volume := containerPressureProtocol(t)
			disk := v.Disk.(*containerPressureDisk)
			disk.changeAttachment = func(att *fixture.Attachment) {
				switch change {
				case "missing":
					att.Volumes = att.Volumes[1:]
				case "duplicate name":
					att.Volumes[0].Name = att.Volumes[1].Name
				case "duplicate UUID":
					att.Volumes[0].UUID = att.Volumes[1].UUID
				case "empty UUID":
					att.Volumes[0].UUID = ""
				case "UUID":
					att.Volumes[0].UUID = "unexpected"
				case "name":
					att.Volumes[0].Name = "unexpected"
				case "filesystem":
					att.Volumes[0].FS = "hfs"
				case "role":
					att.Volumes[0].Role = "System"
				case "locked":
					att.Volumes[0].Locked = true
				}
			}
			if _, err := v.containerWrites(context.Background(), att, out, "writable.raw"); err == nil || volume.peerWrites != 0 || disk.mounted != 0 {
				t.Fatalf("changed inventory reached remount or peers: %v, mounts=%d, peers=%d", err, disk.mounted, volume.peerWrites)
			}
		})
	}
}

func TestContainerPressureVerifiesDurableRemovalAndOriginalProofBeforePeers(t *testing.T) {
	for _, change := range []string{"quota pressure remains", "unreserved pressure remains", "proof missing", "proof corrupt", "proof truncated", "proof replaced", "proof metadata", "proof unallocated"} {
		t.Run(change, func(t *testing.T) {
			v, att, out, volume := containerPressureProtocol(t)
			disk := v.Disk.(*containerPressureDisk)
			disk.changeRemount = func() error {
				proof := filepath.Join("/container", "Reserved", filepath.FromSlash(reservationProofPath))
				switch change {
				case "quota pressure remains", "unreserved pressure remains":
					name := "Limited"
					if change == "unreserved pressure remains" {
						name = "Fresh Empty"
					}
					return volume.Volume.WriteFile(filepath.Join("/container", name, "container-continuation", "pressure"), nil, true)
				case "proof missing":
					return volume.Volume.Remove(proof)
				case "proof corrupt":
					return volume.Pwrite(proof, 0, []byte{0})
				case "proof truncated":
					return volume.Volume.Truncate(proof, 1)
				case "proof replaced":
					if err := volume.Volume.Remove(proof); err != nil {
						return err
					}
					return volume.Volume.WriteFile(proof, reservationProofData(), true)
				case "proof metadata":
					return volume.Lchmod(proof, 0o600)
				case "proof unallocated":
					volume.unallocatedProof = true
				}
				return nil
			}
			if _, err := v.containerWrites(context.Background(), att, out, "writable.raw"); err == nil || volume.peerWrites != 0 {
				t.Fatalf("changed remount state reached peers: %v, peers=%d", err, volume.peerWrites)
			}
		})
	}
}

func TestVolumeGroupPeersDoNotUseContainerPressureBoundary(t *testing.T) {
	v, att, out, volume := containerPressureProtocol(t)
	v.Disk = nil
	out.Source.Recipe = "volume-groups"
	got, err := v.containerWrites(context.Background(), att, out, "writable.raw")
	if err != nil || got != att || volume.pressureReached || volume.boundaryComplete {
		t.Fatalf("volume-group continuation entered ordinary pressure lifecycle: %v", err)
	}
}

type continuationDiagnosticDisk struct {
	fixture.Disk
	transcript *fixture.Transcript
	blockPath  string
}

func (d *continuationDiagnosticDisk) SetTranscript(t *fixture.Transcript) { d.transcript = t }

func (d *continuationDiagnosticDisk) Attach(context.Context, string, fixture.AttachOptions) (*fixture.Attachment, error) {
	if d.blockPath != "" {
		if err := os.Mkdir(d.blockPath, 0o755); err != nil {
			return nil, err
		}
	}
	return nil, d.transcript.RecordFS("attach", []string{"test-attach"}, syscall.EIO, "0")
}

func TestContinuationRetainsInitialNativeFailureCommands(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		t.Run(fmt.Sprint("diagnostic-write-blocked-", blocked), func(t *testing.T) {
			work := t.TempDir()
			disk := &continuationDiagnosticDisk{}
			path := filepath.Join(work, "continuation", "container", "commands.json")
			if blocked {
				disk.blockPath = path
			}
			v := &Verifier{Work: work, Disk: disk}
			_, err := v.Continuation(context.Background(), Paired{Output: schema.Output{Name: "container"}}, schemaCase{})
			if !errors.Is(err, syscall.EIO) {
				t.Fatalf("diagnostic persistence replaced original native failure: %v", err)
			}
			if blocked {
				if !strings.Contains(err.Error(), "retain initial native commands") {
					t.Fatalf("diagnostic persistence failure was omitted: %v", err)
				}
				return
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var commands []schema.Command
			if err := json.Unmarshal(data, &commands); err != nil || len(commands) != 1 || commands[0].Label != "attach" || commands[0].Status == "0" {
				t.Fatalf("initial failure command was not retained: %s, %v", data, err)
			}
		})
	}
}
