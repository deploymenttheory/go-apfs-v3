package native

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func continuedObservations() (*schema.Observation, *schema.Observation) {
	before := containerObservation(true)
	before.Views[0].Entries = append(before.Views[0].Entries, schema.Entry{Path: "native-continuation", Kind: "dir", ID: 100}, entry("native-continuation/entry-00001", 101))
	after := containerObservation(true)
	after.Views[0].Entries = append(after.Views[0].Entries, schema.Entry{Path: "native-continuation", Kind: "dir", ID: 100}, schema.Entry{Path: "native-continuation/go", Kind: "dir", ID: 102})
	data := []byte(strings.Repeat("continued by the product\n", 400))
	for _, name := range []string{"payload", "alias"} {
		after.Views[0].Entries = append(after.Views[0].Entries, schema.Entry{Path: "native-continuation/go/" + name, Kind: "file", ID: 103, Links: 2, Size: int64(len(data)), SHA256: fmt.Sprintf("%x", sha256.Sum256(data))})
	}
	return before, after
}

func TestContinuationChecksNativeContentsAndEveryPeer(t *testing.T) {
	before, after := continuedObservations()
	if err := compareContinuedContainer(before, after, "Reserved"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*schema.Observation)
	}{
		{"peer data changed", func(o *schema.Observation) { o.Views[1].Entries[0].SHA256 = "wrong" }},
		{"original native data changed", func(o *schema.Observation) { o.Views[0].Entries[0].SHA256 = "wrong" }},
		{"missing empty peer", func(o *schema.Observation) { o.Volumes = o.Volumes[:2]; o.Views = o.Views[:2] }},
		{"wrong volume UUID", func(o *schema.Observation) { o.Volumes[1].APFS.VolumeUUID = "different" }},
		{"wrong product payload", func(o *schema.Observation) { o.Views[0].Entries[3].SHA256 = "wrong" }},
		{"flattened product alias", func(o *schema.Observation) { o.Views[0].Entries[4].ID++ }},
		{"unexpected product child", func(o *schema.Observation) {
			o.Views[0].Entries = append(o.Views[0].Entries, entry("native-continuation/go/unexpected", 999))
		}},
		{"deleted native file survived", func(o *schema.Observation) {
			o.Views[0].Entries = append(o.Views[0].Entries, entry("native-continuation/entry-00001", 101))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := cloneObservation(t, after)
			tc.change(got)
			if err := compareContinuedContainer(before, got, "Reserved"); err == nil {
				t.Fatal("altered continuation escaped verification")
			}
		})
	}
}

func TestFinalNativeAllocationMustSurviveWithoutChangingPeers(t *testing.T) {
	_, before := continuedObservations()
	after := cloneObservation(t, before)
	data := []byte("allocated through Apple's kernel after the product edit")
	after.Views[0].Entries = append(after.Views[0].Entries, schema.Entry{Path: "native-continuation/native-after-go", Kind: "file", ID: 104, Links: 1, Size: int64(len(data)), SHA256: fmt.Sprintf("%x", sha256.Sum256(data))})
	if err := compareFinalNativeWrite(before, after, "Reserved", data); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*schema.Observation){
		func(o *schema.Observation) { o.Views[0].Entries = o.Views[0].Entries[:len(o.Views[0].Entries)-1] },
		func(o *schema.Observation) { o.Views[0].Entries[len(o.Views[0].Entries)-1].SHA256 = "wrong" },
		func(o *schema.Observation) { o.Views[1].Entries[0].Times.Modify++ },
		func(o *schema.Observation) { o.Views[0].Entries[0].SHA256 = "wrong" },
	} {
		got := cloneObservation(t, after)
		change(got)
		if err := compareFinalNativeWrite(before, got, "Reserved", data); err == nil {
			t.Fatal("final native corruption escaped verification")
		}
	}
}

type pressureVolume struct {
	fixture.Volume
	err   error
	calls int
}

func (v *pressureVolume) AppendFile(string, []byte) error { v.calls++; return v.err }

func TestNativePressureRequiresTheBoundedAllocationOutcome(t *testing.T) {
	for _, tc := range []struct {
		name    string
		outcome error
		accept  bool
	}{
		{"quota", syscall.EDQUOT, true}, {"space", syscall.ENOSPC, true},
		{"unrelated I/O failure", syscall.EIO, false}, {"permission refusal", syscall.EACCES, false},
		{"no allocation limit", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			memory := fixture.NewMemoryVolume("/volume")
			volume := &pressureVolume{Volume: memory, err: tc.outcome}
			v := &Verifier{Vol: volume}
			err := v.fillVolume(context.Background(), "/volume/pressure", 512<<10)
			if (err == nil) != tc.accept || volume.calls > 2 {
				t.Fatalf("allocation result %v with %d calls, accept=%v", err, volume.calls, tc.accept)
			}
			if tc.outcome != nil && !tc.accept && !errors.Is(err, tc.outcome) {
				t.Fatalf("original error was lost: %v", err)
			}
		})
	}
}

// pressureProtocolVolume models committed allocation separately from dirty
// truncation. Unlinking a pressured inode succeeds, but a later peer fsync fails
// while its released blocks have not been committed. This reproduces the
// ordering failure without mounting a filesystem on the developer host.
type pressureProtocolVolume struct {
	fixture.Volume
	pending                       map[string]bool
	quotaReached, pressureReached bool
	protectedSynced               bool
	fail                          string
	failCalls                     int
	corrupt                       string
	unallocatedProof              bool
}

func (v *pressureProtocolVolume) fault(operation, filename string) error {
	if operation+":"+filename == v.fail {
		v.failCalls++
		return syscall.EIO
	}
	return nil
}

func (v *pressureProtocolVolume) WriteFile(filename string, data []byte, exclusive bool) error {
	if err := v.fault("write", filename); err != nil {
		return err
	}
	if filepath.Base(filename) == "reservation-proof" && !v.pressureReached {
		return fmt.Errorf("reserved allocation was tested before unreserved exhaustion")
	}
	if filepath.Base(filename) == v.corrupt && len(data) != 0 {
		data = append([]byte(nil), data...)
		data[0] ^= 0xff
	}
	return v.Volume.WriteFile(filename, data, exclusive)
}

func (v *pressureProtocolVolume) AppendFile(filename string, data []byte) error {
	stat, err := v.Volume.Lstat(filename)
	if err != nil {
		return err
	}
	switch filepath.Base(filepath.Dir(filepath.Dir(filename))) {
	case "Limited":
		if stat.Size >= 512<<10 {
			v.quotaReached = true
			return syscall.EDQUOT
		}
	case "Fresh Empty":
		if stat.Size >= 1<<20 {
			v.pressureReached = true
			return syscall.ENOSPC
		}
	}
	return v.Volume.AppendFile(filename, data)
}

func (v *pressureProtocolVolume) Truncate(filename string, size int64) error {
	if err := v.fault("truncate", filename); err != nil {
		return err
	}
	if err := v.Volume.Truncate(filename, size); err != nil {
		return err
	}
	if size == 0 {
		v.pending[filename] = true
	}
	return nil
}

func (v *pressureProtocolVolume) Fullfsync(filename string) error {
	if v.pending[filename] {
		if err := v.fault("release-sync", filename); err != nil {
			return err
		}
		stat, err := v.Volume.Lstat(filename)
		if err != nil || stat.Size != 0 {
			return fmt.Errorf("deallocation sync did not retain the truncated inode: %v", err)
		}
		delete(v.pending, filename)
	} else {
		if err := v.fault("sync", filename); err != nil {
			return err
		}
		if filepath.Base(filename) == "peer" && len(v.pending) != 0 {
			return syscall.ENOSPC
		}
		if filepath.Base(filename) == "reservation-proof" {
			v.protectedSynced = true
		}
	}
	return v.Volume.Fullfsync(filename)
}

func (v *pressureProtocolVolume) Remove(filename string) error {
	if err := v.fault("unlink", filename); err != nil {
		return err
	}
	if strings.Contains(filename, "Fresh Empty") && !v.protectedSynced {
		return fmt.Errorf("unreserved pressure was removed before the protected write committed")
	}
	return v.Volume.Remove(filename)
}

func (v *pressureProtocolVolume) Lstat(filename string) (fixture.Stat, error) {
	stat, err := v.Volume.Lstat(filename)
	if v.unallocatedProof && filepath.Base(filename) == "reservation-proof" {
		stat.Allocated = 0
	}
	return stat, err
}

func containerPressureProtocol(t *testing.T) (*Verifier, *fixture.Attachment, schema.Output, *pressureProtocolVolume) {
	t.Helper()
	memory := fixture.NewMemoryVolume("/container")
	att := &fixture.Attachment{}
	for _, name := range []string{"Reserved", "Limited", "Empty", "Fresh Empty"} {
		mount := filepath.Join("/container", name)
		if err := memory.Mkdir(mount, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := memory.WriteFile(filepath.Join(mount, "original"), []byte("original "+name), true); err != nil {
			t.Fatal(err)
		}
		att.Volumes = append(att.Volumes, &fixture.AttachedVolume{Name: name, Mount: mount, FS: "apfs"})
	}
	volume := &pressureProtocolVolume{Volume: memory, pending: map[string]bool{}}
	out := schema.Output{Source: schema.CaseRef{Recipe: "container-volumes"}, Expect: schema.Expectation{Container: &schema.ContainerExpectation{EmptyVolumes: []string{"Fresh Empty"}}}}
	return &Verifier{Vol: volume}, att, out, volume
}

func TestContainerPressureCommitsDeallocationBeforePeerWrites(t *testing.T) {
	v, att, out, volume := containerPressureProtocol(t)
	if err := v.containerWrites(context.Background(), att, out); err != nil {
		t.Fatal(err)
	}
	if !volume.quotaReached || !volume.pressureReached || !volume.protectedSynced || len(volume.pending) != 0 {
		t.Fatal("quota, exhaustion, protected allocation or durable release was not verified")
	}
	for _, peer := range att.Volumes {
		for name, data := range map[string][]byte{"original": []byte("original " + peer.Name), "container-continuation/peer": []byte(peer.Name + "\n")} {
			if err := v.checkNativePayload(filepath.Join(peer.Mount, name), data); err != nil {
				t.Fatal(err)
			}
		}
		for _, name := range []string{"pressure", "reservation-proof"} {
			if _, err := volume.Volume.Lstat(filepath.Join(peer.Mount, "container-continuation", name)); !errors.Is(err, syscall.ENOENT) {
				t.Fatalf("pressure file %s on %s was retained: %v", name, peer.Name, err)
			}
		}
	}
}

func TestContainerPressureReportsFailedOperationsWithoutRetries(t *testing.T) {
	for _, tc := range []struct {
		name, operation, volume, file, context string
	}{
		{"quota-release", "release-sync", "Limited", "pressure", "quota on volume"},
		{"reservation-write", "write", "Reserved", "reservation-proof", "write protected allocation"},
		{"reservation-sync", "sync", "Reserved", "reservation-proof", "sync protected allocation"},
		{"pressure-truncate", "truncate", "Fresh Empty", "pressure", "release reservation pressure"},
		{"pressure-release", "release-sync", "Fresh Empty", "pressure", "sync released pressure"},
		{"pressure-unlink", "unlink", "Fresh Empty", "pressure", "unlink released pressure"},
		{"proof-release", "release-sync", "Reserved", "reservation-proof", "release protected allocation"},
		{"peer-write", "write", "Limited", "peer", "write peer"},
		{"peer-sync", "sync", "Reserved", "peer", "sync peer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, att, out, volume := containerPressureProtocol(t)
			filename := filepath.Join("/container", tc.volume, "container-continuation", tc.file)
			volume.fail = tc.operation + ":" + filename
			err := v.containerWrites(context.Background(), att, out)
			if !errors.Is(err, syscall.EIO) || !strings.Contains(err.Error(), tc.context) || !strings.Contains(err.Error(), filename) || !strings.Contains(err.Error(), tc.volume) || volume.failCalls != 1 {
				t.Fatalf("operation must fail once with exact stage and path: %v, calls=%d", err, volume.failCalls)
			}
		})
	}
}

func TestContainerPressureRequiresAllocatedProofAndExactPeerContents(t *testing.T) {
	for _, change := range []string{"unallocated proof", "reservation-proof", "peer"} {
		t.Run(change, func(t *testing.T) {
			v, att, out, volume := containerPressureProtocol(t)
			if change == "unallocated proof" {
				volume.unallocatedProof = true
			} else {
				volume.corrupt = change
			}
			if err := v.containerWrites(context.Background(), att, out); err == nil {
				t.Fatal("allocation or readback corruption passed the native protocol")
			}
		})
	}
}
