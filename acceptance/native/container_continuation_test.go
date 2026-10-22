package native

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
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
