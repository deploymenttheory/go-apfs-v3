package native

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func TestSnapshotDeletionReferencePreservesAllSurvivorFactsWithoutChangingOriginal(t *testing.T) {
	original := snapshotEditingControl()
	original.Volumes[0].APFS.Snapshots[0].UUID = "old-uuid"
	original.Volumes[0].APFS.Snapshots[0].CreatedNS = 31
	original.Volumes[0].APFS.Snapshots[0].ChangedNS = 41
	before, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	orders, err := SnapshotDeletionOrders(original)
	if err != nil {
		t.Fatal(err)
	}
	for _, deleted := range orders {
		got, err := SnapshotDeletionReference(original, deleted)
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Volumes[0].APFS.Snapshots) != 2-len(deleted) || len(got.Views) != 3-len(deleted) {
			t.Fatal("wrong reference inventory")
		}
		if !reflect.DeepEqual(got.Views[0], original.Views[0]) {
			t.Fatal("live clocks/identities changed")
		}
		for _, s := range got.Volumes[0].APFS.Snapshots {
			for _, w := range original.Volumes[0].APFS.Snapshots {
				if s.XID == w.XID && !reflect.DeepEqual(s, w) {
					t.Fatal("survivor metadata changed")
				}
			}
		}
	}
	after, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) || len(original.Volumes[0].APFS.Snapshots) != 2 || len(original.Views) != 3 {
		t.Fatal("original mutated")
	}
	for _, bad := range [][]schema.SnapshotIdentity{nil, {{Name: "before", XID: 20}}, {{Name: "Before", XID: 10}}, {{Name: "before", XID: 10}, {Name: "before", XID: 10}}} {
		if _, err := SnapshotDeletionReference(original, bad); err == nil {
			t.Fatal("unknown/duplicate identity projected", bad)
		}
	}
}

func TestSnapshotDeletionOutputsRequireBothProfilesEveryOrderAndContinuation(t *testing.T) {
	cases := map[string]corpus.Case{}
	var pairs []Paired
	for _, profile := range []string{"apfs", "apfsx"} {
		ref := schema.CaseRef{Producer: 26, Recipe: "snapshot-history", Profile: profile, Stage: "live"}
		original := snapshotEditingControl()
		cases[CaseKey(ref)] = corpus.Case{Observation: original}
		orders, err := SnapshotDeletionOrders(original)
		if err != nil {
			t.Fatal(err)
		}
		for _, deleted := range orders {
			pairs = append(pairs, Paired{Output: schema.Output{Source: ref, Operation: "delete-snapshot", Format: "UDZO", Expect: schema.Expectation{DeletedSnapshots: deleted, Continuation: true}}})
		}
	}
	for _, profile := range []string{"apfs", "apfsx"} {
		for stage := range encryptedSnapshotDeletionMatrix() {
			ref := schema.CaseRef{Producer: 26, Recipe: "encrypted-snapshot-history", Profile: profile, Stage: stage}
			original := snapshotEditingControl()
			original.Volumes[0].Diskutil["VolumeName"] = "EncryptedHistory"
			original.Volumes[0].APFS.VolumeUUID = "10000000-0000-4000-8000-000000000001"
			original.Volumes[0].APFS.ContainerUUID = "20000000-0000-4000-8000-000000000001"
			original.Volumes[0].APFS.Role = "Data"
			original.Volumes[0].APFS.Encrypted = stage != "decrypted"
			bindMetadataInventory(original)
			cases[CaseKey(ref)] = corpus.Case{Observation: original}
			orders, err := EncryptedSnapshotDeletionOrders(ref, original)
			if err != nil {
				t.Fatal(err)
			}
			for _, deleted := range orders {
				out := schema.Output{Source: ref, Operation: "delete-snapshot", Format: "UDZO",
					Expect: schema.Expectation{Volume: "EncryptedHistory", DeletedSnapshots: deleted, Continuation: true}}
				if stage == "aes128-nested" || stage == "aes256-nested" {
					out.Encrypted, out.Password = true, "encrypted-snapshot-history.image"
				}
				pairs = append(pairs, Paired{Output: out})
			}
		}
		for _, control := range encryptedSnapshotDeletionControls() {
			ref := schema.CaseRef{Producer: 26, Recipe: "encrypted-snapshot-history", Profile: profile, Stage: control.source}
			before := cases[CaseKey(ref)].Observation
			orders, err := VolumeSnapshotDeletionOrders(before, "EncryptedHistory")
			if err != nil {
				t.Fatal(err)
			}
			after, err := VolumeSnapshotDeletionReference(before, "EncryptedHistory", orders[control.order])
			if err != nil {
				t.Fatal(err)
			}
			ref.Stage = control.stage
			cases[CaseKey(ref)] = corpus.Case{Observation: after}
		}
	}
	if err := requireSnapshotDeletionOutputs(pairs, cases, 26); err != nil {
		t.Fatal(err)
	}
	if err := requireSnapshotDeletionOutputs(pairs[:7], cases, 26); err == nil {
		t.Fatal("missing final deletion accepted")
	}
	if err := requireSnapshotDeletionOutputs(append(pairs, pairs[0]), cases, 26); err == nil {
		t.Fatal("duplicate deletion accepted")
	}
	for _, change := range []func(*schema.Output){
		func(o *schema.Output) { o.Expect.Continuation = false },
		func(o *schema.Output) { o.Expect.IgnoreTimes = []string{"change"} },
		func(o *schema.Output) { o.Operation = "edit" },
		func(o *schema.Output) {
			o.Expect.DeletedSnapshots = []schema.SnapshotIdentity{{Name: "before", XID: 20}}
		},
	} {
		altered := append([]Paired(nil), pairs...)
		change(&altered[0].Output)
		if err := requireSnapshotDeletionOutputs(altered, cases, 26); err == nil {
			t.Fatal("relaxed/mismatched deletion contract accepted")
		}
	}
}

func TestSelectedSnapshotDeletionPreservesPeerHistoryAndCredentials(t *testing.T) {
	original := snapshotEditingControl()
	original.Volumes[0].Diskutil["VolumeName"] = "EncryptedHistory"
	original.Volumes[0].APFS.Encrypted = true
	original.Volumes[0].APFS.Password = "primary"
	peer := snapshotEditingControl()
	peer.Volumes[0].Index = 1
	peer.Volumes[0].APFS.Encrypted = true
	peer.Volumes[0].APFS.Password = "peer"
	original.Volumes = append(original.Volumes, peer.Volumes[0])
	for _, view := range peer.Views {
		view.Volume = 1
		original.Views = append(original.Views, view)
	}
	before, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VolumeSnapshotDeletionReference(original, "EncryptedHistory", []schema.SnapshotIdentity{{Name: "before", XID: 10}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Volumes[0].APFS.Snapshots) != 1 || len(got.Views) != 5 ||
		!reflect.DeepEqual(got.Volumes[1], original.Volumes[1]) ||
		!reflect.DeepEqual(got.Views[2:], original.Views[3:]) ||
		got.Volumes[0].APFS.Password != "primary" {
		t.Fatal("selected deletion changed a peer, survivor or credential")
	}
	after, err := json.Marshal(original)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("selected deletion changed original evidence", err)
	}
}
