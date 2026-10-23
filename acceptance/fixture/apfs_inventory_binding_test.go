package fixture

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func retainedDuplicateAPFSObservation(t *testing.T) *schema.Observation {
	t.Helper()
	b, err := os.ReadFile("testdata/apfs-duplicate-identity-observation.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	z, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	b, err = io.ReadAll(io.LimitReader(z, 103885))
	if err != nil || len(b) != 103884 || fmt.Sprintf("%x", sha256.Sum256(b)) != "190690e1419dfe1530885d5c1009bb761d5acdc25e301dd774ca4fb03ce7a196" {
		t.Fatalf("original native observation changed: size %d, error %v", len(b), err)
	}
	var obs schema.Observation
	if err := json.Unmarshal(b, &obs); err != nil {
		t.Fatal(err)
	}
	return &obs
}

func TestAPFSInventoryUsesNativeDeviceBindingsAmongDuplicateUUIDs(t *testing.T) {
	for _, binding := range []string{"reference-and-store", "reference", "store"} {
		t.Run(binding, func(t *testing.T) {
			obs := retainedDuplicateAPFSObservation(t)
			if binding == "reference" {
				delete(obs.Volumes[0].Diskutil, "APFSPhysicalStores")
			}
			if binding == "store" {
				delete(obs.Volumes[0].Diskutil, "APFSContainerReference")
			}
			before, _ := json.Marshal(obs)
			volumes, err := APFSInventory(obs)
			if err != nil {
				t.Fatal("uniquely attached native container rejected:", err)
			}
			if len(volumes) != 1 || volumes[0].Device != "/dev/disk8s1" || volumes[0].APFS.ContainerUUID != "F141C159-EAC3-4201-9BAB-07C76314BC0D" || volumes[0].APFS.VolumeUUID != "95F9C3FE-F1A9-40F4-B9FD-F6638D5CD7BB" {
				t.Fatalf("inventory did not preserve the bound native identities: %+v", volumes)
			}
			after, _ := json.Marshal(obs)
			if !bytes.Equal(before, after) {
				t.Fatal("native source observation was mutated")
			}
		})
	}
}

func changeRetainedGlobalInventory(t *testing.T, obs *schema.Observation, old, replacement string) {
	t.Helper()
	for i := len(obs.Commands) - 1; i >= 0; i-- {
		c := &obs.Commands[i]
		if len(c.Argv) == 4 && isAPFSListPlist(c.Argv) {
			if !strings.Contains(c.StdoutText, old) {
				t.Fatalf("hostile control did not modify the retained global listing: %q", old)
			}
			c.StdoutText = strings.ReplaceAll(c.StdoutText, old, replacement)
			c.StdoutSHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte(c.StdoutText)))
			return
		}
	}
	t.Fatal("retained native global listing missing")
}

func TestAPFSInventoryRefusesMissingConflictingOrAmbiguousDeviceBindings(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*testing.T, *schema.Observation)
	}{
		{"missing-bound-reference", func(_ *testing.T, o *schema.Observation) { o.Volumes[0].Diskutil["APFSContainerReference"] = "disk99" }},
		{"malformed-bound-reference", func(_ *testing.T, o *schema.Observation) { o.Volumes[0].Diskutil["APFSContainerReference"] = 8 }},
		{"empty-bound-reference", func(_ *testing.T, o *schema.Observation) { o.Volumes[0].Diskutil["APFSContainerReference"] = "" }},
		{"conflicting-reference-and-store", func(_ *testing.T, o *schema.Observation) { o.Volumes[0].Diskutil["APFSContainerReference"] = "disk13" }},
		{"missing-bound-store", func(_ *testing.T, o *schema.Observation) {
			o.Volumes[0].Diskutil["APFSPhysicalStores"] = []any{map[string]any{"APFSPhysicalStore": "disk99s1"}}
		}},
		{"malformed-bound-store", func(_ *testing.T, o *schema.Observation) { o.Volumes[0].Diskutil["APFSPhysicalStores"] = "disk7s1" }},
		{"absent-target-reference", func(t *testing.T, o *schema.Observation) {
			changeRetainedGlobalInventory(t, o, "<string>disk8</string>", "<string>disk88</string>")
		}},
		{"unknown-target-reference", func(t *testing.T, o *schema.Observation) {
			changeRetainedGlobalInventory(t, o, "<string>disk8</string>", "<string></string>")
		}},
		{"absent-target-store", func(t *testing.T, o *schema.Observation) {
			changeRetainedGlobalInventory(t, o, "<string>disk7s1</string>", "<string>disk99s1</string>")
		}},
		{"duplicate-bound-reference", func(t *testing.T, o *schema.Observation) {
			changeRetainedGlobalInventory(t, o, "<string>disk13</string>", "<string>disk8</string>")
		}},
		{"duplicate-bound-store", func(t *testing.T, o *schema.Observation) {
			delete(o.Volumes[0].Diskutil, "APFSContainerReference")
			changeRetainedGlobalInventory(t, o, "<string>disk9s1</string>", "<string>disk7s1</string>")
		}},
		{"unbound-duplicate-uuids", func(_ *testing.T, o *schema.Observation) {
			delete(o.Volumes[0].Diskutil, "APFSContainerReference")
			delete(o.Volumes[0].Diskutil, "APFSPhysicalStores")
		}},
		{"wrong-container-uuid", func(_ *testing.T, o *schema.Observation) {
			o.Volumes[0].APFS.ContainerUUID = "11111111-2222-4333-8444-555555555555"
		}},
		{"wrong-volume-uuid", func(t *testing.T, o *schema.Observation) {
			changeRetainedGlobalInventory(t, o, "95F9C3FE-F1A9-40F4-B9FD-F6638D5CD7BB", "11111111-2222-4333-8444-555555555555")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obs := retainedDuplicateAPFSObservation(t)
			tc.change(t, obs)
			// An older, individually scoped and otherwise valid listing remains
			// present. A contradictory latest target must never fall back to it.
			if _, err := APFSInventory(obs); err == nil {
				t.Fatal("invalid native device binding supplied an APFS inventory")
			}
		})
	}
}
