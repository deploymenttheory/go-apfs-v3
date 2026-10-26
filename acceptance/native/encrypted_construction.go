package native

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func validateEncryptedConstruction(out schema.Output) error {
	expected := schema.Expectation{Subtree: "Fixture", Volume: "Primary", Continuation: true, Container: &schema.ContainerExpectation{CapacityBytes: 1536 << 20, EmptyVolumes: []string{"Fresh Encrypted Peer"}, EncryptedVolumes: map[string]string{"Primary": "primary", "Fresh Encrypted Peer": "peer"}}}
	if out.Expect.Container != nil {
		expected.Container.ImageCipher = out.Expect.Container.ImageCipher
	}
	cipher := expected.Container.ImageCipher
	if out.Operation != "create-encrypted" || out.Source.Recipe != "encrypted-volumes" || out.Source.Stage != "clone-shared" || (out.Source.Profile != "apfs" && out.Source.Profile != "apfsx") || out.Format != "UDZO" || !expectationsEqual(out.Expect, expected) || out.Encrypted != (cipher != "") || cipher != "" && cipher != "AES-128" && cipher != "AES-256" || out.Encrypted && out.Password != "encrypted-construction.image" || !out.Encrypted && out.Password != "" {
		return fmt.Errorf("encrypted construction %s lacks its native contract", out.Name)
	}
	return nil
}

func requireEncryptedConstruction(pairs []Paired, cases map[string]corpus.Case, major int) error {
	counts := map[string]int{}
	for _, p := range pairs {
		if p.Output.Operation == "create-encrypted" {
			if err := validateEncryptedConstruction(p.Output); err != nil {
				return err
			}
			counts[p.Output.Source.Profile+"/"+p.Output.Expect.Container.ImageCipher]++
		}
	}
	for _, profile := range []string{"apfs", "apfsx"} {
		control, ok := cases[CaseKey(schema.CaseRef{Producer: major, Recipe: "encrypted-volumes", Profile: profile, Stage: "encrypted-peer"})]
		if !ok || control.Observation == nil || len(control.Observation.Volumes) != 3 {
			return fmt.Errorf("missing independently encrypted peer control")
		}
		for _, cipher := range []string{"", "AES-128", "AES-256"} {
			if counts[profile+"/"+cipher] != 1 {
				return fmt.Errorf("missing encrypted construction %s/%s", profile, cipher)
			}
		}
	}
	return nil
}

// Fresh UUIDs come from the native attachment inventory, never from a Go
// expected image. Original file/metadata observations remain the oracle.
func encryptedConstructionReference(att *fixture.Attachment, source *schema.Observation, out schema.Output) (*schema.Observation, error) {
	if err := validateEncryptedConstruction(out); err != nil {
		return nil, err
	}
	result := *source
	result.Volumes = append([]schema.Volume(nil), source.Volumes...)
	for _, name := range out.Expect.Container.EmptyVolumes {
		result.Volumes = append(result.Volumes, schema.Volume{Index: len(result.Volumes), Diskutil: map[string]any{"VolumeName": name}, APFS: &schema.APFSVolume{CaseSensitive: out.Source.Profile == "apfsx"}})
	}
	if len(att.Volumes) != len(result.Volumes) {
		return nil, fmt.Errorf("encrypted construction native inventory count differs")
	}
	for i, volume := range result.Volumes {
		native := att.Volume(volumeName(volume))
		if native == nil || native.UUID == "" || volume.APFS == nil {
			return nil, fmt.Errorf("missing constructed volume %s", volumeName(volume))
		}
		apfs := *volume.APFS
		apfs.VolumeUUID = native.UUID
		apfs.Snapshots = nil
		apfs.Password = out.Expect.Container.EncryptedVolumes[native.Name]
		apfs.Encrypted = apfs.Password != ""
		apfs.Rejected = nil
		if apfs.Encrypted {
			apfs.Rejected = []string{"wrong"}
			if apfs.Password == "peer" {
				apfs.Rejected = append(apfs.Rejected, "primary")
			} else {
				apfs.Rejected = append(apfs.Rejected, "peer")
			}
		}
		result.Volumes[i].APFS = &apfs
	}
	return &result, nil
}

func (v *Verifier) constructedCredentials(ctx context.Context, image string, password []byte, source *schema.Observation, out schema.Output) (*schema.Observation, error) {
	att, err := v.Disk.Attach(ctx, image, fixture.AttachOptions{ReadOnly: true, Password: password})
	if err != nil {
		return nil, err
	}
	expected, err := encryptedConstructionReference(att, source, out)
	return expected, errors.Join(err, v.Disk.Detach(ctx, att))
}

func checkConstructionCipher(out schema.Output, obs *schema.Observation) error {
	want := out.Expect.Container.ImageCipher
	if want == "" {
		properties, ok := obs.Image.Imageinfo["Properties"].(map[string]any)
		if !ok || properties["Encrypted"] != false {
			return fmt.Errorf("constructed envelope unexpectedly encrypted")
		}
		return nil
	}
	got, err := nativeImageCipher(obs.Image.Imageinfo)
	if err != nil || got != want {
		return fmt.Errorf("constructed envelope cipher %q, want %q: %v", got, want, err)
	}
	return nil
}

// Reuse the exact source extent sampling paths after projecting Fixture to the
// newly constructed root. Physical addresses may move; sharing must survive.
func constructionExtentPaths(source *schema.Observation) []string {
	var result []string
	seen := map[string]bool{}
	for _, view := range source.Views {
		for _, entry := range view.Entries {
			if entry.Extents != nil && strings.HasPrefix(entry.Path, "Fixture/") {
				path := strings.TrimPrefix(entry.Path, "Fixture/")
				if !seen[path] {
					result = append(result, path)
					seen[path] = true
				}
			}
		}
	}
	return result
}

func checkConstructedSharing(got, want *schema.Observation) error {
	for _, expected := range want.Views {
		volume := want.Volumes[expected.Volume]
		actualVolume, err := namedVolume(got, volumeName(volume))
		if err != nil {
			return err
		}
		actual, err := observedView(got, actualVolume.Index, "")
		if err != nil {
			return err
		}
		for _, a := range expected.Entries {
			for _, b := range expected.Entries {
				if a.Path >= b.Path || a.Extents == nil || b.Extents == nil {
					continue
				}
				var x, y *schema.Entry
				for i := range actual.Entries {
					entry := &actual.Entries[i]
					if entry.Path == strings.TrimPrefix(a.Path, "Fixture/") {
						x = entry
					}
					if entry.Path == strings.TrimPrefix(b.Path, "Fixture/") {
						y = entry
					}
				}
				if x == nil || y == nil || x.Extents == nil || y.Extents == nil {
					return fmt.Errorf("constructed clone sampling omitted %s/%s", a.Path, b.Path)
				}
				// Extent sharing is checked separately for data and resource forks below.
				if sharedPhysicalBytes(a.Extents.Data, b.Extents.Data) != sharedPhysicalBytes(x.Extents.Data, y.Extents.Data) || sharedPhysicalBytes(a.Extents.Resource, b.Extents.Resource) != sharedPhysicalBytes(x.Extents.Resource, y.Extents.Resource) {
					return fmt.Errorf("constructed clone sharing differs for %s/%s", a.Path, b.Path)
				}
			}
		}
	}
	return nil
}
