package native

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// nativeWriteAfterEdit allocates through Apple's kernel after the Go transaction,
// then remounts and checks the written bytes and all unrelated entries. The input
// output remains read-only; only a private complete raw copy is modified.
func (v *Verifier) nativeWriteAfterEdit(ctx context.Context, out schema.Output, edited, work, selected string, before *schema.Observation, recipe schema.Recipe) (*schema.Observation, error) {
	raw := filepath.Join(work, "native-after-go.raw")
	att, err := v.Disk.Attach(ctx, edited, fixture.AttachOptions{ReadOnly: true, NoInventory: true})
	if err != nil {
		return nil, err
	}
	_, _, err = v.Disk.DeviceDigest(ctx, att.RDev, raw+".gz")
	if detachErr := v.Disk.Detach(ctx, att); err == nil {
		err = detachErr
	}
	if err != nil {
		return nil, err
	}
	if err := corpus.ExpandGzip(raw+".gz", raw); err != nil {
		return nil, err
	}
	if err := os.Remove(raw + ".gz"); err != nil {
		return nil, err
	}
	att, err = v.Disk.Attach(ctx, raw, fixture.AttachOptions{Raw: true})
	if err != nil {
		return nil, err
	}
	volume := att.Volume(selected)
	if volume == nil {
		_ = v.Disk.Detach(ctx, att)
		return nil, fmt.Errorf("final native continuation lost selected volume %q", selected)
	}
	if err := v.Disk.Mount(ctx, volume, "owners,noatime", filepath.Join(work, "native-after-go-mount"), false); err != nil {
		_ = v.Disk.Detach(ctx, att)
		return nil, err
	}
	data := []byte(strings.Repeat("native allocation after the Go transaction\n", 4096))
	filename := filepath.Join(volume.Mount, "native-continuation", "native-after-go")
	err = v.Vol.WriteFile(filename, data, true)
	if err == nil {
		err = v.Vol.Fullfsync(filename)
	}
	if unmountErr := v.Disk.Unmount(ctx, volume); err == nil {
		err = unmountErr
	}
	if detachErr := v.Disk.Detach(ctx, att); err == nil {
		err = detachErr
	}
	if err != nil {
		return nil, fmt.Errorf("final native allocation on %q: %w", selected, err)
	}
	if err := v.fsckRaw(ctx, raw, volume.FS); err != nil {
		return nil, fmt.Errorf("checker after final native allocation: %w", err)
	}
	after, err := v.observeImage(ctx, out.Name+".native-after-go", raw, "raw", nil, schema.ObserveSpec{}, recipe)
	if err != nil {
		return nil, err
	}
	if err := compareFinalNativeWrite(before, after, selected, data); err != nil {
		return after, err
	}
	return after, nil
}

func compareFinalNativeWrite(before, after *schema.Observation, selected string, data []byte) error {
	if diffs, err := comparePreservedVolumeMetadata(after, before); err != nil {
		return err
	} else if len(diffs) != 0 {
		return fmt.Errorf("final native allocation changed filesystem metadata: %v", diffs)
	}
	if len(before.Volumes) != len(after.Volumes) || len(before.Views) != len(after.Views) {
		return fmt.Errorf("final native allocation changed the volume/view inventory")
	}
	for _, expectedVolume := range before.Volumes {
		name := volumeName(expectedVolume)
		actual, err := namedVolume(after, name)
		if err != nil {
			return err
		}
		want, err := observedView(before, expectedVolume.Index, "")
		if err != nil {
			return err
		}
		got, err := observedView(after, actual.Index, "")
		if err != nil {
			return err
		}
		if name == selected {
			var entries []schema.Entry
			count := 0
			for _, entry := range got.Entries {
				if entry.Path == "native-continuation/native-after-go" {
					count++
					if entry.Kind != "file" || entry.Size != int64(len(data)) || entry.SHA256 != fmt.Sprintf("%x", sha256.Sum256(data)) || entry.Links != 1 {
						return fmt.Errorf("final native allocation did not survive remount")
					}
					continue
				}
				if entry.Path == "native-continuation" {
					for _, original := range want.Entries {
						if original.Path == entry.Path {
							entry.Times.Modify, entry.Times.Change = original.Times.Modify, original.Times.Change
						}
					}
				}
				entries = append(entries, entry)
			}
			if count != 1 {
				return fmt.Errorf("missing or duplicate final native allocation")
			}
			got.Entries = entries
		}
		if diffs := CompareViews(got, want, CompareOptions{}); len(diffs) != 0 {
			return fmt.Errorf("final native allocation changed %q: %v", name, diffs)
		}
	}
	return nil
}
