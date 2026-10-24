package native

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// containerWrites exercises independent peer writes and the native quota and
// reservation policies on disposable writable copies. Pressure is bounded by
// the declared small container; it never fills the runner's host filesystem.
func (v *Verifier) containerWrites(ctx context.Context, att *fixture.Attachment, out schema.Output) error {
	for _, volume := range att.Volumes {
		if volume.Mount == "" {
			return fmt.Errorf("peer %q is not mounted", volume.Name)
		}
		if err := v.writableDirectory(ctx, filepath.Join(volume.Mount, "container-continuation")); err != nil {
			return err
		}
	}
	if out.Source.Recipe == "container-volumes" {
		limited, reserved := att.Volume("Limited"), att.Volume("Reserved")
		if limited == nil || reserved == nil || len(out.Expect.Container.EmptyVolumes) != 1 {
			return fmt.Errorf("missing quota, reserved or empty volume")
		}
		empty := att.Volume(out.Expect.Container.EmptyVolumes[0])
		if empty == nil {
			return fmt.Errorf("missing empty pressure volume")
		}
		if err := v.pressureVolume(ctx, limited, 16<<20); err != nil {
			return fmt.Errorf("quota: %w", err)
		}
		// The unreserved peer must run out before consuming the reserved
		// allocation. Keep the pressure file until the reserved write is synced.
		pressure := filepath.Join(empty.Mount, "container-continuation", "pressure")
		if err := v.fillVolume(ctx, pressure, 256<<20); err != nil {
			return fmt.Errorf("reservation pressure: %w", err)
		}
		proof := filepath.Join(reserved.Mount, "container-continuation", "reservation-proof")
		if err := v.Vol.WriteFile(proof, make([]byte, 1<<20), true); err != nil {
			return fmt.Errorf("reserved volume lost protected allocation: %w", err)
		}
		if err := v.Vol.Fullfsync(proof); err != nil {
			return err
		}
		if err := v.Vol.Truncate(pressure, 0); err != nil {
			return err
		}
		if err := v.Vol.Remove(pressure); err != nil {
			return err
		}
		if err := v.Vol.Remove(proof); err != nil {
			return err
		}
	}
	for _, volume := range att.Volumes {
		if volume.Mount == "" {
			return fmt.Errorf("peer %q is not mounted", volume.Name)
		}
		// Identical names hold distinct contents on each volume, so an
		// accidental selection or cross-volume alias cannot pass readback.
		filename := filepath.Join(volume.Mount, "container-continuation", "peer")
		if err := v.Vol.WriteFile(filename, []byte(volume.Name+"\n"), true); err != nil {
			return err
		}
		if err := v.Vol.Fullfsync(filename); err != nil {
			return err
		}
	}
	return nil
}

func (v *Verifier) pressureVolume(ctx context.Context, volume *fixture.AttachedVolume, bound int64) error {
	filename := filepath.Join(volume.Mount, "container-continuation", "pressure")
	if err := v.fillVolume(ctx, filename, bound); err != nil {
		return err
	}
	if err := v.Vol.Truncate(filename, 0); err != nil {
		return err
	}
	if err := v.Vol.Remove(filename); err != nil {
		return err
	}
	// Reusing quota after removing the last owner is a separate required result.
	if err := v.Vol.WriteFile(filename, make([]byte, 32<<10), true); err != nil {
		return fmt.Errorf("reusing released quota: %w", err)
	}
	if err := v.Vol.Fullfsync(filename); err != nil {
		return err
	}
	return v.Vol.Remove(filename)
}

func (v *Verifier) fillVolume(ctx context.Context, filename string, bound int64) error {
	if err := v.Vol.WriteFile(filename, nil, true); err != nil {
		return err
	}
	chunk := make([]byte, 512<<10)
	for written := int64(0); written < bound; written += int64(len(chunk)) {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := v.Vol.AppendFile(filename, chunk)
		if err == nil {
			err = v.Vol.Fullfsync(filename)
		}
		if errors.Is(err, syscall.EDQUOT) || errors.Is(err, syscall.ENOSPC) {
			return nil
		}
		if err != nil {
			return err
		}
	}
	return fmt.Errorf("native allocation pressure did not reach EDQUOT/ENOSPC within %d bytes", bound)
}

func compareContinuedContainer(before, after *schema.Observation, selected string) error {
	if err := compareHistoricalViews(after, before); err != nil {
		return err
	}
	if diffs, err := comparePreservedVolumeMetadata(after, before); err != nil {
		return err
	} else if len(diffs) != 0 {
		return fmt.Errorf("continued volume metadata changed: %v", diffs)
	}
	if len(before.Volumes) != len(after.Volumes) || len(before.Views) != len(after.Views) {
		return fmt.Errorf("continued container lost a volume or view")
	}
	for _, volume := range before.Volumes {
		name := volumeName(volume)
		actual, err := namedVolume(after, name)
		if err != nil {
			return err
		}
		want, err := observedView(before, volume.Index, "")
		if err != nil {
			return err
		}
		got, err := observedView(after, actual.Index, "")
		if err != nil {
			return err
		}
		if name == selected {
			want, got, err = continuationProjection(want, got)
			if err != nil {
				return err
			}
		}
		if diffs := CompareViews(got, want, CompareOptions{}); len(diffs) != 0 {
			return fmt.Errorf("continued volume %q: %v", name, diffs)
		}
	}
	return nil
}

// continuationProjection removes only the declared Go changes; every untouched
// entry on the selected volume and every peer remains exact.
func continuationProjection(before, after schema.View) (schema.View, schema.View, error) {
	var want, got schema.View
	for _, e := range before.Entries {
		if e.Path != "native-continuation/entry-00001" {
			want.Entries = append(want.Entries, e)
		}
	}
	created := map[string]schema.Entry{}
	for _, e := range after.Entries {
		if e.Path == "native-continuation/entry-00001" {
			return before, after, fmt.Errorf("deleted native entry is still present")
		}
		if e.Path == "native-continuation/go" || strings.HasPrefix(e.Path, "native-continuation/go/") {
			created[e.Path] = e
			continue
		}
		if e.Path == "native-continuation" {
			for _, original := range want.Entries {
				if original.Path == e.Path {
					e.Times.Modify, e.Times.Change = original.Times.Modify, original.Times.Change
				}
			}
		}
		got.Entries = append(got.Entries, e)
	}
	data := []byte(strings.Repeat("continued by the product\n", 400))
	sum := fmt.Sprintf("%x", sha256.Sum256(data))
	payload, p := created["native-continuation/go/payload"]
	alias, a := created["native-continuation/go/alias"]
	dir, d := created["native-continuation/go"]
	if len(created) != 3 || !p || !a || !d || dir.Kind != "dir" || payload.Kind != "file" || alias.Kind != "file" || payload.ID == 0 || payload.ID != alias.ID || payload.Links != 2 || alias.Links != 2 || payload.SHA256 != sum || alias.SHA256 != sum || payload.Size != int64(len(data)) || alias.Size != int64(len(data)) {
		return before, after, fmt.Errorf("product continuation data or hard-link relationship is incorrect")
	}
	return want, got, nil
}
