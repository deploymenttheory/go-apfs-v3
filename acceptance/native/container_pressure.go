package native

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// remountAfterContainerPressure ends the pressure phase before ordinary writes.
// This is one unconditional lifecycle boundary, not a retry of a failed peer
// allocation. A successful fsck and remount do not imply an empty pending-free
// queue; the subsequent real allocations must still succeed.
// The returned attachment, when non-nil, is the only one still needing cleanup.
func (v *Verifier) remountAfterContainerPressure(ctx context.Context, att *fixture.Attachment, out schema.Output, raw string) (*fixture.Attachment, error) {
	want, err := containerMountInventory(att)
	if err != nil {
		return att, fmt.Errorf("pressure boundary initial inventory: %w", err)
	}
	proof := filepath.Join(want["Reserved"].Mount, filepath.FromSlash(reservationProofPath))
	before, err := v.Vol.Lstat(proof)
	if err != nil {
		return att, fmt.Errorf("pressure boundary stat protected allocation %q: %w", proof, err)
	}
	for _, volume := range att.Volumes {
		if err := v.Disk.Unmount(ctx, volume); err != nil {
			return att, fmt.Errorf("pressure boundary unmount volume %q: %w", volume.Name, err)
		}
	}
	if err := v.Disk.Detach(ctx, att); err != nil {
		// Do not retry this failed boundary operation in caller cleanup.
		return nil, fmt.Errorf("pressure boundary detach writable copy: %w", err)
	}
	if err := v.fsckRaw(ctx, raw, "apfs"); err != nil {
		return nil, fmt.Errorf("pressure boundary read-only filesystem check: %w", err)
	}
	att, err = v.Disk.Attach(ctx, raw, fixture.AttachOptions{Raw: true})
	if err != nil {
		return nil, fmt.Errorf("pressure boundary reattach writable copy: %w", err)
	}
	got, err := containerMountInventory(att)
	if err != nil {
		return att, fmt.Errorf("pressure boundary remount inventory: %w", err)
	}
	if len(got) != len(want) {
		return att, fmt.Errorf("pressure boundary volume count changed from %d to %d", len(want), len(got))
	}
	for name, original := range want {
		actual, ok := got[name]
		if !ok || actual.UUID != original.UUID || actual.FS != original.FS || actual.Role != original.Role {
			return att, fmt.Errorf("pressure boundary identity changed for volume %q", name)
		}
	}
	for _, volume := range att.Volumes {
		if err := v.Disk.Mount(ctx, volume, "owners,noatime", want[volume.Name].Mount, false); err != nil {
			return att, fmt.Errorf("pressure boundary remount volume %q: %w", volume.Name, err)
		}
		if volume.Mount != want[volume.Name].Mount {
			return att, fmt.Errorf("pressure boundary volume %q mounted at %q, require %q", volume.Name, volume.Mount, want[volume.Name].Mount)
		}
	}
	for _, name := range []string{"Limited", out.Expect.Container.EmptyVolumes[0]} {
		pressure := filepath.Join(att.Volume(name).Mount, "container-continuation", "pressure")
		if _, err := v.Vol.Lstat(pressure); !errors.Is(err, fs.ErrNotExist) {
			if err == nil {
				err = fmt.Errorf("released pressure file is still present")
			}
			return att, fmt.Errorf("pressure boundary volume %q confirm released pressure %q: %w", name, pressure, err)
		}
	}
	reserved := att.Volume("Reserved")
	if err := v.checkReservedAllocation(reserved, reservationProofData()); err != nil {
		return att, fmt.Errorf("pressure boundary retained proof: %w", err)
	}
	after, err := v.Vol.Lstat(filepath.Join(reserved.Mount, filepath.FromSlash(reservationProofPath)))
	if err != nil {
		return att, fmt.Errorf("pressure boundary stat remounted proof: %w", err)
	}
	// Allocation may be laid out differently; its required physical size was
	// checked above. Every identity and user metadata field must remain exact.
	before.Allocated = after.Allocated
	if before != after {
		return att, fmt.Errorf("pressure boundary protected allocation identity or metadata changed: before %+v, after %+v", before, after)
	}
	return att, nil
}

func containerMountInventory(att *fixture.Attachment) (map[string]fixture.AttachedVolume, error) {
	if att == nil || len(att.Volumes) == 0 {
		return nil, fmt.Errorf("no volumes discovered")
	}
	volumes := make(map[string]fixture.AttachedVolume, len(att.Volumes))
	identities := map[string]bool{}
	for _, volume := range att.Volumes {
		if volume == nil || volume.Name == "" || volume.UUID == "" || volume.FS != "apfs" || volume.Locked {
			return nil, fmt.Errorf("missing, unnamed, unidentified, locked or non-APFS volume")
		}
		identity := strings.ToUpper(volume.UUID)
		if _, exists := volumes[volume.Name]; exists || identities[identity] {
			return nil, fmt.Errorf("duplicate volume name or UUID for %q", volume.Name)
		}
		volumes[volume.Name], identities[identity] = *volume, true
	}
	return volumes, nil
}
