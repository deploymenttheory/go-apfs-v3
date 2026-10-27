package fixture

import (
	"context"
	"fmt"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// ValidateAPFSVerification requires a complete decrypted filesystem check,
// including every retained snapshot, from Disk Management's crypto context.
func ValidateAPFSVerification(output, device string, volume *schema.APFSVolume) error {
	for _, stage := range []string{
		"Checking the container superblock", "Checking the checkpoint with transaction ID ",
		"Checking the space manager", "Checking the space manager free queue trees",
		"Checking the encryption key structures", "Checking the APFS volume superblock",
		"Checking the object map", "Checking the snapshot metadata tree",
		"Checking the snapshot metadata", "Checking the fsroot tree",
		"Checking the extent ref tree", "Verifying volume object map space",
		"Verifying allocated space", "File system check exit code is 0",
		fmt.Sprintf("The volume %s with UUID %s appears to be OK", device, volume.VolumeUUID),
	} {
		if !strings.Contains(output, stage) {
			return fmt.Errorf("APFS verification of %s lacks %q", volume.VolumeUUID, stage)
		}
	}
	for _, snapshot := range volume.Snapshots {
		if !strings.Contains(output, fmt.Sprintf("(%s, transaction ID %d)", snapshot.Name, snapshot.XID)) {
			return fmt.Errorf("APFS verification omitted snapshot %s at %d", snapshot.Name, snapshot.XID)
		}
	}
	for _, failure := range []string{"skipping", "warning:", "error:"} {
		if strings.Contains(strings.ToLower(output), failure) {
			return fmt.Errorf("APFS verification of %s reported %s", volume.VolumeUUID, failure)
		}
	}
	return nil
}

// observeAPFSVolumeChecks checks every APFS volume when an encrypted peer makes
// a bare container fsck unsuitable. Observe has already unlocked each volume.
func observeAPFSVolumeChecks(ctx context.Context, in ObserveInput, obs *schema.Observation) error {
	disk, ok := in.Disk.(*HostDisk)
	if !ok {
		return fmt.Errorf("APFS verification requires a native disk adapter")
	}
	for _, wanted := range obs.Volumes {
		if wanted.APFS == nil {
			continue
		}
		var volume *AttachedVolume
		for _, found := range in.Att.Volumes {
			if found.Dev == wanted.Device && strings.EqualFold(found.UUID, wanted.APFS.VolumeUUID) {
				volume = found
				break
			}
		}
		if volume == nil {
			return fmt.Errorf("verification lacks expected APFS volume %s", wanted.APFS.VolumeUUID)
		}
		output, err := disk.run(ctx, "fsck", false, nil, "diskutil", "verifyVolume", volume.Dev)
		if err != nil {
			return err
		}
		if err := ValidateAPFSVerification(string(output), volume.RDev, wanted.APFS); err != nil {
			return err
		}
		xid := SelectedXID(string(output))
		if xid == 0 || (obs.Checks.SelectedXID != 0 && obs.Checks.SelectedXID != xid) {
			return fmt.Errorf("APFS volume %s selected inconsistent checkpoint %d", wanted.APFS.VolumeUUID, xid)
		}
		obs.Checks.SelectedXID = xid
		if result := lastCommandResult(in.T, "fsck"); result != nil {
			obs.Checks.Fsck = append(obs.Checks.Fsck, *result)
		}
	}
	return nil
}
