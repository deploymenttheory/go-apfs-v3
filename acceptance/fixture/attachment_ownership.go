package fixture

import "fmt"

// AttachmentOwnership distinguishes permission to act from evidence of release.
// In particular, leaving a foreign device alone does not release our image.
type AttachmentOwnership string

const (
	// OwnershipUnknown means the available evidence cannot establish identity or release.
	OwnershipUnknown AttachmentOwnership = "unknown"
	// OwnershipOwned binds the complete image identity to the current device.
	OwnershipOwned AttachmentOwnership = "owned"
	// OwnershipForeign identifies a different image at the expected device.
	OwnershipForeign AttachmentOwnership = "foreign"
	// OwnershipAbsent requires corroborated absence from independent kernel scopes.
	OwnershipAbsent AttachmentOwnership = "absent"
)

// AttachmentOwnershipError refuses cleanup without losing a failed proof's cause.
// Callers must not release a backing image after a foreign or unknown result.
type AttachmentOwnershipError struct {
	State  AttachmentOwnership
	Device string
	Image  string
	Cause  error
}

func (e *AttachmentOwnershipError) Error() string {
	message := fmt.Sprintf("attachment %s for %q is %s; release is not established", e.Device, e.Image, e.State)
	if e.Cause != nil {
		message += ": " + e.Cause.Error()
	}
	return message
}

func (e *AttachmentOwnershipError) Unwrap() error { return e.Cause }

func (d *HostDisk) imageOwnership(native, expected string) (AttachmentOwnership, error) {
	match, err := d.imagePathsMatch(native, expected)
	if err != nil {
		return OwnershipUnknown, err
	}
	if match {
		return OwnershipOwned, nil
	}
	return OwnershipForeign, nil
}
