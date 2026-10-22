package fixture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// mountIdentity is the kernel's identity of the filesystem containing a path.
// Source stays opaque: snapshot sources need not use a particular device syntax.
type mountIdentity struct {
	MountPoint string   `json:"mountPoint"`
	Source     string   `json:"source"`
	FSID       [2]int32 `json:"fsid"`
}

// mountedFrom retains the ordinary volume-mount probe's existing behavior:
// an unmounted directory reports the source of its enclosing filesystem.
func mountedFrom(path string) (string, error) {
	identity, err := mountedFilesystem(path)
	return identity.Source, err
}

func canonicalMountPath(path string) (string, error) {
	if path == "" {
		return "", errors.New("empty snapshot mount path")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
}

// snapshotMountIdentity records a fresh kernel observation and its disposition.
// Initial cleanup requires an exact private pin. After a real busy unmount, a
// containing filesystem proves that pin has disappeared; another identity at
// the exact pin is never eligible for a second unmount. This guards continuity
// of a caller-owned private mount path, not global backing-image ownership.
func (d *HostDisk) snapshotMountIdentity(ctx context.Context, pin string, expected *mountIdentity) (mountIdentity, bool, error) {
	if err := ctx.Err(); err != nil {
		return mountIdentity{}, false, err
	}
	probe := d.mountProbe
	if probe == nil {
		probe = mountedFilesystem
	}
	identity, err := probe(pin)
	receipt := struct {
		Native              mountIdentity  `json:"native"`
		Expected            *mountIdentity `json:"expected,omitempty"`
		CanonicalPin        string         `json:"canonicalPin"`
		CanonicalMountPoint string         `json:"canonicalMountPoint,omitempty"`
		Outcome             string         `json:"outcome"`
	}{Native: identity, Expected: expected, CanonicalPin: pin, Outcome: "refused"}
	if ctx.Err() != nil {
		err = errors.Join(err, ctx.Err())
	}
	if err == nil && (identity.Source == "" || strings.ContainsRune(identity.Source, 0) || !filepath.IsAbs(identity.MountPoint) || strings.ContainsRune(identity.MountPoint, 0)) {
		err = errors.New("kernel mount identity is incomplete or malformed")
	}
	if err == nil {
		identity.MountPoint, err = canonicalMountPath(identity.MountPoint)
		receipt.CanonicalMountPoint = identity.MountPoint
	}
	gone := false
	if err == nil {
		switch {
		case identity.MountPoint != pin:
			rel, relErr := filepath.Rel(identity.MountPoint, pin)
			if expected != nil && relErr == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel) {
				gone, receipt.Outcome = true, "gone"
			} else {
				err = fmt.Errorf("snapshot mount identity does not name the exact pin %q: %q", pin, identity.MountPoint)
			}
		case expected != nil && identity != *expected:
			err = fmt.Errorf("snapshot mount identity changed at %q", pin)
		case expected == nil:
			receipt.Outcome = "captured"
		default:
			receipt.Outcome = "unchanged"
		}
	}
	if ctx.Err() != nil {
		err, gone, receipt.Outcome = errors.Join(err, ctx.Err()), false, "cancelled"
	}
	recordErr := d.T.RecordFS("snapshot-mount-identity", []string{"statfs", pin}, err, "0")
	data, marshalErr := json.Marshal(receipt)
	entry := &d.T.Commands[len(d.T.Commands)-1]
	entry.StdoutSHA256, entry.StdoutText = digestAndText(data)
	return identity, gone, errors.Join(recordErr, marshalErr)
}
