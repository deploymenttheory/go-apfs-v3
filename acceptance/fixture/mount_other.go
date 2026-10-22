//go:build !darwin

package fixture

import "errors"

// Mount verification needs statfs's mounted-from device, which only the
// darwin hosts that mount images have.
func mountedFilesystem(string) (mountIdentity, error) {
	return mountIdentity{}, errors.ErrUnsupported
}
