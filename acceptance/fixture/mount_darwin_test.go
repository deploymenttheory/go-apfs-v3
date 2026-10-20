//go:build darwin

package fixture

import (
	"strings"
	"testing"
)

func TestMountedFromReportsTheDeviceBehindAMountPoint(t *testing.T) {
	from, err := mountedFrom("/")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(from, "/dev/disk") {
		t.Fatalf("the root filesystem is mounted from %q, want a /dev/disk device", from)
	}
}
