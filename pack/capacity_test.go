package pack_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/hfsplus"
	"github.com/deploymenttheory/go-apfs-v3/pack"
	"github.com/deploymenttheory/go-apfs-v3/session"
)

// Check the final on-disk allocation counts, after capacity-dependent metadata
// is placed. Native acceptance separately proves this space is usable by Apple.
func TestAutomaticCapacityRetainsPaddingAfterLayout(t *testing.T) {
	for _, format := range []string{"APFS", "HFS+"} {
		for _, payload := range []int64{8 << 20, 64 << 20} {
			t.Run(fmt.Sprintf("%s/%dMiB", format, payload>>20), func(t *testing.T) {
				ctx := context.Background()
				s, options := inputFormat(t, format)
				host := filepath.Join(t.TempDir(), "large")
				file, err := os.Create(host)
				if err != nil {
					t.Fatal(err)
				}
				err = file.Truncate(payload)
				closeErr := file.Close()
				if err != nil || closeErr != nil {
					t.Fatal(err, closeErr)
				}
				if _, err = s.Copy(ctx, []string{host}, "/large", session.CopyOptions{FromHost: true}); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(t.TempDir(), "automatic.dmg")
				if _, err = pack.Create(ctx, path, s, options); err != nil {
					t.Fatal(err)
				}
				image, err := diskimage.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				defer image.Close()
				section, err := image.Partition(0)
				if err != nil {
					t.Fatal(err)
				}
				var free, padding uint64
				if format == "APFS" {
					// The fresh checkpoint places its spaceman at block 10.
					// spaceman_device_t.sm_free_count is at object offset 0x48.
					object := make([]byte, 4096)
					if _, err = section.ReadAt(object, 10*4096); err != nil {
						t.Fatal(err)
					}
					if binary.LittleEndian.Uint32(object[24:])&0xffff != 5 {
						t.Fatal("missing fresh space manager")
					}
					free = binary.LittleEndian.Uint64(object[0x48:]) * 4096
					padding = 8 << 20
				} else {
					volume, err := hfsplus.Open(section)
					if err != nil {
						t.Fatal(err)
					}
					free = uint64(volume.FreeBlocks) * uint64(volume.BlockSize)
					padding = 2 << 20
				}
				if minimum := padding + uint64(payload)/8; free < minimum {
					t.Fatalf("final layout lost padding: free %d, require at least %d", free, minimum)
				}
				// Explicit capacity keeps the requested block-rounded size,
				// without applying the automatic growth allowance.
				options.Volume.Capacity = payload + 2<<20 + 1
				if report, err := pack.Write(ctx, io.Discard, s, options); err != nil || report.VolumeBytes != payload+2<<20+4096 {
					t.Fatal("explicit capacity changed", report, err)
				}
			})
		}
	}
}
