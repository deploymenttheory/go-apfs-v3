package acceptance_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

func TestMultipleVolumeEditingRefusesMissingAndUnknownSelectors(t *testing.T) {
	cases, _ := loadCorpus(t)
	seen := map[int]bool{}
	for _, k := range cases {
		if k.Recipe != "container-volumes" || k.Stage != "final" {
			continue
		}
		seen[k.Producer] = true
		t.Run(fmt.Sprintf("macos-%d", k.Producer), func(t *testing.T) {
			t.Parallel()
			source := fixtureImage(t, k)
			digest := packingFileDigest(t, source)
			for _, control := range []struct {
				name, volume string
				want         error
			}{
				{name: "missing", want: fs.ErrInvalid},
				{name: "unknown", volume: "00000000-0000-4000-8000-000000000001", want: fs.ErrNotExist},
			} {
				t.Run(control.name, func(t *testing.T) {
					destination := filepath.Join(t.TempDir(), "refused.dmg")
					_, err := imageedit.Apply(context.Background(), source, destination,
						imageedit.Options{Volume: control.volume, Format: "UDZO", Time: fixedClock},
						[]imageedit.Change{{Operation: "chmod", Path: "/Fixture/Name", Mode: "0600"}})
					if !errors.Is(err, control.want) {
						t.Fatalf("volume selection returned %v, want %v", err, control.want)
					}
					if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("refused selection published an output: %v", err)
					}
					if got := packingFileDigest(t, source); got != digest {
						t.Fatal("refused selection changed the native multi-volume image")
					}
				})
			}
		})
	}
	for _, producer := range schema.Producers {
		if !seen[producer] {
			t.Fatalf("corpus has no multi-volume selection control from macOS %d", producer)
		}
	}
}
