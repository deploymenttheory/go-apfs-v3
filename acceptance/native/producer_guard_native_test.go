//go:build native && darwin

package native

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeVerifierRefusesUnsupportedProducerBeforeSetup(t *testing.T) {
	// Both the old and the new setup paths are prevented from invoking native
	// tools; this tests the earlier supported-producer refusal, not a live host.
	t.Setenv("APFS_NATIVE_DISPOSABLE_VM", "")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("RUNNER_ENVIRONMENT", "")
	for _, major := range []int{15, -1, 28} {
		t.Run(fmt.Sprint(major), func(t *testing.T) {
			t.Setenv("APFS_EXPECT_MAJOR", fmt.Sprint(major))
			work := filepath.Join(t.TempDir(), "work")
			t.Setenv("APFS_NATIVE_WORK", work)
			v, err := buildVerifier()
			if v != nil || err == nil || !strings.Contains(err.Error(), fmt.Sprintf("unsupported native verification macOS major %d", major)) {
				t.Fatal("unsupported producer reached verifier setup", err)
			}
			if _, err := os.Stat(work); !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("refused verifier created its work directory", err)
			}
		})
	}
}
