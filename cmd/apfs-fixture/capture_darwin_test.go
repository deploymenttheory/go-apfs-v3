//go:build fixture && darwin

package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCaptureRefusesUnsupportedProducerBeforeSetup(t *testing.T) {
	// Even a regression of producer validation cannot invoke a native command
	// here: the disposable-host guard is deliberately closed in this control.
	t.Setenv("APFS_NATIVE_DISPOSABLE_VM", "")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("RUNNER_ENVIRONMENT", "")
	for _, major := range []int{15, -1, 28} {
		t.Run(fmt.Sprint(major), func(t *testing.T) {
			root := t.TempDir()
			out, bundle := filepath.Join(root, "out"), filepath.Join(root, "bundle")
			err := capture(context.Background(), []string{"--expect-major", fmt.Sprint(major), "--output", out, "--bundle-dir", bundle, "--recipes", filepath.Join(root, "absent-recipes")})
			if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("unsupported capture macOS major %d", major)) {
				t.Fatal("unsupported producer reached capture setup", err)
			}
			for _, path := range []string{out, bundle} {
				if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
					t.Fatal("refused capture created an output", path, err)
				}
			}
		})
	}
}
