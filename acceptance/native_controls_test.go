package acceptance_test

import (
	"os"
	"testing"

	inputs "github.com/deploymenttheory/go-apfs-v3/internal/qualification/replay"
)

// Fixture locations and source versions do not express which later capture
// controls are required. Fresh CI declares these independently; retained inputs
// keep their original obligations when moved through the corpus resolver.
func requireNativeControl(t *testing.T, name string) bool {
	t.Helper()
	required, err := inputs.RequiredControls(os.Getenv("APFS_REQUIRED_CONTROLS"))
	if err != nil {
		t.Fatal(err)
	}
	return required[name]
}

func nativeInput(t testing.TB, environment, fallback string) string {
	t.Helper()
	root, err := inputs.InputPath(environment, fallback)
	if err != nil {
		t.Fatal(err)
	}
	return root
}
