package fixture

import (
	"bytes"
	"os/exec"
	"testing"
)

// This is a read-only checkout-filter check: native evidence must survive a
// Windows-style Git checkout without rewriting any captured byte or digest.
func TestCapturedEvidenceSurvivesGitCheckoutFiltersWithoutByteConversion(t *testing.T) {
	git := func(args ...string) []byte {
		t.Helper()
		out, err := exec.Command("git", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("read-only git %v: %v: %s", args, err, out)
		}
		return out
	}
	names := bytes.Split(bytes.TrimSuffix(git("ls-files", "-z", "--", "testdata/"), []byte{0}), []byte{0})
	if len(names) == 0 || len(names[0]) == 0 {
		t.Fatal("no captured evidence files were available for the checkout contract")
	}
	for _, name := range names {
		path := "HEAD:acceptance/fixture/" + string(name)
		original := git("cat-file", "blob", path)
		filtered := git("-c", "core.autocrlf=true", "-c", "core.eol=crlf", "cat-file", "--filters", path)
		if !bytes.Equal(original, filtered) {
			t.Fatalf("Git checkout filters changed original evidence %s", name)
		}
	}
}
