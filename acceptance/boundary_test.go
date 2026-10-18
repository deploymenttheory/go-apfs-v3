package acceptance_test

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

// Packages that create fixtures or verify Go output with Apple tools must not
// import the code under test. Reading an image with the same code that wrote
// it proves nothing. Every package under acceptance/ is guarded except the
// portable conformance tests themselves, which exist to call the product.
var forbiddenImportPrefixes = []string{
	"github.com/deploymenttheory/go-apfs-v3/apfs",
	"github.com/deploymenttheory/go-apfs-v3/appledouble",
	"github.com/deploymenttheory/go-apfs-v3/block",
	"github.com/deploymenttheory/go-apfs-v3/diskimage",
	"github.com/deploymenttheory/go-apfs-v3/filesystem",
	"github.com/deploymenttheory/go-apfs-v3/hfsplus",
	"github.com/deploymenttheory/go-apfs-v3/imageedit",
	"github.com/deploymenttheory/go-apfs-v3/inspect",
	"github.com/deploymenttheory/go-apfs-v3/internal/",
	"github.com/deploymenttheory/go-apfs-v3/pack",
	"github.com/deploymenttheory/go-apfs-v3/session",
	"github.com/deploymenttheory/go-apfs-v3/workspace",
}

// guardedPackages are checked with every build tag they can be built under.
var guardedPackages = []struct {
	pattern string
	tags    string
}{
	{pattern: "./schema"},
	{pattern: "./corpus"},
	{pattern: "./native", tags: "native"},
	{pattern: "../cmd/apfs-fixture", tags: "fixture"},
}

func TestFixtureAndVerifierPackagesDoNotImportTheProduct(t *testing.T) {
	for _, pkg := range guardedPackages {
		args := []string{"list", "-e", "-f", "{{.ImportPath}}{{range .Deps}} {{.}}{{end}}"}
		if pkg.tags != "" {
			args = append(args, "-tags", pkg.tags)
		}
		args = append(args, pkg.pattern)
		cmd := exec.Command("go", args...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go list %s: %v\n%s", pkg.pattern, err, stderr.String())
		}
		line := strings.TrimSpace(string(out))
		if line == "" || strings.Contains(stderr.String(), "no Go files") || strings.Contains(stderr.String(), "cannot find") {
			// A guarded package that is not in the tree yet cannot violate the
			// boundary; once it exists it is checked on every run.
			t.Logf("%s: not present yet", pkg.pattern)
			continue
		}
		fields := strings.Fields(line)
		for _, dep := range fields[1:] {
			for _, forbidden := range forbiddenImportPrefixes {
				if strings.HasPrefix(dep, forbidden) {
					t.Errorf("%s depends on %s, which is part of the product under test", fields[0], dep)
				}
			}
		}
	}
}
