//go:build native && darwin

package native

import (
	"context"
	_ "embed"
	"os"
	"path/filepath"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
)

//go:embed testdata/appledouble_unpack.c
var appleDoubleUnpackSource []byte

func buildAppleDoubleUnpacker(ctx context.Context, c fixture.Commander, work string) (string, error) {
	if err := fixture.RequireDisposableHost(); err != nil {
		return "", err
	}
	dir := filepath.Join(work, "appledouble-helper")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	source, binary := filepath.Join(dir, "appledouble_unpack.c"), filepath.Join(dir, "appledouble-unpack")
	if err := os.WriteFile(source, appleDoubleUnpackSource, 0644); err != nil {
		return "", err
	}
	cmd := fixture.Command{Label: "build AppleDouble unpack adapter", Argv: []string{"xcrun", "clang", "-Wall", "-Wextra", "-Werror", source, "-o", binary}, Expected: "0"}
	t := &fixture.Transcript{}
	if err := t.Record(cmd, c.Run(ctx, cmd)); err != nil {
		return "", err
	}
	return binary, nil
}
