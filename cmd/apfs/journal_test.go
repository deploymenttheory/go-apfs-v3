package main

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// Go-built HFS+ volumes are nonjournaled and APFS has no HFS journal, so every
// journal command must refuse explicitly, publish nothing and leave the source
// untouched. Interrupted Apple journals belong to the acceptance tier.
func TestJournalCommandsRefuseNonjournaledSourcesAndPreserveEvidence(t *testing.T) {
	ctx := context.Background()
	for _, format := range []string{"hfsplus", "apfs"} {
		t.Run(format, func(t *testing.T) {
			source := builtImage(t, format)
			before := fileDigest(t, source)
			output := filepath.Join(t.TempDir(), "Recovered.dmg")
			var out, diagnostics bytes.Buffer
			if err := run(ctx, []string{"journal", "inspect", "--json", "--image", source}, nil, &out, &diagnostics); !errors.Is(err, filesystem.ErrUnsupported) || out.Len() != 0 {
				t.Fatal("nonjournaled inspection", err, out.String())
			}
			if err := run(ctx, []string{"journal", "replay", "--json", "--format", "UDRO", "--image", source, "--output", output}, nil, &out, &diagnostics); !errors.Is(err, filesystem.ErrUnsupported) || out.Len() != 0 {
				t.Fatal("nonjournaled replay", err, out.String())
			}
			if _, err := os.Lstat(output); !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("refused replay published output", err)
			}
			if err := os.WriteFile(output, []byte("existing"), 0600); err != nil {
				t.Fatal(err)
			}
			for _, tc := range []struct {
				args []string
				want error
			}{
				{[]string{"journal"}, nil}, {[]string{"journal", "reset"}, nil},
				{[]string{"journal", "replay", "--image", source}, fs.ErrInvalid},
				{[]string{"journal", "inspect", "--image", source, "--output", output}, nil},
				{[]string{"journal", "replay", "--session", "build", "--image", source, "--output", output}, nil},
				{[]string{"journal", "replay", "--image", source, "--output", output}, fs.ErrExist},
				{[]string{"journal", "replay", "--image", source, "--output", source}, fs.ErrExist},
			} {
				out.Reset()
				err := run(ctx, tc.args, nil, &out, &diagnostics)
				if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) || out.Len() != 0 {
					t.Fatal("invalid journal command accepted", tc.args, err)
				}
			}
			if err := run(ctx, []string{"cat", source, "/Fixture/example.txt"}, nil, &out, &diagnostics); err != nil || out.String() != fixtureText {
				t.Fatal("ordinary reader changed by journal commands", err)
			}
			if fileDigest(t, source) != before {
				t.Fatal("journal CLI changed source evidence")
			}
			if existing, err := os.ReadFile(output); err != nil || string(existing) != "existing" {
				t.Fatal("existing output replaced", err)
			}
		})
	}
}
