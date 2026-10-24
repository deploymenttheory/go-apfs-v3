package acceptance_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/native"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
	"github.com/deploymenttheory/go-apfs-v3/appledouble"
	"github.com/deploymenttheory/go-apfs-v3/block"
)

// TestAppleDoubleMatchesNativeExports exercises both codec directions against
// every retained Apple export. The reference reader never imports the codec.
func TestAppleDoubleMatchesNativeExports(t *testing.T) {
	cases, _ := loadCorpus(t)
	seen := map[string]bool{}
	for _, k := range cases {
		if k.Recipe != "file-corpus" || k.Stage != "final" {
			continue
		}
		key := fmt.Sprintf("macos-%d/%s", k.Producer, k.Profile)
		if seen[key] || len(k.Observation.Views) != 1 || len(k.Observation.Views[0].AppleDouble) == 0 {
			t.Fatalf("missing or ambiguous AppleDouble exports for %s", key)
		}
		seen[key] = true
		for _, export := range k.Observation.Views[0].AppleDouble {
			t.Run(key+"/"+export.Path, func(t *testing.T) {
				t.Parallel()
				ctx := context.Background()
				source := filepath.Join(k.Dir, filepath.FromSlash(export.File))
				checkDigest := func() {
					t.Helper()
					if sum, err := schema.FileDigest(source); err != nil || sum != export.SHA256 {
						t.Fatalf("native export digest changed: %s (%v)", source, err)
					}
				}
				checkDigest()
				defer checkDigest()
				want, err := native.ReadAppleDoubleFile(source)
				if err != nil {
					t.Fatal(err)
				}
				file, err := block.Open(source)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { closeFixture(t, file) }()
				decoded, err := appledouble.Decode(ctx, file)
				if err != nil {
					t.Fatal(err)
				}
				got := native.AppleDoubleRecord{FinderInfo: decoded.FinderInfo, Flags: decoded.Flags, DebugTag: decoded.DebugTag, Resource: serializedValue(t, decoded.ResourceFork)}
				for _, a := range decoded.Attributes {
					got.Attributes = append(got.Attributes, native.AppleDoubleAttribute{Name: string(a.Name), Flags: a.Flags, AppleDoubleValue: serializedValue(t, a.Value)})
				}
				if diffs := native.CompareAppleDouble(got, want); len(diffs) != 0 {
					t.Fatal("decode:", diffs)
				}
				// The path digest names the filesystem entry without projecting
				// native slashes, Unicode or case collisions into artifact names.
				id := sha256.Sum256([]byte(export.Path))
				name := outputName(k, fmt.Sprintf("appledouble.%x.bin", id[:]))
				output := produceTwice(t, name, true, func(filename string) error {
					f, err := os.Create(filename)
					if err != nil {
						return err
					}
					err = appledouble.Write(ctx, f, decoded)
					if e := f.Close(); err == nil {
						err = e
					}
					return err
				})
				encoded, err := native.ReadAppleDoubleFile(output)
				if err != nil {
					t.Fatal(err)
				}
				if diffs := native.CompareAppleDouble(encoded, want); len(diffs) != 0 {
					t.Fatal("encode:", diffs)
				}
				recordOutput(t, schema.Output{Name: name, File: filepath.Base(output), Operation: "appledouble", Format: "appledouble", Source: caseRef(k), Expect: schema.Expectation{AppleDouble: &schema.AppleDoubleExpectation{Path: export.Path}}})
			})
		}
	}
	for _, major := range schema.Producers {
		for _, profile := range recipesByName(t)["file-corpus"].Profiles {
			if !seen[fmt.Sprintf("macos-%d/%s", major, profile)] {
				t.Errorf("missing AppleDouble consumer for macOS %d/%s", major, profile)
			}
		}
	}
}

func serializedValue(t *testing.T, source block.Source) native.AppleDoubleValue {
	t.Helper()
	if source == nil {
		t.Fatal("missing serialized source")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.NewSectionReader(source, 0, source.Size()))
	if err != nil || n != source.Size() {
		t.Fatalf("serialized value: read %d/%d: %v", n, source.Size(), err)
	}
	return native.AppleDoubleValue{Bytes: n, SHA256: fmt.Sprintf("%x", h.Sum(nil))}
}
