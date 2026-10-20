//go:build fixture && darwin

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func init() { captureCommand = capture }

func capture(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("capture", flag.ContinueOnError)
	recipesDir := fs.String("recipes", "acceptance/recipes", "recipe directory")
	major := fs.Int("expect-major", 0, "macOS major version this host must be")
	output := fs.String("output", "", "directory receiving images and observations")
	bundleDir := fs.String("bundle-dir", "", "directory receiving the bundle")
	profile := fs.String("profile", "", "capture only this profile")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *major == 0 || *output == "" || *bundleDir == "" {
		return fmt.Errorf("--expect-major, --output and --bundle-dir are required")
	}
	if err := fixture.RequireDisposableHost(); err != nil {
		return err
	}
	recipes, err := schema.LoadRecipes(*recipesDir)
	if err != nil {
		return err
	}
	selected := map[string]bool{}
	for _, name := range fs.Args() {
		selected[name] = true
	}
	if len(selected) == 0 {
		for _, r := range recipes {
			selected[r.Name] = true
		}
	}
	recipesDigest, err := schema.TreeDigest(*recipesDir)
	if err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	selfDigest, err := schema.FileDigest(self)
	if err != nil {
		return err
	}
	commander := fixture.Exec{}
	producer, err := fixture.IdentifyProducer(ctx, commander, *major, selfDigest)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*output, 0o755); err != nil {
		return err
	}
	work, err := os.MkdirTemp("", "apfs-fixture-")
	if err != nil {
		return err
	}
	var helperNames []string
	for _, r := range recipes {
		if selected[r.Name] {
			helperNames = append(helperNames, r.Requires.Helpers...)
		}
	}
	helpers, err := fixture.BuildHelpers(ctx, commander, filepath.Join(*recipesDir, "helpers"), filepath.Join(work, "helpers"), helperNames)
	if err != nil {
		return err
	}
	var failures []string
	for i := range recipes {
		r := &recipes[i]
		if !selected[r.Name] {
			continue
		}
		for _, id := range r.Profiles {
			if *profile != "" && id != *profile {
				continue
			}
			p, err := schema.LookupProfile(id)
			if err != nil {
				return err
			}
			caseWork := filepath.Join(work, r.Name, id)
			c := &fixture.Capture{Recipe: r, Profile: p, Disk: &fixture.HostDisk{C: commander, T: &fixture.Transcript{}}, Vol: fixture.HostVolume{}, C: commander,
				Work: caseWork, Out: filepath.Join(*output, r.Name), Payloads: filepath.Join(*recipesDir, "payloads"), Helpers: helpers, Producer: producer}
			fmt.Fprintf(os.Stderr, "== %s %s\n", r.Name, id)
			if err := c.Run(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "FAIL %s %s: %v\n", r.Name, id, err)
				failures = append(failures, fmt.Sprintf("%s/%s: %v", r.Name, id, err))
				continue
			}
			_ = os.RemoveAll(caseWork)
		}
	}
	if len(failures) > 0 {
		sort.Strings(failures)
		for _, f := range failures {
			fmt.Fprintln(os.Stderr, f)
		}
		return fmt.Errorf("%d case(s) failed; no bundle written", len(failures))
	}
	manifest, err := fixture.WriteManifest(*output, producer, recipesDigest)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*bundleDir, 0o755); err != nil {
		return err
	}
	path, sum, size, err := fixture.WriteBundle(*output, *major, *bundleDir)
	if err != nil {
		return err
	}
	fmt.Printf("bundle %s sha256=%s bytes=%d cases=%d\n", path, sum, size, len(manifest.Cases))
	return nil
}
