// Command apfs-fixture captures the Apple fixture corpus: it executes recipes
// with Apple tools and system calls on macOS and records what the kernel
// reports. It never imports the product packages.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// captureCommand is installed by capture_darwin.go when built with
// -tags fixture on macOS; elsewhere it explains the requirement.
var captureCommand = func(context.Context, []string) error {
	return fmt.Errorf("capture requires macOS and a build with -tags fixture")
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch os.Args[1] {
	case "capture":
		err = captureCommand(ctx, os.Args[2:])
	case "digest":
		err = digest(os.Args[2:])
	case "lock":
		err = lock(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "apfs-fixture:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  apfs-fixture capture --recipes DIR --expect-major N --output DIR --bundle-dir DIR [--profile ID] [RECIPE ...]
  apfs-fixture digest --recipes DIR
  apfs-fixture lock --recipes DIR --release TAG --run URL --bundles DIR [--out acceptance/fixtures.lock.json]

capture needs a build with -tags fixture on macOS; digest and lock run anywhere.`)
}

func digest(args []string) error {
	fs := flag.NewFlagSet("digest", flag.ContinueOnError)
	recipes := fs.String("recipes", "acceptance/recipes", "recipe directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	sum, err := schema.TreeDigest(*recipes)
	if err != nil {
		return err
	}
	fmt.Println(sum)
	return nil
}

var bundleName = regexp.MustCompile(`^fixtures-macos-(\d+)-[0-9a-f]{16}\.tar\.gz$`)

// lock writes fixtures.lock.json from the bundles a capture produced. Each
// bundle is extracted to read its manifest so the lock records the exact
// producer build and refuses a bundle captured from other recipes.
func lock(args []string) error {
	fs := flag.NewFlagSet("lock", flag.ContinueOnError)
	recipes := fs.String("recipes", "acceptance/recipes", "recipe directory")
	release := fs.String("release", "", "release tag the bundles are published under")
	run := fs.String("run", "", "capture run URL")
	bundles := fs.String("bundles", "", "directory holding fixtures-macos-<major>-<digest>.tar.gz")
	out := fs.String("out", filepath.Join("acceptance", "fixtures.lock.json"), "lock file to write")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *release == "" || *bundles == "" {
		return fmt.Errorf("--release and --bundles are required")
	}
	digest, err := schema.TreeDigest(*recipes)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(*bundles)
	if err != nil {
		return err
	}
	l := schema.Lock{Schema: schema.LockSchema, Release: *release, RecipesSHA256: digest, Bundles: map[string]schema.Bundle{}}
	for _, entry := range entries {
		m := bundleName.FindStringSubmatch(entry.Name())
		if m == nil {
			continue
		}
		major, _ := strconv.Atoi(m[1])
		if !schema.IsSupportedProducer(major) {
			continue
		}
		path := filepath.Join(*bundles, entry.Name())
		sum, err := schema.FileDigest(path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		tmp, err := os.MkdirTemp("", "lock-")
		if err != nil {
			return err
		}
		if err := fixture.ExtractBundle(path, tmp, 4<<30); err != nil {
			return err
		}
		data, err := os.ReadFile(filepath.Join(tmp, "manifest.json"))
		if err != nil {
			return err
		}
		_ = os.RemoveAll(tmp)
		var manifest schema.Manifest
		if err := schema.DecodeStrict(data, &manifest); err != nil {
			return fmt.Errorf("%s: %w", entry.Name(), err)
		}
		if manifest.Producer.Major != major {
			return fmt.Errorf("%s was produced on macOS %d", entry.Name(), manifest.Producer.Major)
		}
		if manifest.Recipes != digest {
			return fmt.Errorf("%s was captured from recipes %s; the tree is %s", entry.Name(), manifest.Recipes, digest)
		}
		key := "macos-" + strconv.Itoa(major)
		if _, dup := l.Bundles[key]; dup {
			return fmt.Errorf("two bundles for %s", key)
		}
		l.Bundles[key] = schema.Bundle{Asset: entry.Name(), SHA256: sum, Bytes: info.Size(), Build: manifest.Producer.Build, CaptureRun: *run}
	}
	for _, major := range schema.Producers {
		if _, ok := l.Bundles["macos-"+strconv.Itoa(major)]; !ok {
			return fmt.Errorf("no bundle for macos-%d; every producer is required", major)
		}
	}
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(*out, append(data, '\n'), 0o644)
}
