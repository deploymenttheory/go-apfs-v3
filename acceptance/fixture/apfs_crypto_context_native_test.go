//go:build native && darwin

package fixture

import (
	"context"
	"encoding/json"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// Run the unchanged original retained -> edited recipe through the real
// Capture pipeline, including observation, key state, parent attach, auto-mount
// and the next stage's explicit unlock. The projection is diagnostic only.
func TestAPFSObservationReleasesKeysForNextStage(t *testing.T) {
	if err := RequireDisposableHost(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	major, err := strconv.Atoi(os.Getenv("APFS_EXPECT_MAJOR"))
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := schema.FileDigest(executable)
	if err != nil {
		t.Fatal(err)
	}
	producer, err := IdentifyProducer(ctx, Exec{}, major, digest)
	if err != nil {
		t.Fatal(err)
	}
	recipes, err := schema.LoadRecipes("../recipes")
	if err != nil {
		t.Fatal(err)
	}
	root := os.Getenv("APFS_NATIVE_WORK")
	if root == "" {
		t.Fatal("explicit evidence path required")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	for _, recipe := range recipes {
		if recipe.Name != "encrypted-snapshot-history" {
			continue
		}
		if len(recipe.Stages) < 2 || recipe.Stages[0].Name != "retained" || recipe.Stages[1].Name != "edited" {
			t.Fatal("original stage sequence changed")
		}
		originalDigest, err := schema.FileDigest("../recipes/encrypted-snapshot-history.json")
		if err != nil {
			t.Fatal(err)
		}
		recipe.Stages, recipe.Derive = recipe.Stages[:2], nil
		projection := struct {
			OriginalSHA256 string
			Scope          string
			Recipe         schema.Recipe
		}{originalDigest, "Unchanged original retained/edited stages, APFS profile only. No complete corpus or product verdict.", recipe}
		data, err := json.MarshalIndent(projection, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "scope.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
		profile, err := schema.LookupProfile("apfs")
		if err != nil {
			t.Fatal(err)
		}
		commander := Exec{}
		capture := &Capture{Recipe: &recipe, Profile: profile, Disk: &HostDisk{C: commander, T: &Transcript{}}, Vol: HostVolume{}, C: commander, Work: t.TempDir(), Out: filepath.Join(root, "captured"), Payloads: "../recipes/payloads", Producer: producer}
		if err := capture.Run(ctx); err != nil {
			t.Fatal(err)
		}
		for _, stage := range []string{"retained", "edited"} {
			if _, err := os.Stat(filepath.Join(capture.Out, "apfs."+stage+".observation.json")); err != nil {
				t.Fatal(err)
			}
		}
		t.Log("native observation and next writable-stage unlock both completed through the actual collector")
		return
	}
	t.Fatal("original native encrypted history recipe missing")
}
