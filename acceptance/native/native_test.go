//go:build native && darwin

package native

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// newVerifier builds the verifier from the environment the CI job sets:
//
//	APFS_EXPECT_MAJOR   the macOS major version this job must run on
//	APFS_HOST_OUTPUTS   directory holding outputs-linux/ and outputs-windows/
//	APFS_OUTPUT_DIR     this host's own outputs directory
//	APFS_PRODUCT_CLI    path to the built product binary
func newVerifier(t *testing.T) *Verifier {
	t.Helper()
	if err := fixture.RequireDisposableHost(); err != nil {
		t.Fatal(err)
	}
	major, _ := strconv.Atoi(os.Getenv("APFS_EXPECT_MAJOR"))
	if major == 0 {
		t.Fatal("APFS_EXPECT_MAJOR is required")
	}
	commander := fixture.Exec{}
	producer, err := fixture.IdentifyProducer(context.Background(), commander, major, "")
	if err != nil {
		t.Fatal(err)
	}
	c, err := corpus.Resolve(context.Background(), corpus.Options{Root: filepath.Join("..", "..")})
	if err != nil {
		t.Fatal(err)
	}
	cases, err := c.Cases()
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]corpus.Case{}
	for _, k := range cases {
		byKey[CaseKey(schema.CaseRef{Producer: k.Producer, Recipe: k.Recipe, Profile: k.Profile, Stage: k.Stage})] = k
	}
	recipes, err := schema.LoadRecipes(filepath.Join("..", "recipes"))
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]schema.Recipe{}
	for _, r := range recipes {
		byName[r.Name] = r
	}
	drift, err := schema.ReadKnownDrift(filepath.Join("..", "known-drift.json"))
	if err != nil {
		t.Fatal(err)
	}
	dirs := map[string]string{"darwin": os.Getenv("APFS_OUTPUT_DIR")}
	if root := os.Getenv("APFS_HOST_OUTPUTS"); root != "" {
		for _, host := range []string{"linux", "windows"} {
			dirs[host] = filepath.Join(root, "outputs-"+host)
		}
	}
	hosts, err := LoadOutputs(dirs)
	if err != nil {
		t.Fatal(err)
	}
	product := os.Getenv("APFS_PRODUCT_CLI")
	if _, err := os.Stat(product); err != nil {
		t.Fatalf("APFS_PRODUCT_CLI: %v", err)
	}
	work, err := os.MkdirTemp("", "apfs-native-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(work) })
	return &Verifier{Major: major, Corpus: c, Cases: byKey, Hosts: hosts, Recipes: byName, Drift: drift, Product: product, Work: work, Disk: &fixture.HostDisk{C: commander, T: &fixture.Transcript{}}, Vol: fixture.HostVolume{}, C: commander, Producer: producer}
}

// TestOutputsWithAppleTools pairs every host's outputs, requires plaintext
// byte equality and encrypted device equality, then verifies, checks,
// mounts and reads back every output and runs the continuation on those
// that ask for it.
func TestOutputsWithAppleTools(t *testing.T) {
	v := newVerifier(t)
	pairs, err := Pair(v.Hosts)
	if err != nil {
		t.Fatal(err)
	}
	summary := []string{"| output | hosts | verdict |", "| --- | --- | --- |"}
	for _, p := range pairs {
		p := p
		t.Run(p.Name, func(t *testing.T) {
			ctx := context.Background()
			diffs, err := v.VerifyOutput(ctx, p)
			if err != nil {
				summary = append(summary, fmt.Sprintf("| %s | %d | error: %v |", p.Name, len(p.ByHost), err))
				t.Fatal(err)
			}
			for _, d := range diffs {
				t.Error(d)
			}
			verdict := "ok"
			if len(diffs) > 0 {
				verdict = fmt.Sprintf("%d differences", len(diffs))
			}
			if p.Output.Expect.Continuation && len(diffs) == 0 {
				k := v.Cases[CaseKey(p.Output.Source)]
				if _, err := v.Continuation(ctx, p, schemaCase{recipe: v.Recipes[k.Recipe]}); err != nil {
					t.Error(err)
					verdict = "continuation failed"
				} else {
					verdict += ", continuation ok"
				}
			}
			summary = append(summary, fmt.Sprintf("| %s | %d | %s |", p.Name, len(p.ByHost), verdict))
		})
	}
	writeSummary(t, "Outputs verified on macOS "+strconv.Itoa(v.Major), summary)
}

// TestFixturesFromOtherVersionsReadIdentically mounts every fixture that
// another macOS version produced and compares this kernel's view with the
// recorded one. Differences must be in known-drift.json.
func TestFixturesFromOtherVersionsReadIdentically(t *testing.T) {
	v := newVerifier(t)
	cases, err := v.Corpus.Cases()
	if err != nil {
		t.Fatal(err)
	}
	summary := []string{"| fixture | producer | known drift | unexplained |", "| --- | --- | --- | --- |"}
	for _, k := range cases {
		k := k
		if k.Producer == v.Major || len(k.Observation.Views) == 0 {
			continue
		}
		t.Run(fmt.Sprintf("macos-%d/%s/%s/%s", k.Producer, k.Recipe, k.Profile, k.Stage), func(t *testing.T) {
			known, unknown, err := v.CrossVersionDrift(context.Background(), k)
			if err != nil {
				t.Fatal(err)
			}
			for _, d := range unknown {
				t.Errorf("unexplained difference from macOS %d: %s", k.Producer, d)
			}
			var knownText []string
			for _, d := range known {
				knownText = append(knownText, d.Path+" "+d.Field)
			}
			summary = append(summary, fmt.Sprintf("| %s/%s/%s | macOS %d | %s | %d |", k.Recipe, k.Profile, k.Stage, k.Producer, strings.Join(knownText, "<br>"), len(unknown)))
		})
	}
	writeSummary(t, "Cross-version parity on macOS "+strconv.Itoa(v.Major), summary)
}

func writeSummary(t *testing.T, title string, rows []string) {
	path := os.Getenv("GITHUB_STEP_SUMMARY")
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		t.Logf("summary: %v", err)
		return
	}
	defer func() { _ = f.Close() }()
	fmt.Fprintf(f, "## %s\n\n%s\n\n", title, strings.Join(rows, "\n"))
}
