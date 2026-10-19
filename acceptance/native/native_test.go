//go:build native && darwin

package native

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// newVerifier builds the verifier from the environment the CI job sets:
//
//	APFS_EXPECT_MAJOR   the macOS major version this job must run on
//	APFS_HOST_OUTPUTS   directory holding outputs-<host>-macos-<major>/ for
//	                    linux, windows and darwin, and slow-outputs-<host>/
//	APFS_PRODUCT_CLI    path to the built product binary
//	APFS_NATIVE_WORK    optional scratch directory (default: a temporary one)
//
// It also returns the output groups to verify: each group's hosts must
// agree on every output, and only outputs derived from this macOS
// version's fixtures are kept.
func newVerifier(t *testing.T) (*Verifier, []map[string]HostOutputs) {
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
	root := os.Getenv("APFS_HOST_OUTPUTS")
	if root == "" {
		t.Fatal("APFS_HOST_OUTPUTS is required")
	}
	main := map[string]string{}
	for _, host := range []string{"linux", "windows", "darwin"} {
		main[host] = filepath.Join(root, fmt.Sprintf("outputs-%s-macos-%d", host, major))
	}
	slow := map[string]string{}
	for _, host := range []string{"linux", "windows"} {
		slow[host] = filepath.Join(root, "slow-outputs-"+host)
	}
	var groups []map[string]HostOutputs
	for _, dirs := range []map[string]string{main, slow} {
		hosts, err := LoadOutputs(dirs, major)
		if err != nil {
			t.Fatal(err)
		}
		groups = append(groups, hosts)
	}
	product := os.Getenv("APFS_PRODUCT_CLI")
	if _, err := os.Stat(product); err != nil {
		t.Fatalf("APFS_PRODUCT_CLI: %v", err)
	}
	work := os.Getenv("APFS_NATIVE_WORK")
	if work == "" {
		work = t.TempDir()
	} else if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	v := &Verifier{Major: major, Corpus: c, Cases: byKey, Recipes: byName, Drift: drift, Product: product, Work: work, Disk: &fixture.HostDisk{C: commander, T: &fixture.Transcript{}}, Vol: fixture.HostVolume{}, C: commander, Producer: producer}
	return v, groups
}

// summary collects job-summary rows from parallel subtests.
type summary struct {
	mu   sync.Mutex
	rows []string
}

func (s *summary) add(format string, args ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows = append(s.rows, fmt.Sprintf(format, args...))
}

// TestOutputsWithAppleTools pairs every host's outputs derived from this
// macOS version's fixtures, requires plaintext byte equality and encrypted
// device equality, then judges each output with Apple tools: the container
// of a sector-preserving output, or the full check, mount and readback of
// one Go wrote, and the continuation where the output asks for it.
func TestOutputsWithAppleTools(t *testing.T) {
	v, groups := newVerifier(t)
	var pairs []Paired
	for _, hosts := range groups {
		group, err := Pair(hosts)
		if err != nil {
			t.Fatal(err)
		}
		pairs = append(pairs, group...)
	}
	if len(pairs) == 0 {
		t.Fatalf("no outputs derived from macOS %d fixtures", v.Major)
	}
	rows := &summary{}
	lineages, order := groupByLineage(pairs, func(p Paired) string { return outputLineage(p.Output) })
	t.Run("outputs", func(t *testing.T) {
		for _, key := range order {
			group := lineages[key]
			t.Run(key, func(t *testing.T) {
				t.Parallel()
				v := v.ForSubtest()
				for _, p := range group {
					p := p
					t.Run(p.Name, func(t *testing.T) {
						verifyOne(t, v, p, rows)
					})
				}
			})
		}
	})
	sort.Strings(rows.rows)
	writeSummary(t, fmt.Sprintf("Outputs verified on macOS %d (%d)", v.Major, len(pairs)), append([]string{"| output | hosts | verdict |", "| --- | --- | --- |"}, rows.rows...))
}

// outputLineage groups outputs that carry the same filesystem identities:
// everything derived from one fixture's recipe and profile, and every
// fresh build (which assigns its identities from fixed inputs). Images
// sharing a container or volume UUID are never attached at the same time.
func outputLineage(o schema.Output) string {
	if o.Operation == "build" || (o.Operation == "encrypt" && o.Expect.Subtree != "") {
		return "builds"
	}
	return fmt.Sprintf("macos-%d/%s/%s", o.Source.Producer, o.Source.Recipe, o.Source.Profile)
}

// groupByLineage keeps each group's members in their original order.
func groupByLineage[T any](items []T, key func(T) string) (map[string][]T, []string) {
	groups := map[string][]T{}
	var order []string
	for _, item := range items {
		k := key(item)
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], item)
	}
	sort.Strings(order)
	return groups, order
}

// verifyOne judges one paired output and records its verdict.
func verifyOne(t *testing.T, v *Verifier, p Paired, rows *summary) {
	ctx := context.Background()
	diffs, err := v.VerifyOutput(ctx, p)
	if err != nil {
		rows.add("| %s | %d | error: %v |", p.Name, len(p.ByHost), err)
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
	rows.add("| %s | %d | %s |", p.Name, len(p.ByHost), verdict)
}

// TestFixturesFromOtherVersionsReadIdentically mounts every fixture that
// another macOS version produced and compares this kernel's view with the
// recorded one. Differences must be in known-drift.json.
func TestFixturesFromOtherVersionsReadIdentically(t *testing.T) {
	v, _ := newVerifier(t)
	cases, err := v.Corpus.Cases()
	if err != nil {
		t.Fatal(err)
	}
	rows := &summary{}
	var others []corpus.Case
	for _, k := range cases {
		if k.Producer != v.Major && len(k.Observation.Views) > 0 {
			others = append(others, k)
		}
	}
	lineages, order := groupByLineage(others, func(k corpus.Case) string {
		return fmt.Sprintf("macos-%d/%s/%s", k.Producer, k.Recipe, k.Profile)
	})
	t.Run("fixtures", func(t *testing.T) {
		for _, key := range order {
			group := lineages[key]
			t.Run(key, func(t *testing.T) {
				t.Parallel()
				v := v.ForSubtest()
				for _, k := range group {
					k := k
					t.Run(k.Stage, func(t *testing.T) {
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
						rows.add("| %s/%s/%s | macOS %d | %s | %d |", k.Recipe, k.Profile, k.Stage, k.Producer, strings.Join(knownText, "<br>"), len(unknown))
					})
				}
			})
		}
	})
	sort.Strings(rows.rows)
	writeSummary(t, "Cross-version parity on macOS "+strconv.Itoa(v.Major), append([]string{"| fixture | producer | known drift | unexplained |", "| --- | --- | --- | --- |"}, rows.rows...))
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
