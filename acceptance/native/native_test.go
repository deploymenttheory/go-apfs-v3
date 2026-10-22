//go:build native && darwin

package native

import (
	"context"
	"errors"
	"flag"
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
// TestMain reports, after every test in this phase, how often each kind
// of wait for macOS disk state had to retry. A rising count warns that the
// runners' DiskArbitration is lagging before it causes failures.
func TestMain(m *testing.M) {
	code := m.Run()
	counts := fixture.WaitCounts()
	phase := os.Getenv("APFS_NATIVE_GROUPS")
	if phase == "" {
		phase = "all"
	}
	rows := []string{"| wait | retries |", "| --- | --- |"}
	for _, c := range counts {
		rows = append(rows, fmt.Sprintf("| %s | %d |", c.What, c.Retries))
		fmt.Printf("wait %s retried %d times\n", c.What, c.Retries)
	}
	if len(counts) == 0 {
		rows = append(rows, "| none | 0 |")
	}
	if path := os.Getenv("GITHUB_STEP_SUMMARY"); path != "" {
		if f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644); err == nil {
			fmt.Fprintf(f, "## Waits for macOS disk state (%s phase)\n\n%s\n\n", phase, strings.Join(rows, "\n"))
			_ = f.Close()
		}
	}
	os.Exit(code)
}

// nativeGroup is APFS_NATIVE_GROUPS: "fixtures" (cross-version parity,
// which needs only the corpus), "main" (every host's outputs), "slow" (the
// slow bucket's outputs) or empty for all three. CI runs the phases as
// separate steps so each starts as soon as its inputs exist.
func nativeGroup(t *testing.T) string {
	t.Helper()
	group := os.Getenv("APFS_NATIVE_GROUPS")
	switch group {
	case "", "fixtures", "main", "slow":
		return group
	}
	t.Fatalf("APFS_NATIVE_GROUPS=%q, want fixtures, main or slow", group)
	return ""
}

func newVerifier(t *testing.T) *Verifier {
	t.Helper()
	sharedOnce.Do(func() { shared, sharedErr = buildVerifier() })
	if sharedErr != nil {
		t.Fatal(sharedErr)
	}
	return shared.ForSubtest()
}

// outputGroups loads the outputs this invocation verifies: each group's
// hosts must agree on every output, and only outputs derived from this
// macOS version's fixtures are kept.
func outputGroups(t *testing.T, major int) []map[string]HostOutputs {
	t.Helper()
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
	selected := map[string]map[string]string{"main": main, "slow": slow}
	order := []string{"main", "slow"}
	if group := nativeGroup(t); group != "" {
		order = []string{group}
	}
	var groups []map[string]HostOutputs
	for _, name := range order {
		hosts, err := LoadOutputs(selected[name], major)
		if err != nil {
			t.Fatal(err)
		}
		groups = append(groups, hosts)
	}
	return groups
}

// The corpus, recipes and producer identity are resolved once per test
// binary: both tests run in parallel, and resolving the corpus twice at
// once could extract a bundle into the cache concurrently.
var (
	sharedOnce sync.Once
	shared     *Verifier
	sharedErr  error
)

func buildVerifier() (*Verifier, error) {
	if err := fixture.RequireDisposableHost(); err != nil {
		return nil, err
	}
	major, _ := strconv.Atoi(os.Getenv("APFS_EXPECT_MAJOR"))
	if major == 0 {
		return nil, fmt.Errorf("APFS_EXPECT_MAJOR is required")
	}
	commander := fixture.Exec{}
	producer, err := fixture.IdentifyProducer(context.Background(), commander, major, "")
	if err != nil {
		return nil, err
	}
	c, err := corpus.Resolve(context.Background(), corpus.Options{Root: filepath.Join("..", "..")})
	if err != nil {
		return nil, err
	}
	cases, err := c.Cases()
	if err != nil {
		return nil, err
	}
	byKey := map[string]corpus.Case{}
	for _, k := range cases {
		byKey[CaseKey(schema.CaseRef{Producer: k.Producer, Recipe: k.Recipe, Profile: k.Profile, Stage: k.Stage})] = k
	}
	recipes, err := schema.LoadRecipes(filepath.Join("..", "recipes"))
	if err != nil {
		return nil, err
	}
	byName := map[string]schema.Recipe{}
	for _, r := range recipes {
		byName[r.Name] = r
	}
	drift, err := schema.ReadKnownDrift(filepath.Join("..", "known-drift.json"))
	if err != nil {
		return nil, err
	}
	product := os.Getenv("APFS_PRODUCT_CLI")
	if _, err := os.Stat(product); err != nil {
		return nil, fmt.Errorf("APFS_PRODUCT_CLI: %w", err)
	}
	work := os.Getenv("APFS_NATIVE_WORK")
	if work == "" {
		if work, err = os.MkdirTemp("", "apfs-native-"); err != nil {
			return nil, err
		}
	} else if err := os.MkdirAll(work, 0o755); err != nil {
		return nil, err
	}
	var unpacker string
	if group := os.Getenv("APFS_NATIVE_GROUPS"); group == "" || group == "main" {
		unpacker, err = buildAppleDoubleUnpacker(context.Background(), commander, work)
		if err != nil {
			return nil, err
		}
	}
	return &Verifier{Major: major, Corpus: c, Cases: byKey, Recipes: byName, Drift: drift, Product: product, Work: work, Disk: &fixture.HostDisk{C: commander, T: &fixture.Transcript{}}, Vol: fixture.HostVolume{}, C: commander, Producer: producer, AppleDoubleUnpack: unpacker}, nil
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
	t.Parallel()
	if nativeGroup(t) == "fixtures" {
		t.Skip("outputs are verified in the main and slow phases")
	}
	v := newVerifier(t)
	groups := outputGroups(t, v.Major)
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
	if nativeGroup(t) != "slow" {
		if err := requirePreservationSourceOutputs(pairs, v.Cases, v.Major); err != nil {
			t.Fatal(err)
		}
		if err := requireContainerOutputs(pairs, v.Cases, v.Major); err != nil {
			t.Fatal(err)
		}
		if err := requireAppleDoubleOutputs(pairs, v.Cases, v.Major); err != nil {
			t.Fatal(err)
		}
		if err := requireWorkspaceOutputs(pairs, v.Cases, v.Major); err != nil {
			t.Fatal(err)
		}
		if err := requireCloneOutputs(pairs, v.Cases, v.Major); err != nil {
			t.Fatal(err)
		}
		if err := requireEncryptedEditOutputs(pairs, v.Cases, v.Major); err != nil {
			t.Fatal(err)
		}
	}
	rows := &summary{}
	lineages, order := groupByLineage(pairs, func(p Paired) string { return outputLineage(p.Output) })
	prioritizeLineages(order, "outputs")
	for _, key := range order {
		planContainerChecks(lineages[key])
	}
	t.Run("outputs", func(t *testing.T) {
		nativeLineageAdmission().run(order, func(key string) {
			group := lineages[key]
			t.Run(key, func(t *testing.T) {
				v := v.ForSubtest()
				for _, p := range group {
					p := p
					t.Run(p.Name, func(t *testing.T) {
						verifyOne(t, v, p, rows)
					})
				}
			})
		})
	})
	sort.Strings(rows.rows)
	writeSummary(t, fmt.Sprintf("Outputs verified on macOS %d (%d)", v.Major, len(pairs)), append([]string{"| output | hosts | verdict |", "| --- | --- | --- |"}, rows.rows...))
}

// outputLineage groups outputs that carry the same filesystem identities:
// everything derived from one fixture's recipe and profile, and every
// fresh build (which assigns its identities from fixed inputs). Images
// sharing a container or volume UUID are never attached at the same time.
func outputLineage(o schema.Output) string {
	if o.Operation == "container" {
		return "containers"
	}
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

var nativeLineages = sync.OnceValue(func() *lineageAdmission {
	limit, err := strconv.Atoi(flag.Lookup("test.parallel").Value.String())
	if err != nil {
		panic(err)
	}
	return newLineageAdmission(limit)
})

// nativeLineageAdmission uses the same process-wide bound as -parallel. Go's
// parallel-test barrier releases all registered subtests together, so sorted
// registration alone does not preserve priority when they compete for a slot.
// Run supports concurrent callers and returns after subtest cleanup; callbacks
// keep the existing test names and cannot release a filesystem identity early.
func nativeLineageAdmission() *lineageAdmission { return nativeLineages() }

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
		var limit KnownLimit
		switch _, err := v.Continuation(ctx, p, schemaCase{recipe: v.Recipes[k.Recipe]}); {
		case errors.As(err, &limit):
			t.Logf("native writes passed fsck; %v", limit)
			verdict += ", native continuation ok, product edit refused by a tracked limit"
		case err != nil:
			t.Error(err)
			verdict = "continuation failed"
		default:
			verdict += ", continuation ok"
		}
	}
	rows.add("| %s | %d | %s |", p.Name, len(p.ByHost), verdict)
}

// TestFixturesFromOtherVersionsReadIdentically mounts every fixture that
// another macOS version produced and compares this kernel's view with the
// recorded one. Differences must be in known-drift.json.
func TestFixturesFromOtherVersionsReadIdentically(t *testing.T) {
	if group := nativeGroup(t); group != "" && group != "fixtures" {
		t.Skip("cross-version parity runs in the fixtures phase")
	}
	v := newVerifier(t)
	cases, err := v.Corpus.Cases()
	if err != nil {
		t.Fatal(err)
	}
	if err := requireRawImageEncryption(t, v, cases); err != nil {
		t.Fatalf("raw image encryption proof: %v", err)
	}
	t.Parallel()
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
	prioritizeLineages(order, "fixtures")
	t.Run("fixtures", func(t *testing.T) {
		nativeLineageAdmission().run(order, func(key string) {
			group := lineages[key]
			t.Run(key, func(t *testing.T) {
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
		})
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
