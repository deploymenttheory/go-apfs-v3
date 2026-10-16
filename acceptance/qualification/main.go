// Command qualification audits the acceptance contract and records portable Go
// replay evidence. It never invokes native filesystem tools. A source audit alone
// deliberately does not certify execution.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/corpus"
	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/publication"
)

type entrypoint struct {
	Name string `json:"name"`
	File string `json:"file"`
}

// Exits include all testing.Skip calls, including helpers and nested subtests,
// and bare returns in an entrypoint's own body. A return from a nested callback
// is not an entrypoint exit. Locations use syntax, not unstable line numbers.
type exit struct {
	File       string `json:"file"`
	Function   string `json:"function"`
	Expression string `json:"expression"`
}

type inventory struct {
	Entrypoints []entrypoint `json:"entrypoints"`
	Exits       []exit       `json:"exits"`
}

type workflow struct {
	Path   string   `json:"path"`
	SHA256 string   `json:"sha256"`
	Jobs   []string `json:"jobs"`
}

type sourceFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type execution struct {
	Workflow string   `json:"workflow"`
	Jobs     []string `json:"jobs"`
	Scope    string   `json:"scope"`
}

type family struct {
	ID              string       `json:"id"`
	Purpose         string       `json:"purpose"`
	Expectation     string       `json:"expectation"`
	Tests           []entrypoint `json:"tests"`
	Corpora         []string     `json:"corpora"`
	Collectors      []string     `json:"collectors"`
	CaptureClass    string       `json:"capture_class"`
	CaptureReason   string       `json:"capture_reason"`
	RetainedSources []int        `json:"retained_sources"`
	FreshSources    []int        `json:"fresh_sources"`
	PortableHosts   []string     `json:"portable_hosts"`
	NativeMajors    []int        `json:"native_majors"`
	Formats         []string     `json:"formats"`
	Race            string       `json:"race"`
	Checks          []string     `json:"checks"`
	Negative        []string     `json:"negative_controls"`
	Continuations   []string     `json:"continuations"`
	Execution       []execution  `json:"execution"`
}

type reviewedExit struct {
	exit
	Reason string `json:"reason"`
}

type manifest struct {
	Path   string   `json:"path"`
	SHA256 string   `json:"sha256"`
	Cases  []string `json:"cases"`
}

type registry struct {
	Schema      int            `json:"schema"`
	Families    []family       `json:"families"`
	Exits       []reviewedExit `json:"reviewed_exits"`
	Workflows   []workflow     `json:"workflows"`
	Manifests   []manifest     `json:"manifests"`
	TestSources []sourceFile   `json:"test_sources"`
}

func main() {
	root := flag.String("root", ".", "repository root")
	registryPath := flag.String("registry", "acceptance/qualification/registry.json", "reviewed coverage registry, relative to root")
	list := flag.Bool("inventory", false, "print Go syntax inventory instead of auditing")
	corpusCatalog := flag.String("corpus-catalog", "acceptance/qualification/corpus.json", "approved native input catalog, relative to root")
	bootstrap := flag.String("bootstrap-catalog", "", "prepare a new unapproved catalog at this absent path")
	verify := flag.String("verify-corpus", "", "verify one corpus ID or all, including exact retained files")
	bundle := flag.String("bundle-corpus", "", "prepare content-addressed local bundles for one corpus ID or all")
	bundles := flag.String("bundle-dir", "", "existing local bundle directory; no network downloads occur")
	referencePin := flag.String("reference-pin", "", "reviewed release pin for replay; all pinned assets must already be in bundle-dir")
	describe := flag.Bool("describe-catalog", false, "describe catalog inputs, sizes and native source versions")
	replay := flag.Bool("replay", false, "execute existing acceptance entrypoints with complete case evidence; go test arguments follow --")
	receipts := flag.String("receipt-dir", "artifacts/qualification", "directory for execution plans, original events and receipts")
	prepare := flag.String("prepare-references", "", "prepare an unapproved reference candidate from an explicit native input map")
	candidateDir := flag.String("candidate-dir", "artifacts/native-reference-candidate", "absent directory for candidate bundles and metadata")
	captureOnly := flag.Bool("capture-contract", false, "print the conservative native collector dependency identity")
	checkReferences := flag.String("check-references", "", "verify a published candidate pin and all original bundle bytes; grants no execution verdict")
	planReferences := flag.String("reference-obligations", "", "print required portable cases for a complete prepared reference candidate directory")
	checkEvidence := flag.String("check-reference-evidence", "", "verify original candidate receipts in this directory against the complete reference obligations")
	referenceOrigin := flag.String("reference-origin", "", "authenticated original Actions origin document for candidate evidence verification")
	materialize := flag.String("materialize-references", "", "comma-separated approved independent inputs to materialize as managed ordinary files")
	inputDir := flag.String("input-dir", "", "absent absolute managed scratch for materialized reference input trees")
	flag.Parse()
	if (*referenceOrigin != "") != (*checkEvidence != "") {
		fmt.Fprintln(os.Stderr, "candidate evidence verification requires an explicit authenticated reference origin")
		os.Exit(1)
	}
	if *referencePin != "" && !*replay && *materialize == "" || *materialize != "" && (*referencePin == "" || *inputDir == "") {
		fmt.Fprintln(os.Stderr, "a reviewed reference pin requires replay or explicit input materialization; materialization needs an input directory")
		os.Exit(1)
	}
	standalone := 0
	for _, chosen := range []bool{*prepare != "", *captureOnly, *checkReferences != "", *planReferences != "", *checkEvidence != "", *materialize != ""} {
		if chosen {
			standalone++
		}
	}
	if standalone > 1 || standalone == 1 && (*replay || *list || *describe || *bootstrap != "" || *bundle != "" || *verify != "") || *replay && (*list || *describe || *bootstrap != "" || *bundle != "" || *verify != "") || !*replay && len(flag.Args()) != 0 {
		fmt.Fprintln(os.Stderr, "choose one qualification action; go test arguments require -replay")
		os.Exit(1)
	}
	var auditOutput io.Writer = os.Stdout
	if *bundle != "" || *prepare != "" || *captureOnly || *planReferences != "" || *checkEvidence != "" {
		auditOutput = os.Stderr
	}
	if err := run(*root, *registryPath, *list, auditOutput); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if !*list {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		var err error
		if *prepare != "" {
			err = prepareReferences(ctx, *root, *registryPath, *prepare, *candidateDir)
		} else if *materialize != "" {
			err = materializeReferences(ctx, *root, *registryPath, *referencePin, *bundles, *materialize, *inputDir)
		} else if *checkEvidence != "" {
			var origin publication.Origin
			var data []byte
			data, err = readCandidateDocument(*referenceOrigin, 64<<10)
			if err == nil {
				err = corpus.StrictJSON(data, &origin)
			}
			if err == nil {
				var proof referenceEvidenceSummary
				proof, err = checkReferenceEvidence(ctx, *root, *registryPath, *candidateDir, *checkEvidence, origin)
				if err == nil {
					err = json.NewEncoder(os.Stdout).Encode(proof)
				}
			}
		} else if *planReferences != "" {
			var obligations referenceObligations
			obligations, err = planReferenceObligations(ctx, *root, *registryPath, *planReferences)
			if err == nil {
				err = json.NewEncoder(os.Stdout).Encode(obligations)
			}
		} else if *checkReferences != "" {
			err = checkReferenceAssets(ctx, *root, *registryPath, *checkReferences, *bundles)
		} else if *captureOnly {
			var identity string
			identity, err = readCaptureContract(ctx, *root, *registryPath)
			if err == nil {
				_, err = fmt.Fprintln(os.Stdout, identity)
			}
		} else if *replay {
			err = runReplay(ctx, replayOptions{root: *root, registry: *registryPath, catalog: *corpusCatalog, bundles: *bundles, directory: *receipts, referencePin: *referencePin, args: flag.Args()}, os.Stdout)
		} else {
			err = corpusWork(ctx, *root, *registryPath, corpusAction{*corpusCatalog, *bootstrap, *verify, *bundle, *bundles, *describe}, os.Stdout)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}

func run(root, path string, list bool, out io.Writer) error {
	actual, err := inspectTests(root)
	if err != nil {
		return err
	}
	if list {
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(actual)
	}
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		return err
	}
	var r registry
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&r); err != nil {
		return err
	}
	if err = decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("registry contains trailing JSON")
	}
	if err = audit(root, r, actual); err != nil {
		return err
	}
	if _, err = readReplayContract(root, r); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "Coverage contract audited: %d families, %d entrypoints, %d reviewed exits, %d manifests, %d workflows. Execution verdicts remain required.\n", len(r.Families), len(actual.Entrypoints), len(actual.Exits), len(r.Manifests), len(r.Workflows))
	return err
}

func syntax(fset *token.FileSet, node ast.Node) string {
	var b bytes.Buffer
	_ = format.Node(&b, fset, node)
	return b.String()
}

func inspectTests(root string) (inventory, error) {
	result := inventory{Entrypoints: []entrypoint{}, Exits: []exit{}}
	paths, err := testPaths(root)
	if err != nil || len(paths) == 0 {
		return result, errors.New("acceptance test sources are missing")
	}
	for _, path := range paths {
		fset := token.NewFileSet()
		file, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			return result, parseErr
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return result, relErr
		}
		rel = filepath.ToSlash(rel)
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			isTest := fn.Recv == nil && (strings.HasPrefix(fn.Name.Name, "Test") || strings.HasPrefix(fn.Name.Name, "Fuzz") || strings.HasPrefix(fn.Name.Name, "Example") || strings.HasPrefix(fn.Name.Name, "Benchmark"))
			if isTest {
				result.Entrypoints = append(result.Entrypoints, entrypoint{fn.Name.Name, rel})
			}
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				if call, ok := node.(*ast.CallExpr); ok {
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok && slices.Contains([]string{"Skip", "Skipf", "SkipNow"}, sel.Sel.Name) {
						result.Exits = append(result.Exits, exit{rel, fn.Name.Name, syntax(fset, call)})
					}
				}
				return true
			})
			if !isTest {
				continue
			}
			// Register the enclosing condition, so changing a no-input exit's
			// admission cannot silently retain its old review explanation.
			var visit func(ast.Node, string)
			visit = func(node ast.Node, guard string) {
				ast.Inspect(node, func(child ast.Node) bool {
					switch n := child.(type) {
					case *ast.FuncLit:
						return false
					case *ast.IfStmt:
						visit(n.Body, syntax(fset, n.Cond))
						if n.Else != nil {
							visit(n.Else, "else "+syntax(fset, n.Cond))
						}
						return false
					case *ast.ReturnStmt:
						if len(n.Results) == 0 {
							result.Exits = append(result.Exits, exit{rel, fn.Name.Name, "return when " + guard})
						}
					}
					return true
				})
			}
			visit(fn.Body, "unconditional")
		}
	}
	slices.SortFunc(result.Entrypoints, func(a, b entrypoint) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(result.Exits, func(a, b exit) int {
		return strings.Compare(a.File+a.Function+a.Expression, b.File+b.Function+b.Expression)
	})
	return result, nil
}

func testPaths(root string) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(filepath.Join(root, "acceptance"), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && slices.Contains([]string{"qualification", "testdata", "native"}, d.Name()) {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), "_test.go") {
			paths = append(paths, path)
		}
		return nil
	})
	return paths, err
}

func regularFile(root, path string) ([]byte, error) {
	if !filepath.IsLocal(path) || strings.Contains(path, "\\") {
		return nil, fmt.Errorf("unsafe contract path %q", path)
	}
	info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("contract is not a regular file: %s", path)
	}
	return os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
}

var jobPattern = regexp.MustCompile(`(?m)^  ([A-Za-z_][A-Za-z_0-9]*):`)

func audit(root string, r registry, actual inventory) error {
	if r.Schema != 1 || len(r.Families) == 0 || len(r.Workflows) == 0 || len(r.Manifests) == 0 {
		return errors.New("incomplete coverage registry")
	}
	pathsToTests, err := testPaths(root)
	if err != nil {
		return err
	}
	if len(pathsToTests) != len(r.TestSources) {
		return errors.New("acceptance source inventory changed")
	}
	testSources := map[string]bool{}
	for _, source := range r.TestSources {
		if testSources[source.Path] {
			return fmt.Errorf("duplicate acceptance source: %s", source.Path)
		}
		testSources[source.Path] = true
		data, err := regularFile(root, source.Path)
		if err != nil {
			return err
		}
		if err = checkDigest(source.Path, data, source.SHA256); err != nil {
			return err
		}
	}
	for _, path := range pathsToTests {
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if !testSources[filepath.ToSlash(rel)] {
			return fmt.Errorf("unregistered acceptance source: %s", path)
		}
	}
	jobs := map[string][]string{}
	for _, w := range r.Workflows {
		if _, exists := jobs[w.Path]; exists {
			return fmt.Errorf("duplicate workflow %s", w.Path)
		}
		data, err := regularFile(root, w.Path)
		if err != nil {
			return err
		}
		if err = checkDigest(w.Path, data, w.SHA256); err != nil {
			return err
		}
		_, body, found := strings.Cut(string(data), "\njobs:\n")
		if !found {
			return fmt.Errorf("workflow jobs missing: %s", w.Path)
		}
		var names []string
		for _, match := range jobPattern.FindAllStringSubmatch(body, -1) {
			names = append(names, match[1])
		}
		if !reflect.DeepEqual(names, w.Jobs) {
			return fmt.Errorf("workflow job inventory changed: %s", w.Path)
		}
		jobs[w.Path] = names
	}
	var expected []entrypoint
	ids := map[string]bool{}
	corpora := map[string]bool{}
	for _, f := range r.Families {
		if ids[f.ID] || f.ID == "" || f.Purpose == "" || f.Expectation == "" || f.CaptureReason == "" || f.Race == "" || len(f.Tests) == 0 || len(f.Checks) == 0 || len(f.Execution) == 0 || len(f.PortableHosts) == 0 {
			return fmt.Errorf("incomplete or duplicate family: %s", f.ID)
		}
		ids[f.ID] = true
		if !slices.Contains([]string{"apple-independent", "current-go-experiment", "harness-control", "native-continuation"}, f.CaptureClass) {
			return fmt.Errorf("unknown capture class: %s", f.ID)
		}
		if f.CaptureClass != "harness-control" && ((len(f.FreshSources) != 0 && !reflect.DeepEqual(f.FreshSources, []int{15, 26, 27})) || len(f.Collectors) == 0) {
			return fmt.Errorf("native sources or collectors missing: %s", f.ID)
		}
		if !reflect.DeepEqual(f.PortableHosts, []string{"linux", "windows", "darwin"}) && f.CaptureClass != "native-continuation" {
			return fmt.Errorf("portable hosts missing: %s", f.ID)
		}
		expected = append(expected, f.Tests...)
		for _, path := range f.Collectors {
			if _, err := regularFile(root, path); err != nil {
				return err
			}
		}
		for _, c := range f.Corpora {
			corpora[c] = true
		}
		retained := []int{}
		for _, major := range []int{15, 26, 27} {
			for _, c := range f.Corpora {
				info, err := os.Stat(filepath.Join(root, filepath.FromSlash(c), fmt.Sprintf("macos-%d", major)))
				if err == nil && info.IsDir() {
					retained = append(retained, major)
					break
				}
			}
		}
		if !slices.Equal(retained, f.RetainedSources) {
			return fmt.Errorf("retained source versions changed: %s", f.ID)
		}
		for _, e := range f.Execution {
			if e.Scope == "" || len(e.Jobs) == 0 {
				return fmt.Errorf("execution scope missing: %s", f.ID)
			}
			for _, job := range e.Jobs {
				if !slices.Contains(jobs[e.Workflow], job) {
					return fmt.Errorf("unregistered workflow job: %s/%s", e.Workflow, job)
				}
			}
		}
	}
	slices.SortFunc(expected, func(a, b entrypoint) int { return strings.Compare(a.Name, b.Name) })
	if !reflect.DeepEqual(expected, actual.Entrypoints) {
		return errors.New("acceptance entrypoint inventory changed; register every test exactly once with its capability")
	}
	var exits []exit
	for _, e := range r.Exits {
		if e.Reason == "" {
			return errors.New("exit has no review explanation")
		}
		exits = append(exits, e.exit)
	}
	if !slices.Equal(exits, actual.Exits) {
		return errors.New("acceptance skip/early-return inventory changed; review the qualification input requirement")
	}
	directories, err := os.ReadDir(filepath.Join(root, "acceptance", "testdata"))
	if err != nil {
		return err
	}
	for _, d := range directories {
		if d.IsDir() && !corpora["acceptance/testdata/"+d.Name()] {
			return fmt.Errorf("unregistered retained corpus: %s", d.Name())
		}
	}
	paths := map[string]bool{}
	for _, m := range r.Manifests {
		if paths[m.Path] {
			return fmt.Errorf("duplicate manifest: %s", m.Path)
		}
		paths[m.Path] = true
		data, err := regularFile(root, m.Path)
		if err != nil {
			return err
		}
		if err = checkDigest(m.Path, data, m.SHA256); err != nil {
			return err
		}
		cases, err := manifestCases(m.Path, data)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(cases, m.Cases) {
			return fmt.Errorf("retained case inventory changed: %s", m.Path)
		}
	}
	for c := range corpora {
		found := 0
		err := filepath.WalkDir(filepath.Join(root, filepath.FromSlash(c)), func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() || !isManifest(d.Name()) {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			if !paths[filepath.ToSlash(rel)] {
				return fmt.Errorf("unregistered retained manifest: %s", rel)
			}
			found++
			return nil
		})
		if err != nil {
			return err
		}
		if found == 0 {
			return fmt.Errorf("no retained manifests: %s", c)
		}
	}
	return nil
}

func isManifest(name string) bool {
	name = strings.TrimSuffix(name, ".gz")
	return strings.HasSuffix(name, "manifest.json") || name == "recovery.json"
}

func manifestCases(path string, data []byte) ([]string, error) {
	var input io.Reader = bytes.NewReader(data)
	if strings.HasSuffix(path, ".gz") {
		z, err := gzip.NewReader(input)
		if err != nil {
			return nil, err
		}
		defer func() { _ = z.Close() }()
		input = z
	}
	// Inventory only small manifest documents, never image/archive contents.
	data, err := io.ReadAll(io.LimitReader(input, (16<<20)+1))
	if err != nil || len(data) > 16<<20 {
		return nil, fmt.Errorf("invalid or oversized manifest: %s", path)
	}
	var doc map[string]json.RawMessage
	if err = json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	ids := []string{}
	for _, key := range []string{"cases", "rejections", "sectorProbes"} {
		var records []struct {
			ID       string `json:"id"`
			Capacity int64  `json:"capacity"`
		}
		if raw, ok := doc[key]; ok {
			if err = json.Unmarshal(raw, &records); err != nil {
				return nil, err
			}
			for _, record := range records {
				id := record.ID
				if id == "" && key == "sectorProbes" {
					id = fmt.Sprint(record.Capacity)
				}
				if id == "" || slices.Contains(ids, key+"/"+id) {
					return nil, fmt.Errorf("empty or duplicate case in %s", path)
				}
				ids = append(ids, key+"/"+id)
			}
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("manifest has no cases: %s", path)
	}
	return ids, nil
}

func checkDigest(path string, data []byte, want string) error {
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != want {
		return fmt.Errorf("contract digest changed: %s; review obligations before updating the registry", path)
	}
	return nil
}
