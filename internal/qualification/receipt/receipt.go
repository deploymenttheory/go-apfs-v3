// Package receipt checks execution evidence against independently declared
// acceptance obligations. A successful process or an input digest is never a
// substitute for the required case verdicts.
package receipt

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/corpus"
)

const Schema = 1

type Case struct {
	Family       string   `json:"family"`
	Test         string   `json:"test"`
	Corpus       string   `json:"corpus,omitempty"`
	Manifest     string   `json:"manifest,omitempty"`
	NativeCase   string   `json:"native_case"`
	Source       int      `json:"source,omitempty"`
	Variant      string   `json:"variant,omitempty"`
	Continuation bool     `json:"continuation,omitempty"`
	Outputs      []string `json:"outputs"`
}

type Input struct {
	ID         string `json:"id"`
	TreeSHA256 string `json:"tree_sha256"`
	Use        string `json:"use"`
}

type File struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// Environment describes actual execution inputs. Run/job IDs belong to the
// receipt's origin, rather than fingerprints that may later be compared across
// equivalent commits. No inheritance is admitted by this package.
type Environment struct {
	OS           string   `json:"os"`
	Architecture string   `json:"architecture"`
	Version      string   `json:"version"`
	Build        string   `json:"build"`
	Toolchain    string   `json:"toolchain"`
	Flags        []string `json:"flags"`
	Race         bool     `json:"race"`
	Tools        []File   `json:"tools"`
}

type Origin struct {
	Revision string `json:"revision"`
	Run      string `json:"run"`
	Attempt  string `json:"attempt"`
	Job      string `json:"job"`
}

type Plan struct {
	Schema       int         `json:"schema"`
	Stage        string      `json:"stage"`
	Contract     string      `json:"contract_sha256"`
	Production   string      `json:"production_sha256"`
	Inputs       []Input     `json:"inputs"`
	Outputs      []File      `json:"outputs"`
	Environment  Environment `json:"environment"`
	Cases        []Case      `json:"cases"`
	RequiredRuns []string    `json:"required_runs"`
}

type Verdict struct {
	Case   Case   `json:"case"`
	Status string `json:"status"`
}

type Receipt struct {
	Schema      int       `json:"schema"`
	Plan        Plan      `json:"plan"`
	Fingerprint string    `json:"fingerprint"`
	Origin      Origin    `json:"origin"`
	Verdicts    []Verdict `json:"verdicts"`
	Outputs     []File    `json:"outputs"`
	Events      File      `json:"events"`
}

func Digest(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// Fingerprint has separate stage domains. Capture excludes Go implementation
// identity for independent Apple references. Current-Go native experiments must
// explicitly supply their production identity. Verification binds actual output
// files; result receipts never enter an input or plan identity.
func (p Plan) Fingerprint() (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	return Digest(p)
}

func (p Plan) Validate() error {
	if p.Schema != Schema || !slices.Contains([]string{"capture", "replay", "apple-verification"}, p.Stage) || !corpus.ValidDigest(p.Contract) || len(p.Cases) == 0 || len(p.Cases) > 100000 {
		return errors.New("incomplete execution plan")
	}
	if p.Stage != "capture" && !corpus.ValidDigest(p.Production) || p.Production != "" && !corpus.ValidDigest(p.Production) {
		return errors.New("missing/invalid production identity")
	}
	env := p.Environment
	if !slices.Contains([]string{"linux", "windows", "darwin"}, env.OS) || env.Architecture == "" || env.Version == "" || env.Build == "" || env.Toolchain == "" || env.Flags == nil || env.Tools == nil {
		return errors.New("actual execution environment missing")
	}
	if p.Stage != "replay" && env.OS != "darwin" {
		return errors.New("native Apple evidence requires a macOS environment")
	}
	if p.Stage != "replay" && (len(env.Tools) == 0 || !slices.ContainsFunc([]string{"15.", "26.", "27."}, func(major string) bool { return strings.HasPrefix(env.Version, major) })) {
		return errors.New("actual native version and tool identities required")
	}
	if p.Stage == "capture" && slices.ContainsFunc(p.Inputs, func(input Input) bool { return input.Use == "current-go" }) && !corpus.ValidDigest(p.Production) {
		return errors.New("current-Go native experiment is missing its production identity")
	}
	last := ""
	for _, input := range p.Inputs {
		if input.ID == "" || input.ID <= last || !corpus.ValidDigest(input.TreeSHA256) || !slices.Contains([]string{"retained", "native-capture", "current-go", "native-continuation"}, input.Use) {
			return errors.New("invalid/duplicate input identity")
		}
		last = input.ID
	}
	last = ""
	for _, c := range p.Cases {
		if c.Test == "" || c.Test <= last || c.Family == "" || c.NativeCase == "" || c.Source != 0 && !slices.Contains([]int{15, 26, 27}, c.Source) {
			return fmt.Errorf("invalid/duplicate case obligation: %s", c.Test)
		}
		if c.Corpus == "" && c.Manifest != "" || c.Corpus != "" && (c.Manifest == "" && !c.Continuation || c.Manifest != "" && !corpus.PortablePath(c.Manifest) || !slices.ContainsFunc(p.Inputs, func(i Input) bool { return i.ID == c.Corpus })) {
			return fmt.Errorf("case input is not bound: %s", c.Test)
		}
		last = c.Test
		previous := ""
		for _, output := range c.Outputs {
			if !corpus.PortablePath(output) || output <= previous {
				return fmt.Errorf("invalid/duplicate expected case output: %s", output)
			}
			previous = output
		}
	}
	if len(p.RequiredRuns) == 0 || !slices.IsSorted(p.RequiredRuns) {
		return errors.New("required test inventory missing/unsorted")
	}
	last = ""
	for _, name := range p.RequiredRuns {
		if name == "" || name <= last {
			return errors.New("duplicate required test path")
		}
		last = name
	}
	for _, c := range p.Cases {
		if !slices.Contains(p.RequiredRuns, c.Test) {
			return fmt.Errorf("case has no required execution: %s", c.Test)
		}
	}
	if p.Stage == "apple-verification" && len(p.Outputs) == 0 {
		return errors.New("native Apple verification must bind actual portable output bytes")
	}
	return errors.Join(validateFiles(env.Tools), validateFiles(p.Outputs))
}

func validateFiles(files []File) error {
	last := ""
	for _, file := range files {
		if !corpus.PortablePath(file.Path) || file.Path <= last || file.Bytes < 0 || !corpus.ValidDigest(file.SHA256) {
			return fmt.Errorf("invalid/duplicate output or tool digest: %s", file.Path)
		}
		last = file.Path
	}
	return nil
}

// Verify requires the caller's independently constructed plan. A receipt cannot
// approve its own chosen obligations or inherit a verdict from another plan.
func Verify(want Plan, origin Origin, got Receipt) error {
	fingerprint, err := want.Fingerprint()
	if err != nil {
		return err
	}
	actual, err := got.Plan.Fingerprint()
	if err != nil {
		return err
	}
	if got.Schema != Schema || fingerprint != actual || got.Fingerprint != fingerprint || got.Origin != origin || got.Origin.Revision == "" || got.Origin.Run == "" || got.Origin.Attempt == "" || got.Origin.Job == "" {
		return errors.New("receipt execution identity/origin differs")
	}
	if len(got.Verdicts) != len(want.Cases) {
		return errors.New("missing/extra case verdicts")
	}
	for i, verdict := range got.Verdicts {
		if !reflect.DeepEqual(verdict.Case, want.Cases[i]) || verdict.Status != "pass" {
			return fmt.Errorf("missing/duplicate/skipped/failed case verdict: %s", verdict.Case.Test)
		}
	}
	if got.Outputs == nil || validateFiles(got.Outputs) != nil || !corpus.PortablePath(got.Events.Path) || got.Events.Bytes <= 0 || !corpus.ValidDigest(got.Events.SHA256) {
		return errors.New("output or event evidence missing/invalid")
	}
	for _, c := range want.Cases {
		for _, name := range c.Outputs {
			if !slices.ContainsFunc(got.Outputs, func(f File) bool { return f.Path == name }) {
				return fmt.Errorf("required output missing for %s: %s", c.Test, name)
			}
		}
	}
	for _, file := range want.Outputs {
		if !slices.Contains(got.Outputs, file) {
			return fmt.Errorf("qualified portable output changed or missing: %s", file.Path)
		}
	}
	return nil
}

// RequiredRuns includes only real t.Run boundaries. A slash in a subtest name
// does not create an intermediate test execution in Go.
func RequiredRuns(cases []Case, declared []string) []string {
	seen := map[string]bool{}
	for _, c := range cases {
		seen[c.Test] = true
		for _, parent := range declared {
			if strings.HasPrefix(c.Test, parent+"/") {
				seen[parent] = true
			}
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}
