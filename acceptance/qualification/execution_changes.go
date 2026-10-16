package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/corpus"
)

const documentationChanges = "documentation-or-release-only"

type executionChanges struct {
	Schema           int      `json:"schema"`
	Before           string   `json:"original_revision"`
	BeforeTree       string   `json:"original_tree_sha"`
	Current          string   `json:"current_revision"`
	CurrentTree      string   `json:"current_tree_sha"`
	Classification   string   `json:"classification"`
	Paths            []string `json:"changed_paths"`
	ExecutionReasons []string `json:"execution_reasons"`
}

func documentationPath(name string) bool {
	if slices.Contains([]string{"README.md", "CHANGELOG.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "SECURITY.md", "acceptance/README.md"}, name) {
		return true
	}
	return strings.HasPrefix(name, "docs/") && !strings.HasPrefix(name, "docs/qualification-evidence/") && path.Ext(name) == ".md" && path.Base(name) != "AGENTS.md" && path.Base(name) != "SKILL.md"
}

var releaseVersion = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)

func releaseLabel(data []byte) bool {
	var document map[string]string
	if len(data) > 4096 || corpus.StrictJSON(data, &document) != nil || len(document) != 1 || !releaseVersion.MatchString(document["."]) {
		return false
	}
	// SemVer forbids leading zeroes in numeric prerelease identifiers.
	core, _, _ := strings.Cut(document["."], "+")
	if _, prerelease, exists := strings.Cut(core, "-"); exists {
		for _, identifier := range strings.Split(prerelease, ".") {
			if len(identifier) > 1 && identifier[0] == '0' && strings.Trim(identifier, "0123456789") == "" {
				return false
			}
		}
	}
	return true
}

func gitReleaseLabel(ctx context.Context, root, blob string) bool {
	if len(blob) != 40 || blob == strings.Repeat("0", 40) {
		return false
	}
	size, err := commandText(ctx, root, "git", "cat-file", "-s", blob)
	if err != nil {
		return false
	}
	n, err := strconv.ParseInt(size, 10, 64)
	if err != nil || n <= 0 || n > 4096 {
		return false
	}
	command := exec.CommandContext(ctx, "git", "cat-file", "blob", blob)
	command.Dir = root
	data, err := command.Output()
	return err == nil && int64(len(data)) == n && releaseLabel(data)
}

// Classification chooses no verdict. The current complete original receipts
// and source/tool/input fingerprints are independently required for admission.
func classifyExecutionChanges(ctx context.Context, root, before string) (executionChanges, error) {
	result := executionChanges{Schema: 1, Before: before, Classification: "full", Paths: []string{}, ExecutionReasons: []string{}}
	if matched, _ := regexp.MatchString(`^[a-f0-9]{40}$`, before); !matched {
		return result, errors.New("source classification requires an exact original Git revision")
	}
	var err error
	result.BeforeTree, err = commandText(ctx, root, "git", "rev-parse", before+"^{tree}")
	if err != nil {
		return result, err
	}
	result.Current, err = commandText(ctx, root, "git", "rev-parse", "HEAD")
	if err != nil {
		return result, err
	}
	result.CurrentTree, err = commandText(ctx, root, "git", "rev-parse", "HEAD^{tree}")
	if err != nil {
		return result, err
	}
	command := exec.CommandContext(ctx, "git", "diff", "--raw", "--no-ext-diff", "--no-textconv", "--no-renames", "--no-abbrev", "-z", before, result.Current, "--")
	command.Dir = root
	data, err := command.Output()
	if err != nil || len(data) > 16<<20 {
		return result, errors.Join(err, errors.New("source change inventory unavailable or exceeds bound"))
	}
	if len(data) == 0 {
		result.Classification = "identical"
		return result, nil
	}
	fields := bytes.Split(data, []byte{0})
	if len(fields) > 200001 || len(fields)%2 != 1 || len(fields[len(fields)-1]) != 0 {
		return result, errors.New("truncated source change inventory")
	}
	seen := map[string]bool{}
	for index := 0; index < len(fields)-1; index += 2 {
		header := strings.Fields(string(fields[index]))
		name := string(fields[index+1])
		if len(header) != 5 || len(header[0]) != 7 || header[0][0] != ':' || !slices.Contains([]string{"A", "M", "D", "T"}, header[4]) || !corpus.PortablePath(name) || seen[name] {
			return result, errors.New("unsafe or duplicate source change record")
		}
		seen[name] = true
		result.Paths = append(result.Paths, name)
		oldMode, newMode := header[0][1:], header[1]
		reason := ""
		switch {
		case !slices.Contains([]string{"000000", "100644", "100755"}, oldMode) || !slices.Contains([]string{"000000", "100644", "100755"}, newMode):
			reason = "aliased or special Git member"
		case documentationPath(name):
		case name == ".release-please-manifest.json":
			if !gitReleaseLabel(ctx, root, header[2]) || !gitReleaseLabel(ctx, root, header[3]) {
				reason = "unrecognised release metadata"
			}
		default:
			reason = "execution dependency or unclassified file"
		}
		if reason != "" {
			result.ExecutionReasons = append(result.ExecutionReasons, name+": "+reason)
		}
	}
	slices.Sort(result.Paths)
	slices.Sort(result.ExecutionReasons)
	if len(result.ExecutionReasons) == 0 {
		result.Classification = documentationChanges
	}
	return result, nil
}

func checkExecutionSource(ctx context.Context, root string, origin executionEvidenceOrigin) (*executionChanges, error) {
	tree, err := commandText(ctx, root, "git", "rev-parse", "HEAD^{tree}")
	if err != nil {
		return nil, err
	}
	if origin.Tree == tree && origin.Projection == "" {
		return nil, nil
	}
	if origin.Projection != documentationChanges {
		return nil, errors.New("original evidence tested different source contents")
	}
	changes, err := classifyExecutionChanges(ctx, root, origin.Origin.Revision)
	if err != nil || changes.BeforeTree != origin.Tree || !slices.Contains([]string{"identical", documentationChanges}, changes.Classification) {
		return nil, errors.Join(err, fmt.Errorf("original execution has changed dependencies: %v", changes.ExecutionReasons))
	}
	return &changes, nil
}
