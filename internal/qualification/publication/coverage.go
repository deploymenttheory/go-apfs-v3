package publication

import (
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/corpus"
)

// Requirement comes from reviewed entrypoint recipes and the original case
// inventory, never from the available candidate files or its own receipts.
type Requirement struct {
	ID       string
	Manifest string
	Contract string
	Cases    map[int][]string
}

func MatchCoverage(candidate corpus.Catalog, required []Requirement) error {
	if len(required) == 0 {
		return errors.New("independent native case requirements missing")
	}
	entries := map[string]corpus.Entry{}
	for _, entry := range candidate.Entries {
		entries[entry.ID] = entry
	}
	covered := map[string]bool{}
	seen := map[string]bool{}
	for _, r := range required {
		entry, ok := entries[r.ID]
		if !ok || r.Contract == "" || len(r.Cases) == 0 || seen[r.ID+"/"+r.Manifest] {
			return errors.New("invalid/duplicate required native capture scope")
		}
		seen[r.ID+"/"+r.Manifest] = true
		covered[r.ID] = true
		for major, cases := range r.Cases {
			if !slices.Contains([]int{15, 26, 27}, major) || len(cases) == 0 {
				return errors.New("native source case inventory missing")
			}
			matched := 0
			for _, capture := range entry.Captures {
				match, err := path.Match(r.Manifest, strings.TrimSuffix(capture.Manifest, ".gz"))
				if err != nil {
					return err
				}
				if !match || capture.Major != major {
					continue
				}
				matched++
				want, got := slices.Clone(cases), slices.Clone(capture.Cases)
				slices.Sort(want)
				slices.Sort(got)
				if capture.Contract != r.Contract || !slices.Equal(want, got) {
					return fmt.Errorf("native capture case/contract drift: %s/%s", r.ID, capture.Manifest)
				}
			}
			if matched != 1 {
				return fmt.Errorf("required native source manifest absent/ambiguous: %s, macOS %d", r.ID, major)
			}
		}
	}
	for _, entry := range candidate.Entries {
		independent := slices.ContainsFunc(entry.Bindings, func(b corpus.Binding) bool { return b.CaptureClass == "apple-independent" })
		if independent && !covered[entry.ID] {
			return fmt.Errorf("native corpus has no reviewed case obligation: %s", entry.ID)
		}
	}
	return nil
}
