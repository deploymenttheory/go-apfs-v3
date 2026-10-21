package native

import (
	"fmt"
	"math"
	"sort"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// ComparePhysicalRead compares reads of an already opened fork with one
// F_LOG2PHYS_EXT run. Runs use [offset, length] pairs in the decoded container;
// encryption may read complete sectors around the requested logical bytes.
// It checks physical addresses independently of equal logical file contents.
func ComparePhysicalRead(reads [][2]int64, want [3]int64, sector int64) error {
	if sector != 1 && sector != 512 {
		return fmt.Errorf("unsupported physical read sector %d", sector)
	}
	if want[0] < 0 || want[1] < 0 || want[2] <= 0 || want[1] > math.MaxInt64-want[2]-(sector-1) {
		return fmt.Errorf("invalid native physical run %v", want)
	}
	start := want[1] / sector * sector
	end := (want[1] + want[2] + sector - 1) / sector * sector
	ordered := append([][2]int64(nil), reads...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i][0] < ordered[j][0] })
	covered := start
	for _, r := range ordered {
		if r[0] < start || r[1] <= 0 || r[0] > end || r[1] > end-r[0] || r[0] > covered {
			return fmt.Errorf("physical read %v does not cover native range [%d,%d) without gaps or unrelated reads", r, start, end)
		}
		covered = max(covered, r[0]+r[1])
	}
	if covered != end {
		return fmt.Errorf("physical reads cover [%d,%d), native requires [%d,%d)", start, covered, start, end)
	}
	return nil
}

// CheckCloneSharing requires the native controls to distinguish clones, hard
// links and byte-identical ordinary copies before they qualify product reads.
// All sharing assertions use captured physical addresses, never content hashes.
func CheckCloneSharing(view schema.View, stage string) error {
	entries := map[string]schema.Entry{}
	for _, e := range view.Entries {
		if _, exists := entries[e.Path]; exists {
			return fmt.Errorf("duplicate native path %s", e.Path)
		}
		entries[e.Path] = e
		if e.Extents != nil {
			if err := validatePhysicalRuns(e.Extents.Data, e.Size); err != nil {
				return fmt.Errorf("native data fork %s: %w", e.Path, err)
			}
			var resourceBytes int64
			for _, attr := range e.Xattrs {
				if attr.Name == "com.apple.ResourceFork" {
					resourceBytes = attr.Bytes
				}
			}
			if err := validatePhysicalRuns(e.Extents.Resource, resourceBytes); err != nil {
				return fmt.Errorf("native resource fork %s: %w", e.Path, err)
			}
		}
	}
	clone, ok := entries["Fixture/clone"]
	if !ok || clone.Extents == nil || len(clone.Extents.Data) == 0 || len(clone.Extents.Resource) == 0 {
		return fmt.Errorf("native clone lacks physical data/resource evidence")
	}
	if stage == "clone-final-owner" {
		for _, path := range []string{"Fixture/data", "Fixture/alias", "Fixture/replacement"} {
			if _, exists := entries[path]; exists {
				return fmt.Errorf("native final-owner control retained %s", path)
			}
		}
		allocation, ok := entries["Fixture/native-allocation"]
		if clone.Size != 4097 || clone.Links != 1 || !ok || allocation.Size == 0 {
			return fmt.Errorf("native final owner lacks surviving bytes or subsequent allocation")
		}
		return nil
	}
	source, ok := entries["Fixture/data"]
	alias, aliasOK := entries["Fixture/alias"]
	if !ok || source.Extents == nil || !aliasOK || source.ID != alias.ID || source.Links < 2 || clone.ID == source.ID || clone.Links != 1 {
		return fmt.Errorf("native controls do not distinguish a clone from a hard link")
	}
	dataShared := sharedPhysicalBytes(clone.Extents.Data, source.Extents.Data)
	forkShared := sharedPhysicalBytes(clone.Extents.Resource, source.Extents.Resource)
	switch stage {
	case "clone-shared":
		ordinary, ok := entries["Fixture/ordinary-copy"]
		if !ok || ordinary.Extents == nil || ordinary.ID == source.ID || ordinary.ID == clone.ID || ordinary.SHA256 != source.SHA256 || clone.SHA256 != source.SHA256 || clone.Size != source.Size {
			return fmt.Errorf("native ordinary-copy control lacks distinct identity and equal bytes")
		}
		if dataShared != source.Size || forkShared <= 0 || forkShared != physicalBytes(source.Extents.Resource) || sharedPhysicalBytes(ordinary.Extents.Data, source.Extents.Data) != 0 || sharedPhysicalBytes(ordinary.Extents.Resource, source.Extents.Resource) != 0 {
			return fmt.Errorf("native controls lack shared clone forks and unshared ordinary-copy forks")
		}
	case "clone-diverged":
		if dataShared <= 0 || dataShared >= source.Size || forkShared != 0 || clone.SHA256 == source.SHA256 || clone.Size != source.Size {
			return fmt.Errorf("native divergence must retain a shared data tail and independently replace the resource fork")
		}
	case "clone-truncated":
		if clone.Size != 4097 || clone.Size >= source.Size || dataShared != 0 || forkShared != 0 {
			return fmt.Errorf("native truncation lacks a smaller independent clone and retained source")
		}
	default:
		return fmt.Errorf("unknown native sharing stage %q", stage)
	}
	return nil
}

func validatePhysicalRuns(runs [][3]int64, size int64) error {
	var end int64
	for _, run := range runs {
		if run[0] != end || run[1] < 0 || run[2] <= 0 || run[2] > size-end || run[1] > math.MaxInt64-run[2] {
			return fmt.Errorf("invalid run %v for logical size %d", run, size)
		}
		end += run[2]
	}
	if end != size {
		return fmt.Errorf("physical runs cover %d of %d logical bytes", end, size)
	}
	return nil
}

func physicalBytes(runs [][3]int64) int64 {
	var total int64
	for _, run := range runs {
		total += run[2]
	}
	return total
}

func sharedPhysicalBytes(a, b [][3]int64) int64 {
	var total int64
	for _, x := range a {
		for _, y := range b {
			total += max(int64(0), min(x[1]+x[2], y[1]+y[2])-max(x[1], y[1]))
		}
	}
	return total
}
