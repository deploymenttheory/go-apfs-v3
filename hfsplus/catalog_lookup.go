package hfsplus

import (
	"cmp"
	"context"
	"strings"
	"sync"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/names"
)

// Only decoded comparison keys are cached, never source records or nodes. A
// changed source key has different bytes, so writer state cannot become stale.
// The bound limits memory even for large catalogs; reader calls may be concurrent.
type catalogNames struct {
	sensitive bool
	mu        sync.Mutex
	values    map[string]catalogName
}
type catalogName struct {
	comparison string
	err        error
}

func newCatalogNames(sensitive bool) *catalogNames {
	return &catalogNames{sensitive: sensitive, values: map[string]catalogName{}}
}
func (c *catalogNames) name(key []byte) catalogName {
	if len(key) < 8 {
		return catalogName{err: bad("catalog name key")}
	}
	encoded := string(key[6:])
	c.mu.Lock()
	defer c.mu.Unlock()
	if value, ok := c.values[encoded]; ok {
		return value
	}
	decoded, err := unicodeName(key[6:])
	value := catalogName{err: err}
	if err == nil {
		value.comparison = names.HFSStored(decoded, c.sensitive)
	}
	if len(c.values) >= 1024 {
		clear(c.values)
	}
	c.values[encoded] = value
	return value
}
func (c *catalogNames) compare(a, b []byte) int {
	if n := cmp.Compare(be.Uint32(a[2:]), be.Uint32(b[2:])); n != 0 {
		return n
	}
	return strings.Compare(c.name(a).comparison, c.name(b).comparison)
}

// findCatalog follows full catalog-key fences, using the same frozen Apple
// comparison as catalog mutation. Selecting only a parent CNID makes each stat
// scan every sibling; that becomes quadratic during large-directory traversal.
func (t *tree) findCatalog(ctx context.Context, key []byte, sensitive bool) (treeRecord, bool, error) {
	keys := t.catalogKeys
	if keys == nil || keys.sensitive != sensitive {
		keys = newCatalogNames(sensitive)
	}
	compare := keys.compare
	node, height := t.root, -1
	seen := map[uint32]bool{}
	for node != 0 {
		if err := ctx.Err(); err != nil {
			return treeRecord{}, false, err
		}
		if len(seen) >= 32 {
			return treeRecord{}, false, filesystem.ErrLimit
		}
		if node >= t.total || seen[node] {
			return treeRecord{}, false, bad("catalog search cycle or child")
		}
		seen[node] = true
		data := make([]byte, t.nodeSize)
		if err := t.fork.read(data, uint64(node)*uint64(t.nodeSize)); err != nil {
			return treeRecord{}, false, err
		}
		if height < 0 {
			height = int(data[9])
		}
		if height < 1 || int(data[9]) != height || (height == 1 && data[8] != 255) || (height > 1 && data[8] != 0) {
			return treeRecord{}, false, bad("catalog search height")
		}
		records, err := nodeRecords(data, 2)
		if err != nil {
			return treeRecord{}, false, err
		}
		selected := -1
		for i, r := range records {
			if len(r.key) < 8 {
				return treeRecord{}, false, bad("catalog search key")
			}
			if err := keys.name(r.key).err; err != nil {
				return treeRecord{}, false, err
			}
			if i > 0 && compare(records[i-1].key, r.key) >= 0 {
				return treeRecord{}, false, bad("catalog search key order")
			}
			if compare(r.key, key) <= 0 {
				selected = i
			}
		}
		if selected < 0 {
			return treeRecord{}, false, nil
		}
		r := records[selected]
		if height == 1 {
			return r, compare(r.key, key) == 0, nil
		}
		if len(r.value) != 4 || be.Uint32(r.value) == 0 {
			return treeRecord{}, false, bad("catalog search index value")
		}
		node = be.Uint32(r.value)
		height--
	}
	return treeRecord{}, false, nil
}
