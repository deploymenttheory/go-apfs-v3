package native

import (
	"fmt"
	"sort"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// CompareOptions relax a view comparison for produced images.
type CompareOptions struct {
	// Subtree is the expected path the observed root corresponds to.
	Subtree string
	// IgnoreTimes names timestamps that may differ.
	IgnoreTimes map[string]bool
	// IgnoreIdentity accepts different object IDs and link counts, for a
	// fresh build that allocated its own.
	IgnoreIdentity bool
}

// Difference is one mismatch between an observed and an expected view.
type Difference struct {
	Path  string
	Field string
	Got   string
	Want  string
}

func (d Difference) String() string {
	return fmt.Sprintf("%s: %s: got %s, want %s", d.Path, d.Field, d.Got, d.Want)
}

// CompareViews compares what the verifier observed on a mounted output
// with what the fixture observation expects. Both sides come from the
// same observer code, so the comparison is field by field.
func CompareViews(got, want schema.View, opts CompareOptions) []Difference {
	var diffs []Difference
	expected := map[string]schema.Entry{}
	prefix := ""
	if opts.Subtree != "" {
		prefix = opts.Subtree + "/"
	}
	for _, e := range want.Entries {
		if prefix != "" {
			if !strings.HasPrefix(e.Path, prefix) {
				continue
			}
			e.Path = strings.TrimPrefix(e.Path, prefix)
		}
		expected[e.Path] = e
	}
	observed := map[string]schema.Entry{}
	for _, e := range got.Entries {
		observed[e.Path] = e
	}
	var paths []string
	for p := range expected {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		g, ok := observed[p]
		if !ok {
			diffs = append(diffs, Difference{Path: p, Field: "presence", Got: "absent", Want: "present"})
			continue
		}
		diffs = append(diffs, compareEntry(g, expected[p], opts)...)
	}
	var extra []string
	for p := range observed {
		if _, ok := expected[p]; !ok {
			extra = append(extra, p)
		}
	}
	sort.Strings(extra)
	for _, p := range extra {
		diffs = append(diffs, Difference{Path: p, Field: "presence", Got: "present", Want: "absent"})
	}
	return diffs
}

func compareEntry(got, want schema.Entry, opts CompareOptions) []Difference {
	var diffs []Difference
	add := func(field string, g, w any) {
		gs, ws := fmt.Sprint(g), fmt.Sprint(w)
		if gs != ws {
			diffs = append(diffs, Difference{Path: want.Path, Field: field, Got: gs, Want: ws})
		}
	}
	add("kind", got.Kind, want.Kind)
	add("nameBytes", got.NameBytes, want.NameBytes)
	if !opts.IgnoreIdentity {
		add("id", got.ID, want.ID)
		add("links", got.Links, want.Links)
	}
	add("mode", fmt.Sprintf("%o", got.Mode), fmt.Sprintf("%o", want.Mode))
	add("uid", got.UID, want.UID)
	add("gid", got.GID, want.GID)
	add("flags", got.Flags, want.Flags)
	add("size", got.Size, want.Size)
	for name, pair := range map[string][2]int64{"birth": {got.Times.Birth, want.Times.Birth}, "modify": {got.Times.Modify, want.Times.Modify}, "change": {got.Times.Change, want.Times.Change}, "access": {got.Times.Access, want.Times.Access}} {
		if opts.IgnoreTimes[name] {
			continue
		}
		add("time."+name, pair[0], pair[1])
	}
	add("sha256", got.SHA256, want.SHA256)
	add("target", got.Target, want.Target)
	gx := map[string]schema.Xattr{}
	for _, x := range got.Xattrs {
		gx[x.Name] = x
	}
	for _, x := range want.Xattrs {
		g, ok := gx[x.Name]
		if !ok {
			diffs = append(diffs, Difference{Path: want.Path, Field: "xattr." + x.Name, Got: "absent", Want: fmt.Sprintf("%d bytes %s", x.Bytes, x.SHA256[:12])})
			continue
		}
		if g.SHA256 != x.SHA256 || g.Bytes != x.Bytes {
			diffs = append(diffs, Difference{Path: want.Path, Field: "xattr." + x.Name, Got: fmt.Sprintf("%d bytes %s", g.Bytes, g.SHA256[:12]), Want: fmt.Sprintf("%d bytes %s", x.Bytes, x.SHA256[:12])})
		}
		delete(gx, x.Name)
	}
	for name := range gx {
		diffs = append(diffs, Difference{Path: want.Path, Field: "xattr." + name, Got: "present", Want: "absent"})
	}
	switch {
	case got.Compression == nil && want.Compression != nil:
		add("compression", "none", want.Compression.Type)
	case got.Compression != nil && want.Compression == nil:
		add("compression", got.Compression.Type, "none")
	case got.Compression != nil && want.Compression != nil:
		add("compression.type", got.Compression.Type, want.Compression.Type)
		add("compression.storage", got.Compression.Storage, want.Compression.Storage)
	}
	add("acl", got.ACL, want.ACL)
	return diffs
}

// KnownDrift reports whether a difference between two producers' fixture
// observations is in the allow-list.
func KnownDrift(allow *schema.KnownDrift, recipe, profile string, d Difference, producers [2]int) bool {
	for _, entry := range allow.Entries {
		if entry.Recipe != recipe || (entry.Profile != "" && entry.Profile != profile) || (entry.Path != "" && entry.Path != d.Path) || entry.Field != d.Field {
			continue
		}
		a, okA := entry.Producers[fmt.Sprintf("macos-%d", producers[0])]
		b, okB := entry.Producers[fmt.Sprintf("macos-%d", producers[1])]
		if okA && okB && a == d.Got && b == d.Want {
			return true
		}
	}
	return false
}
