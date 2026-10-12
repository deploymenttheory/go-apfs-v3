package session

import (
	"context"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/copyfile"
	"io/fs"
	"path"
	"sort"
)

// WalkOptions follows macOS -R, -h and -H/-L/-P traversal choices. Follow is
// empty or P (physical), H (command-line links), or L (all links).
type WalkOptions struct {
	includeLinks bool // chown -R changes physical symlink ownership; chmod skips it.
	Recursive    bool
	NoFollow     bool
	Follow       string
}
type target struct {
	id   uint64
	path string
}

func resolve(ctx context.Context, r filesystem.Reader, p string, follow bool) (target, error) {
	id, text, err := copyfile.Resolve(ctx, r, p, follow)
	return target{id, text}, err
}
func destination(ctx context.Context, r filesystem.Reader, p string) (string, error) {
	return copyfile.Destination(ctx, r, p)
}
func collect(ctx context.Context, r filesystem.Reader, paths []string, o WalkOptions) ([]target, error) {
	if len(paths) == 0 || (o.Follow != "" && o.Follow != "P" && o.Follow != "H" && o.Follow != "L") {
		return nil, fs.ErrInvalid
	}
	var result []target
	active := map[uint64]bool{}
	var visit func(string, bool, int) error
	visit = func(p string, operand bool, depth int) error {
		if depth > 128 || len(result) >= 200000 {
			return filesystem.ErrLimit
		}
		follow := !o.NoFollow && (!o.Recursive || o.Follow == "L" || (operand && o.Follow == "H"))
		at, err := resolve(ctx, r, p, follow)
		if err != nil {
			return err
		}
		n, err := r.Stat(ctx, at.id)
		if err != nil {
			return err
		}
		if n.Metadata.Mode.Value&0170000 == 0120000 && o.Recursive && !o.NoFollow && !o.includeLinks {
			return nil
		}
		result = append(result, at)
		if n.Metadata.Mode.Value&0170000 != 0040000 || !o.Recursive {
			return nil
		}
		if active[at.id] {
			return filesystem.ErrConflict
		}
		active[at.id] = true
		defer delete(active, at.id)
		var children []filesystem.DirEntry
		if err = r.ReadDir(ctx, at.id, func(e filesystem.DirEntry) error { children = append(children, e); return nil }); err != nil {
			return err
		}
		sort.Slice(children, func(i, j int) bool { return children[i].Name < children[j].Name })
		for _, e := range children {
			if err = visit(path.Join(at.path, e.Name), false, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	for _, p := range paths {
		if err := visit(p, true, 0); err != nil {
			return nil, err
		}
	}
	return result, nil
}

// Lookup resolves an inspection path within the logical session root.
func (s *Session) LookupPath(ctx context.Context, p string, follow bool) (uint64, error) {
	at, err := resolve(ctx, s, p, follow)
	return at.id, err
}
