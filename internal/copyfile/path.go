package copyfile

import (
	"context"
	"errors"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"io/fs"
	"path"
	"strings"
)

type target struct {
	id   uint64
	path string
}

func resolve(ctx context.Context, r filesystem.Reader, p string, follow bool) (target, error) {
	if p == "" || strings.ContainsRune(p, 0) || len(p) > 128*1025 {
		return target{}, fs.ErrInvalid
	}
	requireDirectory := strings.HasSuffix(p, "/")
	parts := strings.Split(p, "/")
	stack := []target{{r.Root(), "/"}}
	links := 0
	steps := 0
	for len(parts) > 0 {
		if err := ctx.Err(); err != nil {
			return target{}, err
		}
		steps++
		if steps > 128*1025 {
			return target{}, filesystem.ErrLimit
		}
		part := parts[0]
		parts = parts[1:]
		parentNode, err := r.Stat(ctx, stack[len(stack)-1].id)
		if err != nil {
			return target{}, err
		}
		if parentNode.Metadata.Mode.Value&0170000 != 0040000 {
			return target{}, fs.ErrInvalid
		}
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
			continue
		}
		parent := stack[len(stack)-1]
		e, err := r.Lookup(ctx, parent.id, part)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && len(parts) == 0 {
				return target{path: path.Join(parent.path, part)}, err
			}
			return target{}, err
		}
		n, err := r.Stat(ctx, e.Object)
		if err != nil {
			return target{}, err
		}
		at := target{e.Object, path.Join(parent.path, e.Name)}
		if n.Metadata.Mode.Value&0170000 == 0120000 && (follow || len(parts) > 0 || requireDirectory) {
			links++
			if links > 40 {
				return target{}, filesystem.ErrLimit
			}
			text, err := r.Readlink(ctx, e.Object)
			if err != nil {
				return target{}, err
			}
			if text == "" || strings.ContainsRune(text, 0) {
				return target{}, filesystem.ErrCorrupt
			}
			if strings.HasPrefix(text, "/") {
				stack = stack[:1]
			}
			parts = append(strings.Split(text, "/"), parts...)
			continue
		}
		stack = append(stack, at)
		if len(stack) > 129 {
			return target{}, filesystem.ErrLimit
		}
	}
	at := stack[len(stack)-1]
	if requireDirectory {
		n, err := r.Stat(ctx, at.id)
		if err != nil {
			return target{}, err
		}
		if n.Metadata.Mode.Value&0170000 != 0040000 {
			return target{}, fs.ErrInvalid
		}
	}
	return at, nil
}
func destination(ctx context.Context, r filesystem.Reader, p string) (string, error) {
	if p == "" || strings.ContainsRune(p, 0) {
		return "", fs.ErrInvalid
	}
	p = strings.TrimRight(p, "/")
	if p == "" || p == "." || p == ".." {
		return "", fs.ErrInvalid
	}
	at := strings.LastIndex(p, "/")
	base, parentPath := p[at+1:], "/"
	if at >= 0 {
		parentPath = p[:at]
		if parentPath == "" {
			parentPath = "/"
		}
	}
	if base == "." || base == ".." {
		return "", fs.ErrInvalid
	}
	parent, err := resolve(ctx, r, parentPath, true)
	if err != nil {
		return "", err
	}
	n, err := r.Stat(ctx, parent.id)
	if err != nil {
		return "", err
	}
	if n.Metadata.Mode.Value&0170000 != 0040000 {
		return "", fs.ErrInvalid
	}
	return path.Join(parent.path, base), nil
}
func operandDestination(ctx context.Context, r filesystem.Reader, source, to string) (string, error) {
	at, err := resolve(ctx, r, to, true)
	if err == nil {
		n, err := r.Stat(ctx, at.id)
		if err != nil {
			return "", err
		}
		if n.Metadata.Mode.Value&0170000 == 0040000 {
			return destination(ctx, r, path.Join(at.path, path.Base(strings.TrimRight(source, "/"))))
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	return destination(ctx, r, to)
}

func Resolve(ctx context.Context, r filesystem.Reader, p string, follow bool) (uint64, string, error) {
	at, err := resolve(ctx, r, p, follow)
	return at.id, at.path, err
}
func Destination(ctx context.Context, r filesystem.Reader, p string) (string, error) {
	return destination(ctx, r, p)
}
func OperandDestination(ctx context.Context, r filesystem.Reader, source, to string) (string, error) {
	return operandDestination(ctx, r, source, to)
}
