package schema

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// TreeDigest returns the SHA-256 of a directory's regular files in a
// platform-independent form: for each file in sorted slash-path order, the
// digest input is "<relative path>\n<sha256 of contents>\n". Directories,
// symlinks and other non-regular entries are rejected so that a tree cannot
// hash identically while differing in structure.
func TreeDigest(root string) (string, error) {
	var paths []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			return nil
		case d.Type().IsRegular():
			paths = append(paths, filepath.ToSlash(rel))
			return nil
		default:
			return fmt.Errorf("tree digest: %s is not a regular file or directory", rel)
		}
	})
	if err != nil {
		return "", err
	}
	sort.Strings(paths)
	digest := sha256.New()
	for _, rel := range paths {
		if strings.ContainsRune(rel, '\n') {
			return "", fmt.Errorf("tree digest: path %q contains a newline", rel)
		}
		sum, err := FileDigest(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return "", err
		}
		if _, err := fmt.Fprintf(digest, "%s\n%s\n", rel, sum); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

// FileDigest returns the lowercase hex SHA-256 of a file's contents.
func FileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	digest := sha256.New()
	_, err = io.Copy(digest, f)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return "", fmt.Errorf("digest %s: %w", path, err)
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}
