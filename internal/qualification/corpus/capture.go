package corpus

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
)

// InspectCapture admits an unapproved current capture using the same bounded
// file/manifest rules as retained inputs. The caller must separately check the
// reviewed capture case contract. This cannot replace or approve a catalog.
func InspectCapture(ctx context.Context, repository string, definition Definition) (Catalog, error) {
	if len(definition.Manifests) != 0 || !PortablePath(definition.Path) {
		return Catalog{}, errors.New("capture inspection requires an explicit input tree without retained pins")
	}
	repo, err := os.OpenRoot(repository)
	if err != nil {
		return Catalog{}, err
	}
	defer func() { _ = repo.Close() }()
	root, err := openCommitted(repo, definition.Path)
	if err != nil {
		return Catalog{}, err
	}
	defer func() { _ = root.Close() }()
	err = fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() || !IsManifest(name) {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > MaxManifestBytes {
			return errors.New("invalid capture manifest file")
		}
		input, err := root.Open(name)
		if err != nil {
			return err
		}
		hash := sha256.New()
		n, err := io.Copy(hash, io.LimitReader(contextReader{ctx, input}, MaxManifestBytes+1))
		closeErr := input.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		if n != info.Size() || n > MaxManifestBytes {
			return errors.New("capture manifest changed or exceeds bound")
		}
		data, err := originalManifest(root, name)
		if err != nil {
			return err
		}
		capture, err := parseCapture(name, data)
		if err != nil {
			return err
		}
		definition.Manifests = append(definition.Manifests, ManifestReference{name, hex.EncodeToString(hash.Sum(nil)), capture.Cases})
		return nil
	})
	if err != nil {
		return Catalog{}, err
	}
	if len(definition.Manifests) == 0 {
		return Catalog{}, errors.New("capture has no native manifests")
	}
	return Build(ctx, repository, []Definition{definition})
}
