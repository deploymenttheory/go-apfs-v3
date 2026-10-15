package corpus

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
)

type Options struct {
	Repository string
	Bundles    string
	Scratch    string
}

type Resolver struct {
	entries map[string]Entry
	options Options
}

type Resolved struct {
	path  string
	entry Entry
	root  *os.Root
	owned bool
}

func (r *Resolved) Path() string       { return r.path }
func (r *Resolved) ID() string         { return r.entry.ID }
func (r *Resolved) TreeSHA256() string { return r.entry.TreeSHA256 }

func New(catalog Catalog, options Options) (*Resolver, error) {
	// Detach metadata slices from the caller before retaining admitted inputs.
	data, err := json.Marshal(catalog)
	if err != nil {
		return nil, err
	}
	catalog, err = Read(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	for _, directory := range []*string{&options.Repository, &options.Bundles, &options.Scratch} {
		if *directory != "" {
			*directory, err = filepath.Abs(*directory)
			if err != nil {
				return nil, err
			}
		}
	}
	r := &Resolver{entries: map[string]Entry{}, options: options}
	for _, entry := range catalog.Entries {
		r.entries[entry.ID] = entry
	}
	return r, nil
}

func (r *Resolver) Resolve(ctx context.Context, id string) (*Resolved, error) {
	entry, ok := r.entries[id]
	if !ok {
		return nil, fmt.Errorf("required corpus is absent from catalog: %s", id)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if entry.Location.Kind == "bundle" {
		result, err := r.extract(ctx, entry)
		if err != nil {
			return nil, fmt.Errorf("corpus %s: %w", id, err)
		}
		return result, nil
	}
	if r.options.Repository == "" {
		return nil, errors.New("repository root is required for committed corpus")
	}
	repo, err := os.OpenRoot(r.options.Repository)
	if err != nil {
		return nil, err
	}
	defer func() { _ = repo.Close() }()
	root, err := openCommitted(repo, entry.Location.Path)
	if err != nil {
		return nil, err
	}
	result := &Resolved{path: filepath.Join(r.options.Repository, filepath.FromSlash(entry.Location.Path)), entry: entry, root: root}
	if err = result.Verify(ctx); err != nil {
		_ = result.Close()
		return nil, fmt.Errorf("corpus %s: %w", id, err)
	}
	return result, nil
}

// Verify checks exact membership and original manifests, both on admission and
// after replay. Callers must place writable outputs in a separate scratch tree.
func (r *Resolved) Verify(ctx context.Context) error {
	if r.root == nil {
		return errors.New("corpus is closed")
	}
	files := map[string]File{}
	directories := map[string]bool{".": true}
	for _, f := range r.entry.Files {
		files[f.Path] = f
		for parent := path.Dir(f.Path); parent != "."; parent = path.Dir(parent) {
			directories[parent] = true
		}
	}
	seen := 0
	err := fs.WalkDir(r.root.FS(), ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() {
			if !directories[name] {
				return fmt.Errorf("unexpected corpus directory: %s", name)
			}
			return nil
		}
		file, ok := files[name]
		if !ok {
			return fmt.Errorf("unexpected corpus member: %s", name)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() != file.Bytes {
			return fmt.Errorf("invalid corpus member: %s", name)
		}
		input, err := r.root.Open(name)
		if err != nil {
			return err
		}
		err = copyVerified(ctx, io.Discard, input, file.Bytes, file.SHA256)
		closeErr := input.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if closeErr != nil {
			return closeErr
		}
		seen++
		return nil
	})
	if err != nil {
		return err
	}
	if seen != len(files) {
		return errors.New("required corpus members are missing")
	}
	for _, capture := range r.entry.Captures {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := verifyCapture(r.root, capture); err != nil {
			return err
		}
	}
	return nil
}

func (r *Resolved) Close() error {
	if r.root == nil {
		return nil
	}
	err := r.root.Close()
	r.root = nil
	if r.owned {
		err = errors.Join(err, os.RemoveAll(r.path))
	}
	return err
}

type contextReader struct {
	context context.Context
	input   io.Reader
}

func (r contextReader) Read(buffer []byte) (int, error) {
	if err := r.context.Err(); err != nil {
		return 0, err
	}
	return r.input.Read(buffer)
}

func copyVerified(ctx context.Context, output io.Writer, input io.Reader, size int64, digest string) error {
	hash := sha256.New()
	n, err := io.CopyBuffer(io.MultiWriter(output, hash), io.LimitReader(contextReader{ctx, input}, size+1), make([]byte, 64<<10))
	if err != nil {
		return err
	}
	if n != size {
		return fmt.Errorf("corpus member size mismatch: want %d, got %d", size, n)
	}
	if hex.EncodeToString(hash.Sum(nil)) != digest {
		return errors.New("corpus member SHA-256 mismatch")
	}
	return nil
}

func originalManifest(root *os.Root, name string) ([]byte, error) {
	input, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = input.Close() }()
	var reader io.Reader = input
	if strings.HasSuffix(name, ".gz") {
		z, err := gzip.NewReader(input)
		if err != nil {
			return nil, err
		}
		defer func() { _ = z.Close() }()
		reader = z
	}
	data, err := io.ReadAll(io.LimitReader(reader, MaxManifestBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxManifestBytes {
		return nil, errors.New("original manifest exceeds bound")
	}
	return data, nil
}

func parseCapture(name string, data []byte) (Capture, error) {
	c := Capture{Manifest: name, OriginalBytes: int64(len(data))}
	sum := sha256.Sum256(data)
	c.OriginalSHA256 = hex.EncodeToString(sum[:])
	var doc map[string]json.RawMessage
	if err := StrictJSON(data, &doc); err != nil {
		return c, err
	}
	c.Role = "native-capture"
	if _, ok := doc["originalManifestSHA256"]; ok {
		c.Role = "retained-projection"
	} else if _, ok := doc["evidence"]; ok {
		c.Role = "retained-index"
	}
	if err := json.Unmarshal(doc["contract"], &c.Contract); err != nil {
		if err = json.Unmarshal(doc["scenario"], &c.Contract); err != nil {
			return c, err
		}
	}
	var producer map[string]any
	decoder := json.NewDecoder(bytes.NewReader(doc["producer"]))
	decoder.UseNumber()
	if err := decoder.Decode(&producer); err != nil {
		return c, err
	}
	version, ok := producer["version"].(string)
	if !ok {
		return c, errors.New("native producer version missing")
	}
	if _, err := fmt.Sscanf(version, "%d.", &c.Major); err != nil {
		return c, err
	}
	canonicalProducer, err := json.Marshal(producer)
	if err != nil {
		return c, err
	}
	sum = sha256.Sum256(canonicalProducer)
	c.ProducerSHA256 = hex.EncodeToString(sum[:])
	if err := json.Unmarshal(doc["producer"], &c.Producer); err != nil {
		return c, err
	}
	for _, key := range []string{"cases", "rejections", "sectorProbes"} {
		if raw, ok := doc[key]; ok {
			var cases []map[string]json.RawMessage
			if err := json.Unmarshal(raw, &cases); err != nil {
				return c, err
			}
			for _, record := range cases {
				var id string
				if key == "sectorProbes" {
					var capacity int64
					if err := json.Unmarshal(record["capacity"], &capacity); err != nil {
						return c, err
					}
					id = fmt.Sprint(capacity)
				} else if err := json.Unmarshal(record["id"], &id); err != nil {
					return c, err
				}
				c.Cases = append(c.Cases, key+"/"+id)
			}
		}
	}
	return c, nil
}

func verifyCapture(root *os.Root, want Capture) error {
	data, err := originalManifest(root, want.Manifest)
	if err != nil {
		return err
	}
	actual, err := parseCapture(want.Manifest, data)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(actual, want) {
		return fmt.Errorf("retained capture manifest differs: %s", want.Manifest)
	}
	return nil
}

func openCommitted(repo *os.Root, name string) (*os.Root, error) {
	for current := name; current != "."; current = path.Dir(current) {
		info, err := repo.Lstat(current)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("corpus directory is not an ordinary directory: %s", current)
		}
	}
	return repo.OpenRoot(name)
}
