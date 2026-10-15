// Package corpus admits immutable native acceptance inputs. It has no network
// or native filesystem-tool execution path and never certifies Go output.
package corpus

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	MaxCatalogBytes        = 16 << 20
	MaxManifestBytes       = 16 << 20
	MaxBundleBytes   int64 = (2 << 30) - 1
	MaxTreeBytes     int64 = 16 << 30
	MaxFiles               = 100000
)

type Catalog struct {
	Schema  int     `json:"schema"`
	Entries []Entry `json:"entries"`
}

type Binding struct {
	Family       string `json:"family"`
	CaptureClass string `json:"capture_class"`
}

type File struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// Capture refers to the original document even when retention gzip-compressed
// it. ProducerSHA256 binds its complete canonical producer object; source/tool
// details remain in that unchanged original, including historical omissions.
type Capture struct {
	Manifest       string   `json:"manifest"`
	Role           string   `json:"role"`
	OriginalBytes  int64    `json:"original_bytes"`
	OriginalSHA256 string   `json:"original_sha256"`
	Major          int      `json:"major"`
	Contract       string   `json:"contract"`
	Producer       Producer `json:"producer"`
	ProducerSHA256 string   `json:"producer_sha256"`
	Cases          []string `json:"cases"`
}

type Producer struct {
	System       string `json:"system"`
	Version      string `json:"version"`
	Build        string `json:"build"`
	Architecture string `json:"architecture"`
}

type Bundle struct {
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

func (b Bundle) Filename() string { return "sha256-" + b.SHA256 + ".tar.gz" }

// Location is excluded from TreeSHA256: transport may change without changing
// input identity. A reviewed catalog still pins the exact transport digest.
type Location struct {
	Kind   string  `json:"kind"`
	Path   string  `json:"path,omitempty"`
	Bundle *Bundle `json:"bundle,omitempty"`
}

type Entry struct {
	ID         string    `json:"id"`
	TreeSHA256 string    `json:"tree_sha256"`
	Bindings   []Binding `json:"bindings"`
	Files      []File    `json:"files"`
	Captures   []Capture `json:"captures"`
	Location   Location  `json:"location"`
}

var identifier = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

func ValidDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && strings.ToLower(value) == value
}

// PortablePath rejects aliases that can escape a root or collide on Windows,
// even when the catalog is being inspected on Linux or macOS.
func PortablePath(value string) bool {
	if !fs.ValidPath(value) || value == "." || len(value) > 1024 || !utf8.ValidString(value) || strings.ContainsAny(value, "\\:\"*?<>|") {
		return false
	}
	for _, component := range strings.Split(value, "/") {
		if strings.TrimRight(component, ". ") != component {
			return false
		}
		for _, c := range component {
			if c < 32 || c == 127 {
				return false
			}
		}
		base := strings.ToUpper(strings.SplitN(component, ".", 2)[0])
		if slices.Contains([]string{"COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³"}, base) {
			return false
		}
		if slices.Contains([]string{"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}, base) || (len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '0' && base[3] <= '9') {
			return false
		}
	}
	return true
}

func (e Entry) Identity() (string, error) {
	data, err := json.Marshal(struct {
		Schema   int       `json:"schema"`
		ID       string    `json:"id"`
		Bindings []Binding `json:"bindings"`
		Files    []File    `json:"files"`
		Captures []Capture `json:"captures"`
	}{1, e.ID, e.Bindings, e.Files, e.Captures})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func (e Entry) TotalBytes() int64 {
	var total int64
	for _, f := range e.Files {
		total += f.Bytes
	}
	return total
}

func (e Entry) Validate() error {
	if !identifier.MatchString(e.ID) || len(e.Files) == 0 || len(e.Files) > MaxFiles || len(e.Bindings) == 0 || len(e.Captures) == 0 {
		return fmt.Errorf("incomplete corpus entry %q", e.ID)
	}
	last := ""
	for _, b := range e.Bindings {
		if !identifier.MatchString(b.Family) || b.Family <= last || !slices.Contains([]string{"apple-independent", "current-go-experiment"}, b.CaptureClass) {
			return fmt.Errorf("invalid/duplicate capture binding in %s", e.ID)
		}
		last = b.Family
	}
	files := map[string]File{}
	var total int64
	last = ""
	for _, f := range e.Files {
		key := strings.ToLower(f.Path)
		if !PortablePath(f.Path) || f.Path <= last || f.Bytes < 0 || f.Bytes > MaxTreeBytes-total || !ValidDigest(f.SHA256) {
			return fmt.Errorf("invalid file contract: %s/%s", e.ID, f.Path)
		}
		if _, exists := files[key]; exists {
			return fmt.Errorf("portable path collision: %s", f.Path)
		}
		files[key] = f
		total += f.Bytes
		last = f.Path
	}
	for key := range files {
		for parent := path.Dir(key); parent != "."; parent = path.Dir(parent) {
			if _, exists := files[parent]; exists {
				return fmt.Errorf("file/directory collision: %s", key)
			}
		}
	}
	directories := map[string]string{}
	for _, f := range e.Files {
		for parent := path.Dir(f.Path); parent != "."; parent = path.Dir(parent) {
			key := strings.ToLower(parent)
			if original, exists := directories[key]; exists && original != parent {
				return fmt.Errorf("portable directory collision: %s", parent)
			}
			directories[key] = parent
			if len(directories) > MaxFiles {
				return errors.New("corpus directory count exceeds bound")
			}
		}
	}
	last = ""
	manifests := map[string]bool{}
	for _, c := range e.Captures {
		f, exists := files[strings.ToLower(c.Manifest)]
		if !exists || f.Path != c.Manifest || c.Manifest <= last || c.OriginalBytes <= 0 || c.OriginalBytes > MaxManifestBytes || !ValidDigest(c.OriginalSHA256) || c.Contract == "" || len(c.Cases) == 0 {
			return fmt.Errorf("invalid capture contract in %s: %s", e.ID, c.Manifest)
		}
		if !slices.Contains([]string{"native-capture", "retained-projection", "retained-index"}, c.Role) {
			return fmt.Errorf("unknown retained manifest role: %s", c.Manifest)
		}
		producer := c.Producer
		if producer.System != "macOS" || producer.Build == "" || producer.Architecture == "" || !ValidDigest(c.ProducerSHA256) || !slices.Contains([]int{15, 26, 27}, c.Major) || !strings.HasPrefix(producer.Version, fmt.Sprint(c.Major)+".") {
			return fmt.Errorf("native producer identity missing: %s", c.Manifest)
		}
		cases := map[string]bool{}
		for _, id := range c.Cases {
			if id == "" || cases[id] {
				return fmt.Errorf("empty/duplicate capture case in %s", c.Manifest)
			}
			cases[id] = true
		}
		last = c.Manifest
		manifests[c.Manifest] = true
	}
	for _, f := range e.Files {
		if IsManifest(f.Path) && !manifests[f.Path] {
			return fmt.Errorf("retained manifest missing capture contract: %s", f.Path)
		}
	}
	switch e.Location.Kind {
	case "committed":
		if !PortablePath(e.Location.Path) || e.Location.Bundle != nil {
			return errors.New("invalid committed corpus location")
		}
	case "bundle":
		b := e.Location.Bundle
		if e.Location.Path != "" || b == nil || !ValidDigest(b.SHA256) || b.Bytes <= 0 || b.Bytes > MaxBundleBytes {
			return errors.New("invalid content-addressed bundle location")
		}
	default:
		return errors.New("unknown corpus transport")
	}
	identity, err := e.Identity()
	if err != nil {
		return err
	}
	if identity != e.TreeSHA256 {
		return fmt.Errorf("corpus input identity differs: %s", e.ID)
	}
	return nil
}

func (c Catalog) Validate() error {
	if c.Schema != 1 || len(c.Entries) == 0 || len(c.Entries) > 1000 {
		return errors.New("invalid corpus catalog schema/count")
	}
	last := ""
	for _, entry := range c.Entries {
		if entry.ID <= last {
			return errors.New("unsorted/duplicate corpus IDs")
		}
		if err := entry.Validate(); err != nil {
			return err
		}
		last = entry.ID
	}
	return nil
}

func Read(input io.Reader) (Catalog, error) {
	var c Catalog
	data, err := io.ReadAll(io.LimitReader(input, MaxCatalogBytes+1))
	if err != nil {
		return c, err
	}
	if len(data) > MaxCatalogBytes {
		return c, errors.New("corpus catalog exceeds size bound")
	}
	if err = StrictJSON(data, &c); err != nil {
		return c, err
	}
	return c, c.Validate()
}

// StrictJSON refuses duplicate keys as well as unknown fields and trailing
// values. Duplicate JSON keys must not select different contracts in tools.
func StrictJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := uniqueValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON value")
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
}

func uniqueValue(decoder *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("JSON nesting exceeds bound")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delim != '{' && delim != '[' {
		return errors.New("unexpected JSON delimiter")
	}
	seen := map[string]bool{}
	for decoder.More() {
		if delim == '{' {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return errors.New("duplicate or invalid JSON key")
			}
			seen[name] = true
		}
		if err := uniqueValue(decoder, depth+1); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}
