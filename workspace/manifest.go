// Package workspace preserves a selected filesystem tree independently of the
// host's names, permissions, extended attributes and link capabilities.
package workspace

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/edit"
)

const maxManifest = 64 << 20
const maxAttributes = 4096
const metadataPolicy = "recorded; host permissions, ownership, flags and timestamps not applied"

// Limits bound both capture and logical editing.
type Limits = edit.Limits

func DefaultLimits() Limits { return edit.DefaultLimits() }

type blob struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type attribute struct {
	Name  []byte `json:"nameBytes"`
	Value blob   `json:"value"`
}

type object struct {
	Node       filesystem.Node `json:"node"`
	Data       *blob           `json:"data,omitempty"`
	RawData    *blob           `json:"rawData,omitempty"`
	Target     []byte          `json:"targetBytes,omitempty"`
	Attributes []attribute     `json:"attributes"`
}

type entry struct {
	Parent       uint64 `json:"parent"`
	Name         []byte `json:"nameBytes"`
	Object       uint64 `json:"object"`
	HostPath     string `json:"hostPath"`
	Materialized string `json:"materialized"`
}

type manifest struct {
	ParentManifestSHA256 string               `json:"parentManifestSHA256,omitempty"`
	Schema               int                  `json:"schema"`
	Root                 uint64               `json:"root"`
	Names                filesystem.NameRules `json:"names"`
	Objects              []object             `json:"objects"`
	Entries              []entry              `json:"entries"`
	Report               Report               `json:"report"`
}

// Report describes preservation separately from the host projection. Source
// permissions, flags, IDs and timestamps are recorded, never enforced on the host.
type Report struct {
	MetadataObjects  int    `json:"metadataObjects,omitempty"`
	AttributeObjects int    `json:"attributeObjects,omitempty"`
	CreatedObjects   int    `json:"createdObjects,omitempty"`
	ModifiedFiles    int    `json:"modifiedFiles,omitempty"`
	Objects          int    `json:"objects"`
	Entries          int    `json:"entries"`
	StoredBytes      int64  `json:"storedBytes"`
	MappedNames      int    `json:"mappedNames"`
	SymlinksRecorded int    `json:"symlinksRecorded"`
	HardLinks        int    `json:"hardLinks"`
	HardLinksCopied  int    `json:"hardLinksCopied"`
	Metadata         string `json:"metadata"`
}

func nameKey(r filesystem.NameRules) (func(string) string, error) { return edit.NameKey(r) }

func validComponent(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, "/\x00") && len(s) <= 1024
}

// Use one conservative spelling policy on every host. Escaped names occupy a
// reserved prefix, so a user file cannot collide with a generated name.
func portableName(name string) string {
	safe := len(name) <= 120 && !strings.HasSuffix(name, ".") && !strings.HasSuffix(name, " ") && !strings.HasPrefix(name, "~")
	for _, c := range []byte(name) {
		if c < 32 || c > 126 || strings.ContainsRune(`<>:"/\|?*`, rune(c)) {
			safe = false
		}
	}
	stem := strings.ToUpper(strings.SplitN(name, ".", 2)[0])
	if stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" || stem == "CLOCK$" || stem == "CONIN$" || stem == "CONOUT$" || (len(stem) == 4 && (strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT")) && stem[3] >= '1' && stem[3] <= '9') {
		safe = false
	}
	if safe {
		return name
	}
	return escapedName(name)
}

func escapedName(name string) string {
	sum := sha256.Sum256([]byte(name))
	return "~" + hex.EncodeToString(sum[:])
}

func validBlob(b blob) bool {
	x, err := hex.DecodeString(b.SHA256)
	return err == nil && len(x) == 32 && hex.EncodeToString(x) == b.SHA256 && b.Size >= 0
}

func allBlobs(o object) []blob {
	var result []blob
	if o.Data != nil {
		result = append(result, *o.Data)
	}
	if o.RawData != nil {
		result = append(result, *o.RawData)
	}
	for _, a := range o.Attributes {
		result = append(result, a.Value)
	}
	return result
}

func kind(o object) uint32 { return o.Node.Metadata.Mode.Value & 0170000 }

// Unknown observation states cannot silently acquire meaning when reopened.
func validNode(n filesystem.Node) bool { return edit.ValidNode(n) }

// Created object numbers are keys in the workspace graph, not native inode IDs.
func createdIdentity(id filesystem.Identity) bool {
	return id.View == 0 && strings.HasPrefix(id.Volume, "workspace:") && validBlob(blob{SHA256: strings.TrimPrefix(id.Volume, "workspace:")})
}
