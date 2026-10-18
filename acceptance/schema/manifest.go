package schema

// ManifestSchema is the current bundle manifest schema version.
const ManifestSchema = 1

// Manifest indexes one producer's bundle. It is written by the capture tool
// after every case has completed and is the only file a consumer needs to
// read to know what the bundle must contain.
type Manifest struct {
	Schema   int        `json:"schema"`
	Producer Producer   `json:"producer"`
	Recipes  string     `json:"recipesSHA256"`
	Cases    []CaseFile `json:"cases"`
}

// Producer identifies the macOS installation and run that produced a bundle.
type Producer struct {
	Major        int               `json:"major"`
	Version      string            `json:"version"`
	Build        string            `json:"build"`
	Architecture string            `json:"architecture"`
	Runner       string            `json:"runner"`
	Repository   string            `json:"repository,omitempty"`
	Commit       string            `json:"commit,omitempty"`
	RunURL       string            `json:"runUrl,omitempty"`
	Tools        map[string]string `json:"tools"` // absolute path -> SHA-256
	CaptureTool  string            `json:"captureToolSHA256"`
}

// CaseFile locates one captured case and every file that belongs to it.
type CaseFile struct {
	Recipe      string      `json:"recipe"`
	Profile     string      `json:"profile"`
	Stage       string      `json:"stage"`
	Observation string      `json:"observation"` // relative path of the observation JSON
	Files       []FileEntry `json:"files"`
}

// FileEntry is a bundle member with its size and digest.
type FileEntry struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}
