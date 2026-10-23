package fixture

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"
	"testing"
	"time"
)

const nativePlatformData = "testdata/native-image-ownership/"

type nativePlatformClaim struct {
	Kind, Image, Device  string
	ExpectedOwned, Owned bool
	Error                string
}

type nativePlatformRelation struct {
	Phase, Image, Device, Relation string
}

type nativePlatformOriginal struct {
	Schema                                              int
	KernelVersion, OSBuild, Architecture, Commit, RunID string
	SymlinkAliases                                      map[string]string
	Claims                                              []nativePlatformClaim
	CommandResults                                      []ownershipCommandEvidence
	ContractError, RetentionError                       string
}

type nativePlatformScope struct {
	Argv   []string
	Result Result
}

// These are declared replay identities, not rewritten native observations.
type nativePlatformCapture struct {
	Major              int
	First, Second      Attachment
	Alias, AliasTarget string
	OriginalClaims     []nativePlatformClaim
	Original           nativePlatformOriginal
	Relations          []nativePlatformRelation
	Phases             map[string][]nativePlatformScope
}

func (c nativePlatformCapture) resolveImage(input string) (string, error) {
	switch input {
	case c.First.Image, c.Alias:
		return fmt.Sprintf("native-platform/%d/first", c.Major), nil
	case c.Second.Image:
		return fmt.Sprintf("native-platform/%d/second", c.Major), nil
	default:
		return "", fs.ErrNotExist
	}
}

type nativePlatformCommander struct {
	scopes []nativePlatformScope
	Calls  []Command
}

func (c *nativePlatformCommander) Run(_ context.Context, cmd Command) Result {
	c.Calls = append(c.Calls, cmd)
	for _, scope := range c.scopes {
		if slices.Equal(scope.Argv, cmd.Argv) {
			result := scope.Result
			result.Stdout = bytes.Clone(result.Stdout)
			result.Stderr = bytes.Clone(result.Stderr)
			return result
		}
	}
	return Result{Status: -1, Err: fmt.Errorf("query has no original native result in this phase: %v", cmd.Argv)}
}

func (c nativePlatformCapture) commander(t *testing.T, phase string) *nativePlatformCommander {
	t.Helper()
	scopes, ok := c.Phases[phase]
	if !ok {
		t.Fatalf("native platform capture %d has no phase %q", c.Major, phase)
	}
	return &nativePlatformCommander{scopes: scopes}
}

// Every ZIP/member digest is verified before a result is exposed to replay.
// The archives, including the native manifest and failed adapter booleans,
// remain verbatim. No native tool is invoked and no raw image is expanded.
func retainedNativePlatformCaptures(t *testing.T) []nativePlatformCapture {
	t.Helper()
	var provenance struct {
		Schema                                 int
		RunID                                  int64
		HeadCommit, CheckoutCommit, SourceTree string
		Captures                               []struct {
			Major                                           int
			File, ZipSHA256, ManifestMember, ManifestSHA256 string
			ZipBytes                                        int64
			Provider                                        struct {
				ID          int64
				Digest      string
				WorkflowRun struct {
					ID      int64
					HeadSHA string `json:"head_sha"`
				} `json:"workflow_run"`
			}
			Members []struct {
				Name, SHA256 string
				Bytes        int64
			}
			Relations []nativePlatformRelation
		}
	}
	b, err := os.ReadFile(nativePlatformData + "provenance.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &provenance); err != nil {
		t.Fatal(err)
	}
	if provenance.Schema != 1 || provenance.RunID != 39941597269 || provenance.HeadCommit != "f4ace5f9344f55c5e2869898347a51535782a343" || provenance.CheckoutCommit != "3687692e090a1c39d61e40de837f4e9e2e7756bd" || provenance.SourceTree != "0829b2be5618092a925ad8c30977a2734ef2879c" || len(provenance.Captures) != 3 {
		t.Fatal("original native platform capture provenance changed")
	}
	providers := map[int]string{15: "41b3cd5418c2d6b192592d3899216810e9616a298fe6c7219dcb13f2f41ebed7", 26: "014eb2a870e2fdf8b95cb0c45afe4cbb463307073a5ede7b2cbc940179137c1c", 27: "a2ddd1e26ec38cec7c45405fd5391022ff9117eddd5a7b3222f12c74381f274e"}
	providerIDs := map[int]int64{15: 12496501587, 26: 12495962540, 27: 12496641090}
	var captures []nativePlatformCapture
	for _, source := range provenance.Captures {
		raw, err := os.ReadFile(nativePlatformData + source.File)
		want, present := providers[source.Major]
		if err != nil || !present || source.File != fmt.Sprintf("macos-%d.zip", source.Major) || source.Provider.ID != providerIDs[source.Major] || source.Provider.WorkflowRun.ID != provenance.RunID || source.Provider.WorkflowRun.HeadSHA != provenance.HeadCommit || int64(len(raw)) != source.ZipBytes || fmt.Sprintf("%x", sha256.Sum256(raw)) != want || source.ZipSHA256 != want || source.Provider.Digest != "sha256:"+want {
			t.Fatalf("original provider archive %d changed: %v", source.Major, err)
		}
		delete(providers, source.Major)
		z, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
		if err != nil {
			t.Fatal(err)
		}
		members := map[string]*zip.File{}
		for _, file := range z.File {
			if file.FileInfo().IsDir() {
				continue
			}
			if _, duplicate := members[file.Name]; duplicate {
				t.Fatal("duplicate original archive member", file.Name)
			}
			members[file.Name] = file
		}
		read := func(name string) []byte {
			t.Helper()
			file := members[name]
			if file == nil {
				t.Fatal("missing original archive member", name)
			}
			r, err := file.Open()
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(r)
			if closeErr := r.Close(); err == nil {
				err = closeErr
			}
			if err != nil {
				t.Fatal(err)
			}
			return data
		}
		if len(source.Members) != len(members) {
			t.Fatal("original archive member inventory changed")
		}
		verifiedMembers := map[string]bool{}
		for _, member := range source.Members {
			file := members[member.Name]
			if file == nil || verifiedMembers[member.Name] || int64(file.UncompressedSize64) != member.Bytes {
				t.Fatal("original member size changed", member.Name)
			}
			verifiedMembers[member.Name] = true
			r, err := file.Open()
			if err != nil {
				t.Fatal(err)
			}
			h := sha256.New()
			_, err = io.Copy(h, r)
			if closeErr := r.Close(); err == nil {
				err = closeErr
			}
			if err != nil || fmt.Sprintf("%x", h.Sum(nil)) != member.SHA256 {
				t.Fatal("original member digest changed", member.Name, err)
			}
		}
		manifest := read(source.ManifestMember)
		if fmt.Sprintf("%x", sha256.Sum256(manifest)) != source.ManifestSHA256 {
			t.Fatal("original native manifest changed")
		}
		var original nativePlatformOriginal
		if err := json.Unmarshal(manifest, &original); err != nil {
			t.Fatal(err)
		}
		if original.Schema != 1 || original.Commit != provenance.CheckoutCommit || original.RunID != "39941597269" || original.RetentionError != "" || !strings.HasPrefix(original.KernelVersion, fmt.Sprint(source.Major)+".") {
			t.Fatal("native capture provenance or complete-retention status changed")
		}
		capture := nativePlatformCapture{Major: source.Major, Original: original, OriginalClaims: original.Claims, Relations: source.Relations, Phases: map[string][]nativePlatformScope{}}
		for _, claim := range original.Claims {
			switch claim.Kind {
			case "positive-first":
				capture.First = Attachment{Image: claim.Image, Dev: claim.Device}
			case "positive-second":
				capture.Second = Attachment{Image: claim.Image, Dev: claim.Device}
			}
		}
		if capture.First.Image == "" || capture.Second.Image == "" || capture.First.Image == capture.Second.Image || capture.First.Dev == capture.Second.Dev || len(original.SymlinkAliases) != 1 {
			t.Fatal("original distinct image bindings changed")
		}
		for alias, target := range original.SymlinkAliases {
			capture.Alias, capture.AliasTarget = alias, target
		}
		if capture.AliasTarget != capture.First.Image {
			t.Fatal("original alias target changed")
		}
		for _, row := range original.CommandResults {
			streams := make([][]byte, 2)
			for i, stream := range []ownershipStreamEvidence{row.Stdout, row.Stderr} {
				data := read(path.Join(path.Dir(source.ManifestMember), stream.File))
				if stream.RetentionError != "" || len(data) != stream.Bytes || stream.StoredBytes != stream.Bytes || fmt.Sprintf("%x", sha256.Sum256(data)) != stream.SHA256 || stream.StoredSHA256 != stream.SHA256 {
					t.Fatal("original complete command-result stream changed", row.Sequence)
				}
				streams[i] = data
			}
			if !strings.HasPrefix(row.Label, "collect-") {
				continue
			}
			result := Result{Status: row.Status, Stdout: streams[0], Stderr: streams[1], Duration: time.Duration(row.WallNS)}
			if row.Error != "" {
				result.Err = errors.New(row.Error)
			}
			capture.Phases[row.Phase] = append(capture.Phases[row.Phase], nativePlatformScope{Argv: row.Argv, Result: result})
		}
		captures = append(captures, capture)
	}
	return captures
}
