package acceptance_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/mode"
	"github.com/deploymenttheory/go-apfs-v3/workspace"
)

type nativeCommand struct {
	Argv    []string                    `json:"argv"`
	StartNS int64                       `json:"startNS"`
	EndNS   int64                       `json:"endNS"`
	Effects map[string]map[string]int64 `json:"effects"`
}
type nativeModeVector struct {
	Expression string `json:"expression"`
	Input      uint32 `json:"input"`
	Umask      uint32 `json:"umask"`
	Valid      bool   `json:"valid"`
	Output     uint32 `json:"output"`
}
type nativeFileCommands struct {
	ReadAccessPolicy string             `json:"readAccessPolicy"`
	ModeVectors      []nativeModeVector `json:"modeVectors"`
	Operations       []nativeCommand    `json:"operations"`
	Rejections       [][]string         `json:"rejections"`
	Inputs           []struct {
		File   string `json:"file"`
		Size   int64  `json:"size"`
		SHA256 string `json:"sha256"`
	} `json:"inputs"`
	StartNS     int64  `json:"startNS"`
	EndNS       int64  `json:"endNS"`
	FixedTime   string `json:"fixedTime"`
	UID         uint32 `json:"uid"`
	GID         uint32 `json:"gid"`
	Ownership   string `json:"ownership"`
	After       string `json:"after"`
	AfterSHA256 string `json:"afterSHA256"`
	Image       string `json:"image"`
	ImageSHA256 string `json:"imageSHA256"`
}

var fileCommandsCLI string

func TestNativeFileCommands(t *testing.T) {
	t.Parallel()
	fileCommandsCLI = filepath.Join(t.TempDir(), "apfs")
	if runtime.GOOS == "windows" {
		fileCommandsCLI += ".exe"
	}
	build := exec.Command("go", "build", "-o", fileCommandsCLI, "../cmd/apfs")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build command CLI: %v\n%s", err, output)
	}
	testFileCorpus(t, "file-commands", "APFS_NATIVE_COMMANDS", "testdata/file-commands", 17, nil)
}
func compareFileCommands(t *testing.T, reader filesystem.Reader, before fileObservation, dir, caseID, major string) {
	t.Helper()
	ctx := context.Background()
	ref := before.FileCommands
	if ref == nil || ref.ReadAccessPolicy != "noatime" || len(ref.Operations) != 23 || len(ref.Rejections) != 5 || len(ref.Inputs) != 3 || ref.StartNS >= ref.EndNS {
		t.Fatal("incomplete file-command evidence")
	}
	if len(ref.ModeVectors) != 390 {
		t.Fatal("incomplete native mode vectors", len(ref.ModeVectors))
	}
	for _, v := range ref.ModeVectors {
		program, err := mode.Parse(v.Expression, v.Umask)
		if (err == nil) != v.Valid {
			t.Fatalf("mode %q validity: %v (native %t)", v.Expression, err, v.Valid)
		}
		if err == nil && program.Apply(v.Input) != v.Output {
			t.Fatalf("mode %q on %#o mask %#o: got %#o want %#o", v.Expression, v.Input, v.Umask, program.Apply(v.Input), v.Output)
		}
	}
	if os.Getenv("APFS_REQUIRED_NATIVE_MAJORS") != "" && ref.Ownership != "changed-with-sudo" {
		t.Fatal("missing native ownership change")
	}
	verifyDigest(t, dir, ref.After, ref.AfterSHA256)
	verifyDigest(t, dir, ref.Image, ref.ImageSHA256)
	inputs := map[string]bool{}
	for _, input := range ref.Inputs {
		verifyDigest(t, dir, input.File, input.SHA256)
		info, err := os.Stat(filepath.Join(dir, input.File))
		if err != nil || info.Size() != input.Size {
			t.Fatal("command input", err)
		}
		inputs[input.File] = true
	}
	output := os.Getenv("APFS_COMMAND_OUTPUT")
	if output == "" {
		output = t.TempDir()
	}
	output = filepath.Join(output, "macos-"+major, strings.TrimPrefix(caseID, "file-commands/"))
	if err := os.MkdirAll(output, 0700); err != nil {
		t.Fatal(err)
	}
	scratch := filepath.Join(t.TempDir(), "scratch")
	run := func(arguments []string, reject bool) {
		t.Helper()
		args := append([]string{arguments[0], "--session", "build", "--scratch-dir", scratch}, arguments[1:]...)
		if arguments[0] == "session" {
			args = append([]string{"session", arguments[1], "--scratch-dir", scratch}, arguments[2:]...)
		}
		data, err := exec.Command(fileCommandsCLI, args...).CombinedOutput()
		if reject {
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() <= 0 {
				t.Fatalf("expected command rejection %v: %v %s", args, err, data)
			}
		} else if err != nil {
			t.Fatalf("command %v: %v\n%s", args, err, data)
		}
	}
	image := strings.TrimPrefix(caseID, "file-commands/") + ".dmg"
	run([]string{"session", "open", "--image", filepath.Join(dir, image), "--path", before.Root, "--uid", strconv.FormatUint(uint64(ref.UID), 10), "--gid", strconv.FormatUint(uint64(ref.GID), 10), "--time", ref.FixedTime, "build"}, false)
	run([]string{"session", "export", "build", filepath.Join(output, "before")}, false)
	for i, op := range ref.Operations {
		if op.StartNS < ref.StartNS || op.EndNS > ref.EndNS || op.StartNS > op.EndNS || len(op.Argv) == 0 {
			t.Fatal("invalid native command timing")
		}
		args := append([]string(nil), op.Argv...)
		for j, arg := range args {
			if strings.HasPrefix(arg, "@") {
				name := arg[1:]
				if !inputs[name] {
					t.Fatal("unknown command input")
				}
				args[j] = filepath.Join(dir, name)
			}
		}
		t.Logf("native command %d: %v", i+1, op.Argv)
		run(args, false)
	}
	for _, args := range ref.Rejections {
		current := filepath.Join(scratch, "build", "current")
		data, err := os.ReadFile(current)
		if err != nil {
			t.Fatal(err)
		}
		old := sha256.Sum256(data)
		run(args, true)
		data, err = os.ReadFile(current)
		if err != nil || sha256.Sum256(data) != old {
			t.Fatal("rejected command changed session", err)
		}
	}
	run([]string{"session", "verify", "build"}, false)
	run([]string{"session", "export", "build", filepath.Join(output, "after")}, false)
	result, err := workspace.Open(ctx, filepath.Join(output, "after"))
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	var after fileObservation
	decodeEvidence(t, filepath.Join(dir, ref.After), &after)
	originals := map[uint64]bool{}
	for _, n := range before.Entries {
		originals[n.Object] = true
	}
	expected := after
	expected.Root = "."
	expected.Entries = append([]nativeFile(nil), after.Entries...)
	mapped, reverse := map[uint64]uint64{}, map[uint64]uint64{}
	fixed, err := time.Parse(time.RFC3339Nano, ref.FixedTime)
	if err != nil {
		t.Fatal(err)
	}
	unit := int64(1)
	if reader.NameRules().Format == "HFS+" {
		unit = int64(time.Second)
		fixed = fixed.Truncate(time.Second)
	}
	convert := func(ns int64) int64 {
		if ns >= ref.StartNS/unit*unit && ns <= ref.EndNS/unit*unit+unit-1 {
			return fixed.UnixNano()
		}
		return ns
	}
	for i := range expected.Entries {
		n := &expected.Entries[i]
		nativeID := n.Object
		n.Path = strings.TrimPrefix(n.Path, before.Root+"/")
		if n.Path == before.Root {
			n.Path = "."
		}
		id, err := filesystem.LookupExact(ctx, result, n.Path)
		if err != nil {
			t.Fatal(n.Path, err)
		}
		got, err := result.Stat(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if mapped[nativeID] != 0 && mapped[nativeID] != id {
			t.Fatal("split native hard-link group")
		}
		if reverse[id] != 0 && reverse[id] != nativeID {
			t.Fatal("merged native objects")
		}
		mapped[nativeID] = id
		reverse[id] = nativeID
		n.Object = id
		if originals[nativeID] {
			if got.Created || got.Identity.Object != nativeID {
				t.Fatal("source identity changed")
			}
		} else if !got.Created || !strings.HasPrefix(got.Identity.Volume, "workspace:") {
			t.Fatal("new object impersonates native identity")
		}
		if n.BirthNS == nil {
			t.Fatal("missing native birth precision")
		}
		birth := convert(*n.BirthNS)
		n.BirthNS = &birth
		n.BirthSeconds = birth / int64(time.Second)
		n.ModifyNS = convert(n.ModifyNS)
		n.ChangeNS = convert(n.ChangeNS)
		n.AccessNS = convert(n.AccessNS)
		// This phase makes new copies from logical contents; it does not encode
		// compression. Native copyfile may retain its own physical representation.
		if got.Created && n.Mode&0170000 == 0100000 {
			n.Flags &^= 32
		}
		// Only fresh objects without a copied source receive runner-injected
		// security provenance. Preserve the raw observation; do not manufacture it.
		if commandCreatedPath(n.Path) {
			n.Attributes = maps.Clone(n.Attributes)
			delete(n.Attributes, "com.apple.provenance")
		}
	}
	compareFiles(t, result, expected)
	t.Logf("matched %d native file commands and %d rejection controls over %d entries", len(ref.Operations), len(ref.Rejections), len(after.Entries))
}

func commandCreatedPath(p string) bool {
	switch p {
	case "Applications/Source.app/Contents/Moved", "Applications/Source.app/Contents/Moved/deep", "Applications/Source.app/Contents/Moved/build.bin", "build-alias", "app-link":
		return true
	}
	return false
}
