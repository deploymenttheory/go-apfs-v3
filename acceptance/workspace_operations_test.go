package acceptance_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/native"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/workspace"
)

func TestWorkspaceOperationsMatchAppleStates(t *testing.T) {
	cases, _ := loadCorpus(t)
	recipes := recipesByName(t)
	indexed := indexCases(cases)
	for _, before := range cases {
		if before.Recipe != "workspace-edits" || before.Stage != "before" {
			continue
		}
		t.Run(fmt.Sprintf("macos-%d/%s", before.Producer, before.Profile), func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			recipe := recipes[before.Recipe]
			_, reader, closeSource := openSingleVolume(t, ctx, before, recipe)
			defer closeSource()
			root, err := filesystem.LookupExact(ctx, reader, "Fixture")
			if err != nil {
				t.Fatal(err)
			}
			sourceHash, err := schema.FileDigest(before.Image())
			if err != nil {
				t.Fatal(err)
			}
			current := produceWorkspace(t, before, before, "extract", &schema.WorkspaceExpectation{Policy: "preserve"}, func(dir string) error {
				_, err := workspace.Extract(ctx, reader, root, dir, workspace.Limits{})
				return err
			})
			defer func() { _ = current.Close() }()
			parentOutput := outputName(before, "workspace.extract.tar.gz")
			for _, stage := range recipe.Stages[1:] {
				after := indexed[stageKey(before.Producer, before.Recipe, before.Profile, stage.Name)]
				if after.Observation == nil {
					t.Fatalf("missing native %s stage", stage.Name)
				}
				var next *workspace.Workspace
				if stage.Name == "replaced" {
					replacements := workspaceReplacements(t, current, stage)
					next = produceWorkspace(t, before, after, "replace", &schema.WorkspaceExpectation{Policy: "preserve", ParentOutput: parentOutput}, func(dir string) error {
						_, err := current.ReplaceData(ctx, replacements, dir, workspace.Limits{})
						return err
					})
				} else {
					_, reference, closeReference := openSingleVolume(t, ctx, after, recipe)
					changes, probes := workspaceChanges(t, current, reference, stage, after)
					next = produceWorkspace(t, before, after, "edit", &schema.WorkspaceExpectation{Policy: "preserve", ParentOutput: parentOutput}, func(dir string) error {
						_, err := current.Edit(ctx, changes, dir, workspace.Limits{})
						return err
					})
					for _, probe := range probes {
						checkWorkspaceProbe(t, next, probe)
					}
					closeReference()
				}
				if next.ParentManifestSHA256() != current.ManifestSHA256() {
					t.Fatal("workspace edit lost its parent digest")
				}
				if err := current.Close(); err != nil {
					t.Fatal(err)
				}
				current = next
				operation := "edit"
				if stage.Name == "replaced" {
					operation = "replace"
				}
				parentOutput = outputName(after, "workspace."+operation+".tar.gz")
			}
			if sum, err := schema.FileDigest(before.Image()); err != nil || sum != sourceHash {
				t.Fatal("workspace operations changed the native source", err)
			}
		})
	}
}

func indexCases(cases []corpus.Case) map[string]corpus.Case {
	out := map[string]corpus.Case{}
	for _, k := range cases {
		out[stageKey(k.Producer, k.Recipe, k.Profile, k.Stage)] = k
	}
	return out
}

// Every stage publishes the actual preservation output, including its host
// projection. Tar headers describe only portable names and bytes, not host IDs
// or wall clocks. Hard-link aliases are serialized as ordinary files; the
// manifest independently retains and verifies their logical relationship.
func archiveWorkspace(directory, destination string) (err error) {
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	z := gzip.NewWriter(out)
	w := tar.NewWriter(z)
	err = filepath.WalkDir(directory, func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if filename == directory {
			return nil
		}
		rel, err := filepath.Rel(directory, filename)
		if err != nil {
			return err
		}
		h := &tar.Header{Name: filepath.ToSlash(rel), Mode: 0600, Typeflag: tar.TypeReg, Format: tar.FormatPAX}
		if entry.IsDir() {
			h.Typeflag, h.Mode = tar.TypeDir, 0700
			return w.WriteHeader(h)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("unsafe workspace projection %s", rel)
		}
		h.Size = info.Size()
		if err := w.WriteHeader(h); err != nil {
			return err
		}
		f, err := os.Open(filename)
		if err != nil {
			return err
		}
		_, err = io.Copy(w, f)
		return errors.Join(err, f.Close())
	})
	return errors.Join(err, w.Close(), z.Close(), out.Close())
}

func produceWorkspace(t *testing.T, before, after corpus.Case, operation string, policy *schema.WorkspaceExpectation, produce func(string) error) *workspace.Workspace {
	t.Helper()
	var first string
	name := outputName(after, "workspace."+operation+".tar.gz")
	archive := produceTwice(t, name, true, func(destination string) error {
		dir := filepath.Join(t.TempDir(), "workspace")
		if err := produce(dir); err != nil {
			return err
		}
		if first == "" {
			first = dir
		}
		return archiveWorkspace(dir, destination)
	})
	expect := schema.Expectation{Subtree: "Fixture", Workspace: policy}
	if after.Stage != before.Stage {
		expect.View = after.Stage
	}
	view, err := native.WorkspaceReference(before.Observation.Views[0], after.Observation.Views[0], expect)
	if err != nil {
		t.Fatal(err)
	}
	w, err := workspace.Open(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	// The public reader and the independent archive decoder must agree with
	// native observations. The latter also checks all raw values and identities.
	compareViewWith(t, context.Background(), name, w, view, compareOptions{subtree: "Fixture"})
	diffs, err := native.VerifyWorkspaceArchive(archive, before.Profile, before.Observation.Views[0], after.Observation.Views[0], expect)
	if err != nil {
		t.Fatal(name, err)
	}
	for _, d := range diffs {
		t.Error(name, d)
	}
	recordOutput(t, schema.Output{Name: name, File: filepath.Base(archive), Format: "workspace", Operation: "workspace-" + operation, Source: caseRef(before), Expect: expect})
	return w
}

func workspacePath(p string) string { return strings.TrimPrefix(p, "$MOUNT/Fixture/") }

func workspaceReplacements(t *testing.T, w *workspace.Workspace, stage schema.Stage) []workspace.DataReplacement {
	t.Helper()
	data := map[uint64][]byte{}
	for _, step := range stage.Steps {
		f := step.FS
		if f == nil || f.Op == "fullfsync" {
			continue
		}
		if f.Op != "write" && f.Op != "append" {
			t.Fatalf("unhandled replacement operation %s", f.Op)
		}
		id, err := filesystem.LookupExact(context.Background(), w, workspacePath(f.Path))
		if err != nil {
			t.Fatal(err)
		}
		value, err := stepBytes(f)
		if err != nil {
			t.Fatal(err)
		}
		if f.Op == "append" {
			data[id] = append(data[id], value...)
		} else {
			data[id] = value
		}
	}
	var ids []uint64
	for id := range data {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	var out []workspace.DataReplacement
	for _, id := range ids {
		out = append(out, workspace.DataReplacement{Object: id, Data: bytes.NewReader(data[id])})
	}
	return out
}

type workspaceProbe struct {
	change      workspace.Change
	success     bool
	nativeErrno string
}

func workspaceChanges(t *testing.T, w *workspace.Workspace, reference filesystem.Reader, stage schema.Stage, after corpus.Case) ([]workspace.Change, []workspaceProbe) {
	t.Helper()
	ctx := context.Background()
	known := map[string]bool{}
	var walk func(uint64, string)
	walk = func(id uint64, p string) {
		if err := w.ReadDir(ctx, id, func(e filesystem.DirEntry) error {
			q := path.Join(p, e.Name)
			known[q] = true
			n, err := w.Stat(ctx, e.Object)
			if err != nil {
				return err
			}
			if n.Metadata.Mode.Value&0170000 == 0040000 {
				walk(e.Object, q)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	walk(w.Root(), "")
	creation := func(p string, kind uint32) (*filesystem.Metadata, map[string]block.Source) {
		id, err := filesystem.Lookup(ctx, reference, "Fixture/"+p)
		if err != nil {
			id, err = filesystem.Lookup(ctx, reference, "Fixture")
			if err != nil {
				t.Fatal(err)
			}
		}
		n, err := reference.Stat(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		m := n.Metadata
		m.Mode = filesystem.Observed(kind | n.Metadata.Mode.Value&07777)
		m.BSDFlags = filesystem.Observed(uint32(0))
		attrs := map[string]block.Source{}
		if v, err := reference.OpenAttribute(ctx, id, "com.apple.provenance"); err == nil {
			data, err := readValue(v)
			if err != nil {
				t.Fatal(err)
			}
			attrs["com.apple.provenance"] = bytes.NewReader(data)
		}
		return &m, attrs
	}
	var changes []workspace.Change
	var probes []workspaceProbe
	for _, step := range stage.Steps {
		var c workspace.Change
		var expect string
		if f := step.FS; f != nil {
			if f.Op == "fullfsync" {
				continue
			}
			p := workspacePath(f.Path)
			c.Path = p
			expect = f.Expect
			data, err := stepBytes(f)
			if err != nil {
				t.Fatal(err)
			}
			switch f.Op {
			case "write":
				if strings.HasSuffix(p, "/..namedfork/rsrc") {
					c.Path = strings.TrimSuffix(p, "/..namedfork/rsrc")
					c.Op = workspace.ReplaceResourceFork
				} else if known[p] && f.Option != "create" {
					c.Op = workspace.ReplaceFileData
				} else {
					c.Op = workspace.CreateFile
					c.Metadata, c.Attributes = creation(p, 0100000)
				}
				c.Data = bytes.NewReader(data)
			case "symlink":
				c.Op, c.Target = workspace.CreateSymlink, f.Target
				c.Metadata, c.Attributes = creation(p, 0120000)
			case "unlink", "rmdir":
				c.Op = workspace.RemoveEntry
			case "rename":
				c.Op, c.To = workspace.RenameEntry, workspacePath(f.Target)
			case "link":
				c.Op, c.To = workspace.CreateHardLink, workspacePath(f.Target)
			case "chmod":
				reader := filesystem.Reader(w)
				id, err := filesystem.Lookup(ctx, reader, p)
				if err != nil {
					reader = reference
					id, err = filesystem.Lookup(ctx, reader, "Fixture/"+p)
				}
				if err != nil {
					t.Fatal(err)
				}
				n, err := reader.Stat(ctx, id)
				if err != nil {
					t.Fatal(err)
				}
				c.Op, c.Metadata = workspace.SetMetadata, &filesystem.Metadata{Mode: filesystem.Observed(n.Metadata.Mode.Value&0170000 | f.Mode)}
			case "chflags":
				c.Op, c.Metadata = workspace.SetMetadata, &filesystem.Metadata{BSDFlags: filesystem.Observed(f.Flags)}
			case "setxattr":
				c.Op, c.Attribute, c.AttributeMode, c.Data = workspace.SetAttribute, f.Name, workspace.AttributeMode(f.Option), bytes.NewReader(data)
			case "removexattr":
				c.Op, c.Attribute = workspace.RemoveAttribute, f.Name
			case "settimes":
				m := &filesystem.Metadata{}
				if f.Times.Birth != 0 {
					m.BirthTime = filesystem.Observed(time.Unix(0, f.Times.Birth))
				}
				if f.Times.Modify != 0 {
					m.ModifyTime = filesystem.Observed(time.Unix(0, f.Times.Modify))
				}
				if f.Times.Access != 0 {
					m.AccessTime = filesystem.Observed(time.Unix(0, f.Times.Access))
				}
				c.Op, c.Metadata = workspace.SetMetadata, m
			default:
				t.Fatalf("unhandled workspace fs operation %s", f.Op)
			}
			if f.Op == "unlink" && f.Expect == "record" {
				continue
			}
			// Name probes are independently applied to the completed stage. A
			// successful create is removed in the same batch; rejections publish
			// no workspace and cannot alter the completed source.
			if strings.Contains(step.Note, "name length probe") || expect != "" && expect != "0" {
				success, errno := nativeFSVerdict(t, after, *f)
				probes = append(probes, workspaceProbe{c, success, errno})
				continue
			}
		} else if tool := step.Tool; tool != nil {
			a := tool.Args
			switch tool.Program {
			case "mkdir":
				c.Op, c.Path = workspace.CreateDirectory, workspacePath(a[len(a)-1])
				c.Metadata, c.Attributes = creation(c.Path, 0040000)
			case "ln":
				c.Op, c.Path, c.To = workspace.CreateHardLink, workspacePath(a[0]), workspacePath(a[1])
			case "mv":
				c.Op, c.Path, c.To = workspace.RenameEntry, workspacePath(a[0]), workspacePath(a[1])
				// mv into an existing directory differs from rename(2)'s
				// replacement semantics exposed by the preservation API.
				if id, err := filesystem.Lookup(ctx, w, c.To); err == nil {
					n, err := w.Stat(ctx, id)
					if err != nil {
						t.Fatal(err)
					}
					if n.Metadata.Mode.Value&0170000 == 0040000 {
						c.To = path.Join(c.To, path.Base(c.Path))
					}
				}
			case "chown":
				c.Op, c.Path, c.Metadata = workspace.SetMetadata, workspacePath(a[len(a)-1]), &filesystem.Metadata{UID: filesystem.Observed(uint32(60001)), GID: filesystem.Observed(uint32(60002))}
			default:
				t.Fatalf("unhandled workspace tool %s", tool.Program)
			}
		} else {
			t.Fatal("unhandled workspace step")
		}
		changes = append(changes, c)
		switch c.Op {
		case workspace.CreateFile, workspace.CreateDirectory, workspace.CreateSymlink:
			known[c.Path] = true
		case workspace.RemoveEntry:
			delete(known, c.Path)
		}
	}
	return changes, probes
}

func nativeFSVerdict(t *testing.T, k corpus.Case, f schema.FSStep) (bool, string) {
	t.Helper()
	for i := len(k.Observation.Commands) - 1; i >= 0; i-- {
		c := k.Observation.Commands[i]
		if len(c.Argv) >= 2 && c.Argv[0] == "fs:"+f.Op && strings.HasSuffix(c.Argv[1], strings.TrimPrefix(f.Path, "$MOUNT")) && (f.Name == "" || len(c.Argv) > 2 && c.Argv[2] == f.Name) {
			return c.Status == "0", c.Errno
		}
	}
	t.Fatalf("native transcript lacks %s %s", f.Op, f.Path)
	return false, ""
}

func checkWorkspaceProbe(t *testing.T, w *workspace.Workspace, probe workspaceProbe) {
	t.Helper()
	ctx := context.Background()
	before := w.ManifestSHA256()
	destination := filepath.Join(t.TempDir(), "probe")
	changes := []workspace.Change{probe.change}
	if probe.success && probe.change.Op == workspace.CreateFile {
		changes = append(changes, workspace.Change{Op: workspace.RemoveEntry, Path: probe.change.Path})
	}
	_, err := w.Edit(ctx, changes, destination, workspace.Limits{})
	if probe.success {
		if err != nil {
			t.Fatal("native accepted workspace probe", probe.change.Path, err)
		}
	} else {
		if err == nil {
			t.Fatal("native rejection succeeded", probe.nativeErrno, probe.change.Path)
		}
		kind := map[string]error{"EEXIST": fs.ErrExist, "ENOENT": fs.ErrNotExist, "ENOATTR": fs.ErrNotExist, "ENOTEMPTY": filesystem.ErrConflict, "EINVAL": fs.ErrInvalid, "ENOTDIR": fs.ErrInvalid, "EISDIR": fs.ErrInvalid, "EPERM": fs.ErrInvalid, "ERANGE": fs.ErrInvalid, "ENAMETOOLONG": filesystem.ErrLimit}[probe.nativeErrno]
		if probe.change.Op == workspace.ReplaceResourceFork || probe.change.Op == workspace.SetAttribute && probe.nativeErrno == "ENAMETOOLONG" {
			kind = fs.ErrInvalid
		}
		if kind == nil || !errors.Is(err, kind) {
			t.Fatalf("native rejection %s: expected portable %v, got %v", probe.nativeErrno, kind, err)
		}
		if _, openErr := workspace.Open(ctx, destination); openErr == nil {
			t.Fatal("rejected edit published a completed workspace")
		}
		if errors.Is(err, fs.ErrClosed) || errors.Is(err, context.Canceled) {
			t.Fatal("probe failed for an unrelated reason", err)
		}
	}
	if w.ManifestSHA256() != before {
		t.Fatal("probe mutated the source workspace")
	}
}

func TestCorpusContainsEveryWorkspaceAndCommandStage(t *testing.T) {
	cases, _ := loadCorpus(t)
	indexed := indexCases(cases)
	for _, recipe := range recipesByName(t) {
		if recipe.Name != "workspace-edits" && recipe.Name != "file-command-journeys" && recipe.Name != "permission-inheritance" {
			continue
		}
		for _, producer := range schema.Producers {
			for _, profile := range recipe.Profiles {
				for _, stage := range recipe.Stages {
					key := stageKey(producer, recipe.Name, profile, stage.Name)
					k, ok := indexed[key]
					if !ok || k.Observation == nil || len(k.Observation.Views) != 1 {
						t.Errorf("missing native workspace/command state %s", key)
					}
				}
			}
		}
	}
}

func readValue(v filesystem.Value) ([]byte, error) {
	defer func() { _ = v.Close() }()
	return io.ReadAll(io.NewSectionReader(v, 0, v.Size()))
}
