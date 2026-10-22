package native

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

var cloneEditStages = []string{"shared", "data-replaced", "data-truncated", "fork-replaced", "attribute-replaced", "metadata-changed", "compressed-replaced", "sparse-replaced", "source-removed", "clones-removed", "final-owner-removed", "allocation-reused"}

const retainedPartialClone = "native-clone-continuation/partial"

// cloneExtentPaths selects the ordinary dense controls supported by Apple's
// F_LOG2PHYS_EXT. The default observer still records every compressed and sparse
// file's content, forks, attributes, compression and holes. Keep this collection
// scope identical to every apfs-clones recipe stage.
func cloneExtentPaths() []string {
	return []string{
		"Fixture/attribute", "Fixture/edit", "Fixture/edit-alias",
		"Fixture/equal-independent", "Fixture/final-owner", "Fixture/fork",
		"Fixture/metadata", "Fixture/metadata-alias", "Fixture/remove",
		"Fixture/reused", "Fixture/source", "Fixture/truncate",
		"Fixture/untouched-clone", "Fixture/untouched-source",
	}
}

// requireCloneOutputs is a closed capability matrix, independent of which
// outputs a producer happened to supply. Every Apple transition must be edited.
func requireCloneOutputs(pairs []Paired, cases map[string]corpus.Case, major int) error {
	qualified := func(profile, stage string) bool {
		if profile != "apfs" && profile != "apfsx" {
			return false
		}
		for _, expected := range cloneEditStages {
			if expected == stage {
				return true
			}
		}
		return false
	}
	for _, k := range cases {
		if k.Producer == major && k.Recipe == "apfs-clones" && !qualified(k.Profile, k.Stage) {
			return fmt.Errorf("unqualified clone control %s/%s", k.Profile, k.Stage)
		}
	}
	for _, p := range pairs {
		o := p.Output
		if o.Source.Producer == major && o.Source.Recipe == "apfs-clones" && o.Operation == "edit" && (!qualified(o.Source.Profile, o.Expect.View) || o.Expect.View == "shared") {
			return fmt.Errorf("unqualified clone output %s", o.Name)
		}
	}
	for _, profile := range []string{"apfs", "apfsx"} {
		for i, stage := range cloneEditStages {
			ref := schema.CaseRef{Producer: major, Recipe: "apfs-clones", Profile: profile, Stage: stage}
			if _, ok := cases[CaseKey(ref)]; !ok {
				return fmt.Errorf("missing native clone control %s", CaseKey(ref))
			}
			if i == 0 {
				continue
			}
			var matched []schema.Output
			for _, p := range pairs {
				o := p.Output
				if o.Source.Producer == major && o.Source.Recipe == ref.Recipe && o.Source.Profile == profile && o.Operation == "edit" && o.Expect.View == stage {
					matched = append(matched, o)
				}
			}
			if len(matched) != 1 {
				return fmt.Errorf("clone transition %s has %d outputs, require one", CaseKey(ref), len(matched))
			}
			o := matched[0]
			if o.Source.Stage != cloneEditStages[i-1] || o.Format != "UDZO" || o.Encrypted || o.Expect.Continuation != (i == len(cloneEditStages)-1) || o.Expect.ContinuationRefusal != "" || !o.Expect.NewIdentities || len(o.Expect.IgnoreTimes) != 0 {
				return fmt.Errorf("wrong clone edit/continuation contract for %s", CaseKey(ref))
			}
		}
	}
	return nil
}

func clonePhysicalForks(view schema.View) (map[string][][3]int64, error) {
	forks := map[string][][3]int64{}
	seen := map[string]bool{}
	ids := map[string]uint64{}
	for _, entry := range view.Entries {
		if seen[entry.Path] {
			return nil, fmt.Errorf("duplicate clone observation path %s", entry.Path)
		}
		seen[entry.Path] = true
		ids[entry.Path] = entry.ID
		if entry.Kind != "file" || entry.Path != retainedPartialClone && (!strings.HasPrefix(entry.Path, "Fixture/") || strings.HasPrefix(entry.Path, "Fixture/compressed-") || strings.HasPrefix(entry.Path, "Fixture/sparse-")) {
			continue
		}
		if entry.Extents == nil {
			return nil, fmt.Errorf("clone control %s lacks physical measurements", entry.Path)
		}
		if err := validatePhysicalRuns(entry.Extents.Data, entry.Size); err != nil {
			return nil, fmt.Errorf("%s data: %w", entry.Path, err)
		}
		var resource int64
		for _, attr := range entry.Xattrs {
			if attr.Name == "com.apple.ResourceFork" {
				resource = attr.Bytes
			}
		}
		if err := validatePhysicalRuns(entry.Extents.Resource, resource); err != nil {
			return nil, fmt.Errorf("%s resource: %w", entry.Path, err)
		}
		forks[entry.Path+"/data"] = entry.Extents.Data
		forks[entry.Path+"/resource"] = entry.Extents.Resource
	}
	if ids["Fixture/untouched-source"] == 0 || ids["Fixture/untouched-source"] == ids["Fixture/untouched-clone"] {
		return nil, fmt.Errorf("native untouched controls do not distinguish clones from hard links")
	}
	for _, fork := range []string{"data", "resource"} {
		a, aok := forks["Fixture/untouched-source/"+fork]
		b, bok := forks["Fixture/untouched-clone/"+fork]
		if !aok || !bok || physicalBytes(a) == 0 || physicalBytes(a) != physicalBytes(b) || sharedPhysicalBytes(a, b) != physicalBytes(a) {
			return nil, fmt.Errorf("untouched clone lacks complete native %s sharing", fork)
		}
	}
	return forks, nil
}

// requireRetainedPartialClone proves that the subsequent Go admission sees an
// independently identified native clone with both private and shared physical
// ranges in its data and resource streams.
func requireRetainedPartialClone(view schema.View) error {
	forks, err := clonePhysicalForks(view)
	if err != nil {
		return err
	}
	var source, partial schema.Entry
	for _, entry := range view.Entries {
		if entry.Path == "Fixture/untouched-source" {
			source = entry
		}
		if entry.Path == retainedPartialClone {
			partial = entry
		}
	}
	if partial.ID == 0 || partial.ID == source.ID || partial.Links != 1 || partial.Size != source.Size {
		return fmt.Errorf("retained partial clone lacks independent native identity/size")
	}
	for _, fork := range []string{"data", "resource"} {
		a, b := forks[retainedPartialClone+"/"+fork], forks["Fixture/untouched-source/"+fork]
		shared := sharedPhysicalBytes(a, b)
		if physicalBytes(a) != physicalBytes(b) || shared <= 0 || shared >= physicalBytes(b) {
			return fmt.Errorf("retained partial clone lacks private and shared native %s ranges", fork)
		}
	}
	return nil
}

// CheckCloneEditingControl requires genuine native sharing in the plaintext
// editing family. It does not infer sharing from equal logical contents.
func CheckCloneEditingControl(view schema.View, stage string) error {
	forks, err := clonePhysicalForks(view)
	if err != nil {
		return err
	}
	qualified := false
	for _, name := range cloneEditStages {
		qualified = qualified || name == stage
	}
	if !qualified {
		return fmt.Errorf("unqualified clone editing stage %s", stage)
	}
	entries := map[string]schema.Entry{}
	for _, entry := range view.Entries {
		entries[entry.Path] = entry
	}
	for _, pair := range [][2]string{{"edit", "edit-alias"}, {"metadata", "metadata-alias"}} {
		a, aok := entries["Fixture/"+pair[0]]
		b, bok := entries["Fixture/"+pair[1]]
		if aok != bok || aok && (a.ID != b.ID || a.Links != 2 || b.Links != 2) {
			return fmt.Errorf("native clone hard-link control differs for %v", pair)
		}
	}
	if stage == "shared" {
		source, ordinary := entries["Fixture/source"], entries["Fixture/equal-independent"]
		if source.ID == 0 || ordinary.ID == source.ID || ordinary.SHA256 != source.SHA256 || sharedPhysicalBytes(forks["Fixture/source/data"], forks["Fixture/equal-independent/data"]) != 0 {
			return fmt.Errorf("native equal independent copy does not distinguish bytes from sharing")
		}
		for _, name := range []string{"edit", "truncate", "fork", "attribute", "metadata", "remove", "final-owner"} {
			clone := entries["Fixture/"+name]
			if clone.ID == 0 || clone.ID == source.ID {
				return fmt.Errorf("native clone %s lacks independent identity", name)
			}
			for _, fork := range []string{"data", "resource"} {
				a, b := forks["Fixture/source/"+fork], forks["Fixture/"+name+"/"+fork]
				if physicalBytes(a) == 0 || sharedPhysicalBytes(a, b) != physicalBytes(a) {
					return fmt.Errorf("native clone %s lacks full shared %s", name, fork)
				}
			}
		}
	}
	return nil
}

// cloneOutputDifferences compares relations measured by Apple's kernel on the
// Go output and retained Apple after-state. Equal file bytes are not evidence
// of sharing, and independently allocated output addresses need not coincide.
func cloneOutputDifferences(observed *schema.Observation, want schema.View) ([]Difference, error) {
	if observed == nil || len(observed.Views) != 1 || observed.Views[0].Snapshot != "" {
		return nil, fmt.Errorf("clone output requires one live native view")
	}
	expected, err := clonePhysicalForks(want)
	if err != nil {
		return nil, fmt.Errorf("retained native clone evidence: %w", err)
	}
	actual, err := clonePhysicalForks(observed.Views[0])
	if err != nil {
		return nil, fmt.Errorf("native output clone evidence: %w", err)
	}
	var names []string
	for name := range expected {
		if _, ok := actual[name]; !ok {
			return nil, fmt.Errorf("native clone output lacks fork %s", name)
		}
		names = append(names, name)
	}
	if len(expected) != len(actual) {
		return nil, fmt.Errorf("native clone output has unexpected physical fork inventory")
	}
	sort.Strings(names)
	var differences []Difference
	for i, a := range names {
		for _, b := range names[i+1:] {
			want, got := sharedPhysicalBytes(expected[a], expected[b]), sharedPhysicalBytes(actual[a], actual[b])
			if got != want {
				differences = append(differences, Difference{Path: a + " <> " + b, Field: "sharedPhysicalBytes", Got: fmt.Sprint(got), Want: fmt.Sprint(want)})
			}
		}
	}
	return differences, nil
}

type nativeCloneState struct {
	Stat     fixture.Stat
	Data     string
	Attrs    map[string][]byte
	DataRuns [][3]int64
	ForkRuns [][3]int64
}

func (v *Verifier) cloneNativeState(path string) (nativeCloneState, error) {
	var s nativeCloneState
	var err error
	if s.Stat, err = v.Vol.Lstat(path); err != nil {
		return s, err
	}
	if s.Data, _, err = v.Vol.Hash(path); err != nil {
		return s, err
	}
	s.Attrs = map[string][]byte{}
	names, err := v.Vol.Listxattr(path, true)
	if err != nil {
		return s, err
	}
	for _, name := range names {
		if s.Attrs[name], err = v.Vol.Getxattr(path, name, true); err != nil {
			return s, err
		}
	}
	if s.DataRuns, err = v.Vol.Extents(path, "data"); err != nil {
		return s, err
	}
	if s.ForkRuns, err = v.Vol.Extents(path, "rsrc"); err != nil {
		return s, err
	}
	return s, nil
}

// continueCloneWrites requires Apple's clone syscall and physical COW on an
// existing Go-edited image. The normal continuation's unmount/fsck/full-view
// Go edit and later native allocation remain mandatory after this procedure.
func (v *Verifier) continueCloneWrites(ctx context.Context, mount, stage string) (resultErr error) {
	return v.continueCloneWritesFrom(ctx, mount, stage, "Fixture/untouched-source", "Fixture/untouched-clone")
}

func (v *Verifier) continueCloneWritesFrom(ctx context.Context, mount, stage, sourcePath, siblingPath string) (resultErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(stage, 0o755); err != nil {
		return err
	}
	transcript := &fixture.Transcript{}
	states := map[string]nativeCloneState{}
	defer func() {
		b, err := json.MarshalIndent(struct {
			Commands []schema.Command
			States   map[string]nativeCloneState
		}{transcript.Commands, states}, "", "  ")
		if err == nil {
			err = os.WriteFile(filepath.Join(stage, "clone-continuation.json"), b, 0o644)
		}
		resultErr = errors.Join(resultErr, err)
	}()
	run := func(op string, paths []string, action func() error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return transcript.RecordFS(op, paths, action(), "0")
	}
	source := filepath.Join(mount, sourcePath)
	sibling := filepath.Join(mount, siblingPath)
	root := filepath.Join(mount, "native-clone-continuation")
	if err := v.writableDirectory(ctx, root); err != nil {
		return err
	}
	first, second, alias := filepath.Join(root, "first"), filepath.Join(root, "second"), filepath.Join(root, "alias")
	initial, err := v.cloneNativeState(source)
	if err != nil {
		return err
	}
	peer, err := v.cloneNativeState(sibling)
	if err != nil || initial.Stat.Ino == peer.Stat.Ino || sharedPhysicalBytes(initial.DataRuns, peer.DataRuns) != initial.Stat.Size || sharedPhysicalBytes(initial.ForkRuns, peer.ForkRuns) != int64(len(initial.Attrs["com.apple.ResourceFork"])) {
		return errors.Join(fmt.Errorf("output lost its independent native untouched clone sharing"), err)
	}
	if err := run("clone", []string{source, first}, func() error { return v.Vol.Clone(source, first) }); err != nil {
		return err
	}
	attribute := bytes.Repeat([]byte("native shared attribute"), 400)
	if err := run("setxattr", []string{first, "org.go-apfs.clone-continuation"}, func() error { return v.Vol.Setxattr(first, "org.go-apfs.clone-continuation", attribute, "") }); err != nil {
		return err
	}
	if err := run("clone", []string{first, second}, func() error { return v.Vol.Clone(first, second) }); err != nil {
		return err
	}
	if err := run("link", []string{first, alias}, func() error { return v.Vol.Link(first, alias) }); err != nil {
		return err
	}
	for name, path := range map[string]string{"source": source, "sibling": sibling, "first": first, "second": second} {
		s, err := v.cloneNativeState(path)
		if err != nil {
			return err
		}
		states["before/"+name] = s
	}
	a, b := states["before/first"], states["before/second"]
	if a.Stat.Ino == b.Stat.Ino || a.Stat.Nlink != 2 || b.Stat.Nlink != 1 || a.Stat.Size == 0 || sharedPhysicalBytes(a.DataRuns, b.DataRuns) != a.Stat.Size || len(a.Attrs["com.apple.ResourceFork"]) == 0 || sharedPhysicalBytes(a.ForkRuns, b.ForkRuns) != int64(len(a.Attrs["com.apple.ResourceFork"])) {
		return fmt.Errorf("native clone/hard-link procedure did not establish physical sharing")
	}
	if a.Stat.Size > 1<<20 || a.Stat.Size < 8192 || len(a.Attrs["com.apple.ResourceFork"]) < 8192 {
		return fmt.Errorf("native clone continuation requires bounded block-crossing data/fork controls")
	}
	expectedData, err := v.Vol.Pread(first, 0, int(a.Stat.Size))
	if err != nil || int64(len(expectedData)) != a.Stat.Size {
		return errors.Join(fmt.Errorf("read native clone before partial writes"), err)
	}
	expectedFork := bytes.Clone(a.Attrs["com.apple.ResourceFork"])
	private := []byte("native private bytes")
	copy(expectedData[4095:], private)
	copy(expectedFork[4095:], private)
	for _, fork := range []string{"data", "resource"} {
		path := first
		if fork == "resource" {
			path = filepath.Join(first, "..namedfork", "rsrc")
		}
		if err := run("pwrite "+fork, []string{path, "4095"}, func() error { return v.Vol.Pwrite(path, 4095, private) }); err != nil {
			return err
		}
	}
	if err := run("setxattr", []string{first, "org.go-apfs.clone-continuation"}, func() error {
		return v.Vol.Setxattr(first, "org.go-apfs.clone-continuation", []byte("private attribute"), "replace")
	}); err != nil {
		return err
	}
	if err := run("chmod", []string{alias, "0600"}, func() error { return v.Vol.Lchmod(alias, 0o600) }); err != nil {
		return err
	}
	if err := run("fullfsync", []string{first}, func() error { return v.Vol.Fullfsync(first) }); err != nil {
		return err
	}
	changed, err := v.cloneNativeState(first)
	if err != nil {
		return err
	}
	states["changed/first"] = changed
	wantData := sha256.Sum256(expectedData)
	if changed.Data != hex.EncodeToString(wantData[:]) || !bytes.Equal(changed.Attrs["com.apple.ResourceFork"], expectedFork) {
		return fmt.Errorf("native partial clone data/fork readback differs from supplied writes")
	}
	for _, pair := range [][2][][3]int64{{changed.DataRuns, b.DataRuns}, {changed.ForkRuns, b.ForkRuns}} {
		shared := sharedPhysicalBytes(pair[0], pair[1])
		if shared <= 0 || shared >= physicalBytes(pair[1]) {
			return fmt.Errorf("native partial clone write did not preserve untouched sharing and privatize affected blocks")
		}
	}
	for name, path := range map[string]string{"source": source, "sibling": sibling, "second": second} {
		s, err := v.cloneNativeState(path)
		if err != nil || !reflect.DeepEqual(s, states["before/"+name]) {
			return errors.Join(fmt.Errorf("native private clone write changed %s", name), err)
		}
	}
	aliasState, err := v.cloneNativeState(alias)
	if err != nil || !reflect.DeepEqual(aliasState, changed) || changed.Stat.Mode != 0o600 || !bytes.Equal(changed.Attrs["org.go-apfs.clone-continuation"], []byte("private attribute")) {
		return errors.Join(fmt.Errorf("native hard-link alias did not retain private clone changes"), err)
	}
	for _, path := range []string{first, alias, second} {
		if err := run("unlink", []string{path}, func() error { return v.Vol.Remove(path) }); err != nil {
			return err
		}
		if path == first {
			survivor, err := v.cloneNativeState(alias)
			if err != nil || survivor.Stat.Nlink != 1 || survivor.Data != changed.Data || !reflect.DeepEqual(survivor.Attrs, changed.Attrs) {
				return errors.Join(fmt.Errorf("native nonfinal hard-link unlink retired private clone storage"), err)
			}
		}
		if path == alias {
			survivor, err := v.cloneNativeState(second)
			if err != nil || !reflect.DeepEqual(survivor, b) {
				return errors.Join(fmt.Errorf("native final private clone unlink changed its shared sibling"), err)
			}
		}
	}
	reused := filepath.Join(root, "after-retirement")
	payload := bytes.Repeat([]byte("native post-clone allocation"), 4096)
	if err := run("write", []string{reused}, func() error { return v.Vol.WriteFile(reused, payload, true) }); err != nil {
		return err
	}
	if err := run("fullfsync", []string{reused}, func() error { return v.Vol.Fullfsync(reused) }); err != nil {
		return err
	}
	digest, size, err := v.Vol.Hash(reused)
	want := sha256.Sum256(payload)
	if err != nil || size != int64(len(payload)) || digest != hex.EncodeToString(want[:]) {
		return errors.Join(fmt.Errorf("native post-clone allocation readback differs"), err)
	}
	// Keep a separate partial clone for the full unmount/fsck/Go-edit/native
	// readback sequence. The retirement checks above remain independent.
	retained := filepath.Join(mount, retainedPartialClone)
	if err := run("clone", []string{source, retained}, func() error { return v.Vol.Clone(source, retained) }); err != nil {
		return err
	}
	for _, fork := range []string{"data", "resource"} {
		path := retained
		if fork == "resource" {
			path = filepath.Join(retained, "..namedfork", "rsrc")
		}
		if err := run("pwrite "+fork, []string{path, "4095"}, func() error { return v.Vol.Pwrite(path, 4095, private) }); err != nil {
			return err
		}
	}
	if err := run("fullfsync", []string{retained}, func() error { return v.Vol.Fullfsync(retained) }); err != nil {
		return err
	}
	partial, err := v.cloneNativeState(retained)
	if err != nil {
		return err
	}
	states["retained/partial"] = partial
	if partial.Stat.Ino == 0 || partial.Stat.Ino == initial.Stat.Ino || partial.Stat.Nlink != 1 || partial.Stat.Size != initial.Stat.Size || partial.Data != hex.EncodeToString(wantData[:]) || !bytes.Equal(partial.Attrs["com.apple.ResourceFork"], expectedFork) {
		return fmt.Errorf("retained native partial clone identity/data/fork differs")
	}
	for _, pair := range [][2][][3]int64{{partial.DataRuns, initial.DataRuns}, {partial.ForkRuns, initial.ForkRuns}} {
		shared := sharedPhysicalBytes(pair[0], pair[1])
		if physicalBytes(pair[0]) != physicalBytes(pair[1]) || shared <= 0 || shared >= physicalBytes(pair[1]) {
			return fmt.Errorf("retained native partial clone lacks private and shared physical ranges")
		}
	}
	for name, path := range map[string]string{"source": source, "sibling": sibling} {
		s, err := v.cloneNativeState(path)
		if err != nil || !reflect.DeepEqual(s, states["before/"+name]) {
			return errors.Join(fmt.Errorf("native clone retirement/reuse changed %s", name), err)
		}
		states["after/"+name] = s
	}
	return nil
}
