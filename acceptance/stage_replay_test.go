package acceptance_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
	"github.com/deploymenttheory/go-apfs-v3/inspect"
)

// replayedRecipes are the recipes whose stages apply ordinary filesystem
// operations that the image editor also offers. Every stage after the
// first is replayed by Go from Apple's image of the stage it starts from,
// and the result must match the stage's own observation. The slow build
// tag adds the recipes that take minutes per stage (see
// stage_replay_slow_test.go).
var replayedRecipes = map[string]bool{
	"apfs-clones":                   true,
	"apfs-container-geometry":       true,
	"apfs-directory-statistics":     true,
	"hfs-attributes-initialization": true,
	"hfs-fragmented-metadata":       true,
}

// unreplayableStages lists stages no editor operation can produce, with
// the reason. A stage that cannot be translated and is not listed here
// fails the test; read parity still covers the listed stages.
var unreplayableStages = map[string]string{
	"apfs-directory-statistics/after-27-compressed": "native compression is created through com.apple.decmpfs and UF_COMPRESSED, which the editor refuses by design",
}

// knownProductLimits names, by recipe, the error a tracked product limit
// gives the native continuation's product edit on the final replayed
// state. Remove an entry when its issue is fixed: the native verifier then
// requires the edit to succeed.
var knownProductLimits = map[string]string{}

// largeReplaySourceBytes is the source disk size above which a replay runs
// alone: the editor streams the whole disk into scratch, twice per output.
// Sparse expansion keeps the 512 MiB catalog-growth replays cheap enough
// to run in parallel; the 1.5 GiB container geometry still runs alone.
const largeReplaySourceBytes = 1 << 30

// TestGoEditsReproduceAppleStageStates translates each recipe stage's steps
// into editor changes, applies them to Apple's image of the preceding
// stage, and reads the result back against the stage's observation. Each
// stage replays independently, so a divergence belongs to one stage.
func TestGoEditsReproduceAppleStageStates(t *testing.T) {
	cases, _ := loadCorpus(t)
	recipes := recipesByName(t)
	byKey := map[string]corpus.Case{}
	for _, k := range cases {
		byKey[stageKey(k.Producer, k.Recipe, k.Profile, k.Stage)] = k
	}
	for _, k := range cases {
		k := k
		if !replayedRecipes[k.Recipe] {
			continue
		}
		recipe := recipes[k.Recipe]
		index := -1
		for i := range recipe.Stages {
			if recipe.Stages[i].Name == k.Stage {
				index = i
			}
		}
		if index < 0 {
			t.Fatalf("%s: stage %s is not in the recipe", k.Recipe, k.Stage)
		}
		if index == 0 {
			continue // the first stage starts from a freshly formatted volume
		}
		stage := recipe.Stages[index]
		// The native tier continues writing to the final state of each
		// sequence, which carries every structure the earlier stages built.
		last := index == len(recipe.Stages)-1
		from := stage.From
		if from == "" {
			from = recipe.Stages[index-1].Name
		}
		source, ok := byKey[stageKey(k.Producer, k.Recipe, k.Profile, from)]
		if !ok {
			t.Fatalf("%s/%s: corpus has no %s stage to replay from", k.Recipe, k.Profile, from)
		}
		t.Run(fmt.Sprintf("macos-%d/%s/%s/%s", k.Producer, k.Recipe, k.Profile, k.Stage), func(t *testing.T) {
			if reason, listed := unreplayableStages[k.Recipe+"/"+k.Stage]; listed {
				t.Skip(reason)
			}
			if source.Observation.Image.DiskBytes <= largeReplaySourceBytes {
				t.Parallel()
			}
			groups, touched, err := replayGroups(stage, k.Profile)
			if err != nil {
				t.Fatalf("stage is not replayable: %v (if no editor operation can produce it, list it in unreplayableStages with the reason)", err)
			}
			if len(groups) == 0 {
				t.Fatalf("stage has no steps to replay")
			}
			ctx := context.Background()
			current := fixtureImage(t, source)
			name := outputName(k, "replay.UDZO.dmg")
			var final string
			for i, g := range groups {
				options := imageedit.Options{Format: "UDZO", Time: fixedClock}
				if g.volume != "" {
					options.Volume = volumeUUIDByName(t, source, g.volume)
				}
				last := i == len(groups)-1
				changes := g.changes
				produce := func(p string) error {
					// Edit batches large change lists without restaging the disk.
					_, err := imageedit.Edit(ctx, current, p, options, func(e *imageedit.Editor) error {
						_, err := e.Apply(changes)
						return err
					})
					return err
				}
				var out string
				if last {
					out = produceTwice(t, name, true, produce)
				} else {
					out = filepath.Join(outputDir(t), fmt.Sprintf("%s.part%d", name, i))
					if err := produce(out); err != nil {
						t.Fatalf("%s: %v", out, err)
					}
				}
				if i > 0 {
					_ = os.Remove(current)
				}
				current, final = out, out
			}
			checkReplayedImage(t, ctx, final, source, k, recipes[k.Recipe], touched)
			ignoreTimes := []string{"birth", "modify", "change", "access"}
			if k.Recipe == "apfs-clones" {
				ignoreTimes = nil // independent native command-clock projection
			}
			recordOutput(t, schema.Output{Name: name, File: filepath.Base(final), Operation: "edit", Format: "UDZO", Source: caseRef(source), Expect: schema.Expectation{View: k.Stage, IgnoreTimes: ignoreTimes, Continuation: last, NewIdentities: true, ContinuationRefusal: refusalIf(last, knownProductLimits[k.Recipe])}})
		})
	}
}

func refusalIf(last bool, refusal string) string {
	if !last {
		return ""
	}
	return refusal
}

func stageKey(producer int, recipe, profile, stage string) string {
	return fmt.Sprintf("%d/%s/%s/%s", producer, recipe, profile, stage)
}

// replayGroup is a run of consecutive changes addressed to one volume.
type replayGroup struct {
	volume  string
	changes []imageedit.Change
}

var mountPath = regexp.MustCompile(`^\$MOUNT(?::([^/]+))?(/.*)?$`)

// splitMountPath turns a recipe path into the volume it names (empty for
// the only volume) and the path inside it.
func splitMountPath(p string) (volume, inner string, err error) {
	m := mountPath.FindStringSubmatch(p)
	if m == nil {
		return "", "", fmt.Errorf("path %q is not under $MOUNT", p)
	}
	inner = m[2]
	if inner == "" {
		inner = "/"
	}
	return m[1], path.Clean(inner), nil
}

// replayGroups translates a stage's steps into editor changes grouped by
// volume, in order, and reports the paths whose timestamps the stage
// changed so they are not compared against Apple's wall clock.
func replayGroups(stage schema.Stage, profile string) ([]replayGroup, *touchedPaths, error) {
	var groups []replayGroup
	touched := &touchedPaths{paths: map[string]bool{}, pinnedModify: map[string]bool{}}
	add := func(volume string, c imageedit.Change) {
		if n := len(groups); n > 0 && groups[n-1].volume == volume {
			groups[n-1].changes = append(groups[n-1].changes, c)
			return
		}
		groups = append(groups, replayGroup{volume: volume, changes: []imageedit.Change{c}})
	}
	for i, step := range stage.Steps {
		if len(step.Only) > 0 && !containsString(step.Only, profile) {
			continue
		}
		switch {
		case step.FS != nil:
			volume, changes, err := translateFSStep(step.FS, touched)
			if err != nil {
				return nil, nil, fmt.Errorf("step %d (%s %s): %w", i+1, step.FS.Op, step.FS.Path, err)
			}
			for _, c := range changes {
				add(volume, c)
			}
		case step.Tool != nil:
			volume, c, err := translateToolStep(step.Tool, touched)
			if err != nil {
				return nil, nil, fmt.Errorf("step %d (%s): %w", i+1, step.Tool.Program, err)
			}
			add(volume, c)
		case step.Control != nil:
			return nil, nil, fmt.Errorf("step %d: control %s is not an editor operation", i+1, step.Control.Action)
		case step.Host != nil:
			// Host staging only produces bytes a later tool step moves.
		}
	}
	return groups, touched, nil
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// touchedPaths records which observed paths a stage changed. Their
// timestamps come from the kernel's clock on the Mac and the editor's
// fixed clock here, so only the modification times a recipe pinned with
// settimes are compared for them.
type touchedPaths struct {
	paths        map[string]bool
	pinnedModify map[string]bool
}

func (tp *touchedPaths) touch(inner string) {
	rel := strings.TrimPrefix(inner, "/")
	tp.paths[rel] = true
	if parent := path.Dir(rel); parent != "." && parent != "/" {
		tp.paths[parent] = true
	}
}

// expandAliases adds every path sharing an inode with a touched path: the
// kernel stamps the shared inode's change time, so all aliases carry it.
func (tp *touchedPaths) expandAliases(before, after []schema.Entry) {
	ids := map[uint64]bool{}
	for _, list := range [][]schema.Entry{before, after} {
		for _, e := range list {
			if tp.paths[e.Path] && e.Links > 1 {
				ids[e.ID] = true
			}
		}
	}
	for _, e := range after {
		if ids[e.ID] {
			tp.paths[e.Path] = true
		}
	}
}

func (tp *touchedPaths) ignoreTimes(rel string) map[string]bool {
	if !tp.paths[rel] {
		return nil
	}
	ignore := map[string]bool{"birth": true, "change": true, "access": true}
	if !tp.pinnedModify[rel] {
		ignore["modify"] = true
	}
	return ignore
}

const userFlagBits = 0x800f // nodump, uimmutable, uappend, opaque, hidden

func translateFSStep(f *schema.FSStep, touched *touchedPaths) (string, []imageedit.Change, error) {
	if f.Expect != "" && f.Expect != "0" {
		return "", nil, fmt.Errorf("a step whose failure is the observation is not replayed")
	}
	volume, inner, err := splitMountPath(f.Path)
	if err != nil {
		return "", nil, err
	}
	resource := false
	if strings.HasSuffix(inner, "/..namedfork/rsrc") {
		resource = true
		inner = strings.TrimSuffix(inner, "/..namedfork/rsrc")
	}
	data, err := stepBytes(f)
	if err != nil {
		return "", nil, err
	}
	var changes []imageedit.Change
	switch f.Op {
	case "write":
		touched.touch(inner)
		changes = append(changes, imageedit.Change{Operation: "cp", Path: inner, Data: bytes.NewReader(data), ResourceFork: resource, NoClobber: f.Option == "create"})
	case "truncate":
		if f.Bytes != 0 {
			return "", nil, fmt.Errorf("truncate to %d bytes has no editor operation", f.Bytes)
		}
		touched.touch(inner)
		changes = append(changes, imageedit.Change{Operation: "cp", Path: inner, Data: bytes.NewReader(nil), ResourceFork: resource})
	case "mkdir":
		touched.touch(inner)
		c := imageedit.Change{Operation: "mkdir", Path: inner}
		if f.Mode != 0 {
			c.Mode = strconv.FormatUint(uint64(f.Mode), 8)
		}
		changes = append(changes, c)
	case "symlink":
		touched.touch(inner)
		changes = append(changes, imageedit.Change{Operation: "ln", Symbolic: true, Path: f.Target, Destination: inner})
	case "link":
		_, target, err := splitMountPath(f.Target)
		if err != nil {
			return "", nil, err
		}
		touched.touch(inner)
		touched.touch(target)
		changes = append(changes, imageedit.Change{Operation: "ln", Path: inner, Destination: target})
	case "rename":
		targetVolume, target, err := splitMountPath(f.Target)
		if err != nil {
			return "", nil, err
		}
		if targetVolume != volume {
			return "", nil, fmt.Errorf("rename across volumes has no editor operation")
		}
		touched.touch(inner)
		touched.touch(target)
		changes = append(changes, imageedit.Change{Operation: "mv", Path: inner, Destination: target})
	case "unlink":
		touched.touch(inner)
		changes = append(changes, imageedit.Change{Operation: "rm", Path: inner})
	case "rmdir":
		// The editor removes directories only recursively; a recipe's rmdir
		// of a populated directory fails natively and is recorded as such.
		touched.touch(inner)
		changes = append(changes, imageedit.Change{Operation: "rm", Path: inner, Recursive: true})
	case "chmod":
		touched.touch(inner)
		changes = append(changes, imageedit.Change{Operation: "chmod", Path: inner, Mode: strconv.FormatUint(uint64(f.Mode), 8)})
	case "chflags":
		if f.Flags&^uint32(userFlagBits) != 0 {
			return "", nil, fmt.Errorf("flags %#x are outside the user flags the editor sets", f.Flags)
		}
		touched.touch(inner)
		changes = append(changes, imageedit.Change{Operation: "chflags", Path: inner, Flags: strconv.FormatUint(uint64(f.Flags), 8)})
	case "setxattr":
		if f.Name == "com.apple.decmpfs" || f.Name == "com.apple.ResourceFork" {
			return "", nil, fmt.Errorf("attribute %s is not an ordinary attribute edit", f.Name)
		}
		touched.touch(inner)
		changes = append(changes, imageedit.Change{Operation: "xattr", Path: inner, Attribute: f.Name, Data: bytes.NewReader(data), AttributeMode: f.Option})
	case "removexattr":
		touched.touch(inner)
		changes = append(changes, imageedit.Change{Operation: "xattr", Path: inner, Attribute: f.Name, DeleteAttribute: true})
	case "settimes":
		if f.Times == nil || f.Times.Birth != 0 {
			return "", nil, fmt.Errorf("settimes replays modification and access times only")
		}
		touched.touch(inner)
		rel := strings.TrimPrefix(inner, "/")
		c := imageedit.Change{Operation: "touch", Path: inner, Metadata: &filesystem.Metadata{}}
		if f.Times.Modify != 0 {
			c.Metadata.ModifyTime = filesystem.Observed(time.Unix(0, f.Times.Modify).UTC())
			c.Modify = true
			touched.pinnedModify[rel] = true
		}
		if f.Times.Access != 0 {
			c.Metadata.AccessTime = filesystem.Observed(time.Unix(0, f.Times.Access).UTC())
			c.Access = true
		}
		changes = append(changes, c)
	case "fill":
		if f.Count <= 0 {
			return "", nil, fmt.Errorf("fill without a count runs until the volume is full")
		}
		touched.touch(inner)
		for i := 0; i < f.Count; i++ {
			name := fmt.Sprintf("%05d%s", int(f.Offset)+i, f.Label)
			touched.touch(path.Join(inner, name))
			changes = append(changes, imageedit.Change{Operation: "cp", Path: path.Join(inner, name), Data: bytes.NewReader(data), NoClobber: true})
		}
	default:
		return "", nil, fmt.Errorf("fs op %s has no editor operation", f.Op)
	}
	return volume, changes, nil
}

func translateToolStep(ts *schema.ToolStep, touched *touchedPaths) (string, imageedit.Change, error) {
	if ts.Expect != "0" {
		return "", imageedit.Change{}, fmt.Errorf("a tool whose failure is the observation is not replayed")
	}
	if ts.Program != "ln" {
		return "", imageedit.Change{}, fmt.Errorf("%s is not an editor operation", ts.Program)
	}
	args := ts.Args
	symbolic := false
	if len(args) > 0 && args[0] == "-s" {
		symbolic, args = true, args[1:]
	}
	if len(args) != 2 {
		return "", imageedit.Change{}, fmt.Errorf("ln with %d operands", len(args))
	}
	volume, link, err := splitMountPath(args[1])
	if err != nil {
		return "", imageedit.Change{}, err
	}
	touched.touch(link)
	if symbolic {
		return volume, imageedit.Change{Operation: "ln", Symbolic: true, Path: args[0], Destination: link}, nil
	}
	sourceVolume, source, err := splitMountPath(args[0])
	if err != nil {
		return "", imageedit.Change{}, err
	}
	if sourceVolume != volume {
		return "", imageedit.Change{}, fmt.Errorf("ln across volumes")
	}
	touched.touch(source)
	return volume, imageedit.Change{Operation: "ln", Path: source, Destination: link}, nil
}

// stepBytes mirrors the capture tool's byte generation for a step.
func stepBytes(f *schema.FSStep) ([]byte, error) {
	switch {
	case f.Payload != "":
		return os.ReadFile(filepath.Join("recipes", "payloads", f.Payload))
	case f.Pattern != "":
		return generatePattern(f.Pattern, f.Label, f.Bytes), nil
	case f.Repeat > 0:
		return []byte(strings.Repeat(f.Content, f.Repeat)), nil
	default:
		return []byte(f.Content), nil
	}
}

func generatePattern(pattern, label string, n int64) []byte {
	if n <= 0 {
		return []byte{}
	}
	var cycle []byte
	switch pattern {
	case "zeros":
		return make([]byte, n)
	case "reverse":
		for i := 255; i >= 0; i-- {
			cycle = append(cycle, byte(i))
		}
	default:
		for i := 0; i < 256; i++ {
			cycle = append(cycle, byte(i))
		}
		if label != "" {
			cycle = append(append(cycle, label...), '\n')
		}
	}
	out := make([]byte, 0, n)
	for int64(len(out)) < n {
		out = append(out, cycle...)
	}
	return out[:n]
}

// volumeUUIDByName finds an observed APFS volume's UUID for editor volume
// selection in a multi-volume image.
func volumeUUIDByName(t *testing.T, k corpus.Case, name string) string {
	t.Helper()
	for _, vol := range k.Observation.Volumes {
		if volumeName(vol) == name {
			if vol.APFS == nil {
				t.Fatalf("volume %s is not APFS; the recipe addressed it by name", name)
			}
			return vol.APFS.VolumeUUID
		}
	}
	t.Fatalf("observation has no volume named %s", name)
	return ""
}

func volumeName(vol schema.Volume) string {
	name, _ := vol.Diskutil["VolumeName"].(string)
	return name
}

// checkReplayedImage reads the editor's output back against the target
// stage: every volume's live view, with timestamps compared except on
// the paths the stage changed, and directory statistics where recorded.
func checkReplayedImage(t *testing.T, ctx context.Context, output string, source, target corpus.Case, recipe schema.Recipe, touched *touchedPaths) {
	t.Helper()
	img, err := diskimage.Open(output)
	if err != nil {
		t.Fatalf("%s: %v", output, err)
	}
	defer func() { closeFixture(t, img) }()
	report, err := inspect.Image(ctx, img)
	if err != nil {
		t.Fatalf("%s: inspect: %v", output, err)
	}
	label := filepath.Base(output)
	for _, vol := range target.Observation.Volumes {
		name := volumeName(vol)
		reader, closer := openVolume(t, ctx, report, vol, name, recipe, img)
		if closer != nil {
			defer closer()
		}
		for _, view := range target.Observation.Views {
			if view.Volume != vol.Index || view.Snapshot != "" {
				continue
			}
			var before schema.View
			for _, sv := range source.Observation.Views {
				if sv.Volume == vol.Index && sv.Snapshot == "" {
					before = sv
				}
			}
			touched.expandAliases(before.Entries, view.Entries)
			// Identities of entries the stage created are the allocator's:
			// Apple's HFS kernel consumes a catalog node ID each time the
			// catalog B-tree grows mid-insert, so a bulk create leaves gaps
			// the editor's contiguous allocation does not. Every entry that
			// existed before the stage must keep its identity.
			existed := map[string]bool{}
			for _, e := range before.Entries {
				existed[e.Path] = true
			}
			created := func(path string) bool { return !existed[path] }
			compareViewWith(t, ctx, label+":"+name, reader, view, compareOptions{ignoreTimesFor: touched.ignoreTimes, ignoreIDFor: created})
			if len(view.Statistics) > 0 {
				compareStatistics(t, ctx, label+":"+name, reader, view.Statistics, before.Statistics)
			}
		}
	}
}

// directoryStatistics is what apfs.util -S prints for a tracked directory.
type directoryStatistics struct {
	descendants, physicalSize, generation uint64
}

func parseStatistics(text string) (directoryStatistics, error) {
	var s directoryStatistics
	seen := 0
	for _, line := range strings.Split(text, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		switch strings.TrimSpace(key) {
		case "descendants":
			s.descendants, seen = n, seen+1
		case "physical size":
			s.physicalSize, seen = n, seen+1
		case "gen-count":
			s.generation, seen = n, seen+1
		default:
			continue
		}
		if err != nil {
			return s, fmt.Errorf("statistics line %q: %w", line, err)
		}
	}
	if seen != 3 {
		return s, fmt.Errorf("statistics text lacks descendants, physical size or gen-count: %q", text)
	}
	return s, nil
}

// compareStatistics requires the product's directory statistics to match
// apfs.util -S: descendants and physical size exactly, and the generation
// exactly when before is nil (reading Apple's own image) or, after an
// edit, changed exactly when Apple's changed (generation strides differ
// between kernels, see docs/apfs-editing.md).
func compareStatistics(t *testing.T, ctx context.Context, label string, r filesystem.Reader, want, before map[string]string) {
	t.Helper()
	volume, ok := r.(*apfs.Volume)
	if !ok {
		t.Errorf("%s: directory statistics recorded on a non-APFS volume", label)
		return
	}
	for dir, text := range want {
		id, err := filesystem.Lookup(ctx, r, dir)
		if text == "absent" {
			// The observer records absent for a listed directory that no
			// longer exists at this stage.
			if !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("%s: %s: native absent, product lookup %d, %v", label, dir, id, err)
			}
			continue
		}
		expected, err2 := parseStatistics(text)
		if err2 != nil {
			t.Errorf("%s: %s: %v", label, dir, err2)
			continue
		}
		if err != nil {
			t.Errorf("%s: %s: lookup: %v", label, dir, err)
			continue
		}
		got, err := volume.DirectoryStatistics(ctx, id)
		if err != nil {
			t.Errorf("%s: %s: statistics: %v", label, dir, err)
			continue
		}
		if got.NumChildren != expected.descendants {
			t.Errorf("%s: %s: descendants %d, native %d", label, dir, got.NumChildren, expected.descendants)
		}
		if got.TotalSize != expected.physicalSize {
			t.Errorf("%s: %s: physical size %d, native %d", label, dir, got.TotalSize, expected.physicalSize)
		}
		if before == nil {
			if got.GenCount != expected.generation {
				t.Errorf("%s: %s: gen-count %d, native %d", label, dir, got.GenCount, expected.generation)
			}
			continue
		}
		prior, err := parseStatistics(before[dir])
		if err != nil || before[dir] == "absent" {
			// The directory did not exist or was untracked before the stage;
			// only the exact counts above apply.
			continue
		}
		if (got.GenCount != prior.generation) != (expected.generation != prior.generation) {
			t.Errorf("%s: %s: gen-count %d from %d, native %d from %d (must change exactly when Apple's did)", label, dir, got.GenCount, prior.generation, expected.generation, prior.generation)
		}
	}
}
