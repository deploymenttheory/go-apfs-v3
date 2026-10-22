package apfs

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/session"
)

func TestAPFSCaptureRecognizesRealWholeStreamSharingAndPreservesItAcrossSessions(t *testing.T) {
	ctx := context.Background()
	r, _ := declaredCloneInput(t)
	plan, err := Plan(ctx, r, BuildOptions{Name: "Clones", Time: builtClock})
	if err != nil {
		t.Fatal(err)
	}
	var raw bytes.Buffer
	if err := plan.Write(ctx, &raw); err != nil {
		t.Fatal(err)
	}
	container := openBuilt(t, raw.Bytes())
	volume := &container.Volumes[0]
	groups, err := volume.CloneStreams(ctx, volume.Root())
	if err != nil {
		t.Fatal(err)
	}
	source, _ := filesystem.LookupExact(ctx, volume, "/source")
	clone, _ := filesystem.LookupExact(ctx, volume, "/clone")
	independent, _ := filesystem.LookupExact(ctx, volume, "/independent")
	if groups[source].Data == "" || !reflect.DeepEqual(groups[source], groups[clone]) || groups[independent].Data != "" || len(groups[source].Partial) != 0 {
		t.Fatal("physical identity, independent equality or hardlinks were confused", groups)
	}
	directory := filepath.Join(t.TempDir(), "captured")
	s, err := session.Capture(ctx, volume, directory, session.Options{Time: &builtClock})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = session.Open(ctx, directory)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	node, err := s.Stat(ctx, clone)
	if err != nil || node.CloneStreams == nil || !reflect.DeepEqual(*node.CloneStreams, groups[clone]) {
		t.Fatal("reopened native capture lost storage identity", node.CloneStreams, err)
	}
	rebuilt, err := Plan(ctx, s, BuildOptions{Name: "Rebuilt", Time: builtClock})
	if err != nil {
		t.Fatal(err)
	}
	var result bytes.Buffer
	if err := rebuilt.Write(ctx, &result); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMutation(ctx, bytes.NewReader(result.Bytes())); err != nil {
		t.Fatal(err)
	}
}

func TestCapturedPartialSharingIsDetectedByRangeOverlapRatherThanEqualBytes(t *testing.T) {
	for name, events := range map[string][]cloneExtentEvent{
		"overlap":       {{10, "first", true}, {20, "first", false}, {19, "second", true}, {30, "second", false}},
		"nested":        {{10, "first", true}, {30, "first", false}, {15, "second", true}, {20, "second", false}},
		"later segment": {{1, "first", true}, {5, "first", false}, {10, "first", true}, {20, "first", false}, {18, "second", true}, {25, "second", false}},
	} {
		t.Run(name, func(t *testing.T) {
			if got := partialCloneMaps(events); !got["first"] || !got["second"] || len(got) != 2 {
				t.Fatal("partial physical overlap was lost", got)
			}
		})
	}
	if got := partialCloneMaps([]cloneExtentEvent{{10, "first", true}, {20, "first", false}, {20, "second", true}, {30, "second", false}}); len(got) != 0 {
		t.Fatal("adjacent allocations became clones", got)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	volume := &openBuilt(t, builtContainer(t, nil)).Volumes[0]
	if _, err := volume.CloneStreams(cancelled, volume.Root()); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestAPFSCaptureMarksAccountedPartialForkAndFreshConstructionRefusesIt(t *testing.T) {
	ctx := context.Background()
	r, _ := declaredCloneInput(t)
	plan, err := Plan(ctx, r, BuildOptions{Name: "Clones", Time: builtClock})
	if err != nil {
		t.Fatal(err)
	}
	var raw bytes.Buffer
	if err := plan.Write(ctx, &raw); err != nil {
		t.Fatal(err)
	}
	disk := newCloneMutationDisk(raw.Bytes())
	if _, err := Modify(ctx, disk, []Change{{Path: "/clone", ResourceFork: true, Data: bytes.NewReader(bytes.Repeat([]byte("x"), len(cloneFork)))}}, builtClock); err != nil {
		t.Fatal(err)
	}
	// Declared synthetic partial-COW state: restore one cloned fork block to
	// its source allocation, retaining the private suffix and exact physical
	// reference counts. It does not call the inventory under test to construct
	// the fixture; complete storage admission independently checks the result.
	m, err := openMutation(ctx, disk)
	if err != nil {
		t.Fatal(err)
	}
	source, _ := m.lookupEntry("/source")
	clone, _ := m.lookupEntry("/clone")
	sourceAttr, _ := m.fs.get(buildXattr(source.id, filesystem.ResourceFork, nil, 0).key)
	cloneAttr, _ := m.fs.get(buildXattr(clone.id, filesystem.ResourceFork, nil, 0).key)
	sourceExtent := m.fs.records(le.Uint64(sourceAttr.value[4:]), 8)[0]
	cloneExtent := m.fs.records(le.Uint64(cloneAttr.value[4:]), 8)[0]
	shared, private := le.Uint64(sourceExtent.value[8:]), le.Uint64(cloneExtent.value[8:])
	length := le.Uint64(cloneExtent.value)
	if err := m.releaseExtent(private, 1); err != nil {
		t.Fatal(err)
	}
	first := bytes.Clone(cloneExtent.value)
	le.PutUint64(first, 4096)
	le.PutUint64(first[8:], shared)
	if err := m.fs.put(cloneExtent.key, first); err != nil {
		t.Fatal(err)
	}
	secondKey, second := bytes.Clone(cloneExtent.key), bytes.Clone(cloneExtent.value)
	le.PutUint64(secondKey[8:], 4096)
	le.PutUint64(second, length-4096)
	le.PutUint64(second[8:], private+1)
	if err := m.fs.put(secondKey, second); err != nil {
		t.Fatal(err)
	}
	physical, ok := m.extents.get(buildKey(shared, 2, 0))
	if !ok || le.Uint32(physical.value[16:]) != 1 {
		t.Fatal("synthetic source fork must be independently owned")
	}
	owner := le.Uint64(physical.value[8:])
	firstRef := buildExtentReference(shared, 1, owner)
	le.PutUint32(firstRef.value[16:], 2)
	if err := m.extents.put(firstRef.key, firstRef.value); err != nil {
		t.Fatal(err)
	}
	lastRef := buildExtentReference(shared+1, (length/4096)-1, owner)
	if err := m.extents.put(lastRef.key, lastRef.value); err != nil {
		t.Fatal(err)
	}
	if err := m.commit(uint64(builtClock.UnixNano())); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMutation(ctx, disk); err != nil {
		t.Fatal("partial fixture is not independently accounted", err)
	}
	container := openBuilt(t, disk.data)
	volume := &container.Volumes[0]
	groups, err := volume.CloneStreams(ctx, volume.Root())
	if err != nil || !reflect.DeepEqual(groups[source.id].Partial, []string{filesystem.ResourceFork}) || !reflect.DeepEqual(groups[clone.id].Partial, []string{filesystem.ResourceFork}) || groups[source.id].Data == "" {
		t.Fatal("partial fork was hidden or unrelated whole sharing lost", groups, err)
	}
	before := bytes.Clone(disk.data)
	if _, err := Plan(ctx, volume, BuildOptions{Name: "Refused", Time: builtClock}); !errors.Is(err, filesystem.ErrUnsupported) || !bytes.Equal(before, disk.data) {
		t.Fatal("partial native import was silently flattened or changed", err)
	}
}

func TestAPFSCaptureNeverTreatsDescriptorlessPrivateIDAsSharedData(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		container := openBuilt(t, descriptorlessCloneImage(t, compressed))
		volume := &container.Volumes[0]
		groups, err := volume.CloneStreams(context.Background(), volume.Root())
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{"/source", "/clone", "/unowned-hint"} {
			id, _ := filesystem.LookupExact(context.Background(), volume, path)
			if groups[id].Data != "" {
				t.Fatal("private-ID hint became owned clone data", compressed, path)
			}
		}
	}
}
