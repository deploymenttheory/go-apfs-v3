package apfs

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/session"
)

type declaredCloneReader struct {
	filesystem.Reader
	groups map[uint64]*filesystem.CloneStreams
}

func (r declaredCloneReader) Stat(ctx context.Context, id uint64) (filesystem.Node, error) {
	node, err := r.Reader.Stat(ctx, id)
	if clones := r.groups[id]; err == nil && clones != nil {
		node.CloneStreams = clones
	}
	return node, err
}

// The declared groups are supplied independently of the builder. Equal bytes
// in /independent deliberately have no clone declaration.
func declaredCloneInput(t *testing.T) (declaredCloneReader, *session.Session) {
	t.Helper()
	ctx := context.Background()
	s, err := session.Create(ctx, filepath.Join(t.TempDir(), "session"), session.Options{Names: filesystem.NameRules{Format: "APFS", NormalizationInsensitive: true}, Time: &builtClock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	host := filepath.Join(t.TempDir(), "data")
	if err := os.WriteFile(host, cloneData, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Copy(ctx, []string{host}, "/source", session.CopyOptions{FromHost: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReplaceResourceFork(ctx, "/source", bytes.NewReader(cloneFork)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetAttribute(ctx, []string{"/source"}, "org.go-apfs.large", bytes.NewReader(cloneAttribute), session.AttributeOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/clone", "/independent"} {
		if _, err := s.Copy(ctx, []string{"/source"}, path, session.CopyOptions{Preserve: true}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Link(ctx, "/clone", "/alias", session.LinkOptions{}); err != nil {
		t.Fatal(err)
	}
	r := declaredCloneReader{Reader: s, groups: map[uint64]*filesystem.CloneStreams{}}
	for _, path := range []string{"/source", "/clone"} {
		id, err := filesystem.LookupExact(ctx, s, path)
		if err != nil {
			t.Fatal(err)
		}
		r.groups[id] = &filesystem.CloneStreams{Data: "declared-data-lineage", Attributes: map[string]string{filesystem.ResourceFork: "declared-fork-lineage", "org.go-apfs.large": "declared-attribute-lineage"}}
	}
	return r, s
}

func TestAPFSBuildExplicitCloneStreamsHaveRealReferencesAndIndependentEdits(t *testing.T) {
	ctx := context.Background()
	r, _ := declaredCloneInput(t)
	plan, err := Plan(ctx, r, BuildOptions{Name: "Clones", Time: builtClock, Capacity: 8 << 20})
	if err != nil {
		t.Fatal(err)
	}
	var raw, repeated bytes.Buffer
	if err := plan.Write(ctx, &raw); err != nil {
		t.Fatal(err)
	}
	if err := plan.Write(ctx, &repeated); err != nil || !bytes.Equal(raw.Bytes(), repeated.Bytes()) {
		t.Fatal("plaintext construction is not deterministic", err)
	}
	disk := newCloneMutationDisk(raw.Bytes())
	m, err := openMutation(ctx, disk)
	if err != nil {
		t.Fatal(err)
	}
	source, _ := m.lookupEntry("/source")
	clone, _ := m.lookupEntry("/clone")
	alias, _ := m.lookupEntry("/alias")
	independent, _ := m.lookupEntry("/independent")
	sourceInode, _ := m.inodeRecord(source.id)
	cloneInode, _ := m.inodeRecord(clone.id)
	independentInode, _ := m.inodeRecord(independent.id)
	stream := le.Uint64(sourceInode.value[8:])
	if source.id == clone.id || alias.id != clone.id || le.Uint64(cloneInode.value[8:]) != stream || le.Uint64(independentInode.value[8:]) == stream {
		t.Fatal("clone, hard-link and independent file identities were conflated")
	}
	ref, exists := m.fs.get(buildKey(stream, 6, 0))
	if !exists || le.Uint32(ref.value) != 2 {
		t.Fatal("data references count aliases instead of distinct clone inodes")
	}
	for _, name := range []string{filesystem.ResourceFork, "org.go-apfs.large"} {
		left, _ := m.fs.get(buildXattr(source.id, name, nil, 0).key)
		right, _ := m.fs.get(buildXattr(clone.id, name, nil, 0).key)
		leftID, rightID := le.Uint64(left.value[4:]), le.Uint64(right.value[4:])
		leftExtents, rightExtents := m.fs.records(leftID, 8), m.fs.records(rightID, 8)
		if leftID == rightID || len(leftExtents) != 1 || len(rightExtents) != 1 || le.Uint64(leftExtents[0].value[8:]) != le.Uint64(rightExtents[0].value[8:]) {
			t.Fatal("attribute clone lacks distinct stream IDs with shared physical storage", name)
		}
		physical, ok := m.extents.get(buildKey(le.Uint64(leftExtents[0].value[8:]), 2, 0))
		if !ok || le.Uint32(physical.value[16:]) != 2 {
			t.Fatal("attribute physical reference count", name)
		}
	}
	for _, change := range []Change{
		{Path: "/clone", Data: bytes.NewReader([]byte("private data"))},
		{Path: "/clone", ResourceFork: true, Data: bytes.NewReader([]byte("private fork"))},
		{Operation: "xattr", Path: "/clone", Attribute: "org.go-apfs.large", Data: bytes.NewReader([]byte("private attribute"))},
		{Operation: "rm", Path: "/source"},
	} {
		if _, err := Modify(ctx, disk, []Change{change}, builtClock); err != nil {
			t.Fatal(change.Path, change.Operation, err)
		}
	}
	if err := ValidateMutation(ctx, disk); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectStorage(ctx, disk); err != nil {
		t.Fatal(err)
	}
	for path, expected := range map[string][]byte{"/clone": []byte("private data"), "/alias": []byte("private data"), "/independent": cloneData} {
		if !bytes.Equal(cloneContents(t, disk, path, ""), expected) {
			t.Fatal("fresh readback", path)
		}
	}
	if !bytes.Equal(cloneContents(t, disk, "/independent", filesystem.ResourceFork), cloneFork) || !bytes.Equal(cloneContents(t, disk, "/independent", "org.go-apfs.large"), cloneAttribute) {
		t.Fatal("independent equal file changed")
	}
}

func TestAPFSBuildRejectsFalseCloneDeclarationsAndPartialCaptureBeforeOutput(t *testing.T) {
	ctx := context.Background()
	for _, damage := range []string{"payload", "attribute", "missing", "partial"} {
		t.Run(damage, func(t *testing.T) {
			r, s := declaredCloneInput(t)
			id, _ := filesystem.LookupExact(ctx, s, "/clone")
			switch damage {
			case "payload":
				if _, err := s.ReplaceData(ctx, "/clone", bytes.NewReader(bytes.Repeat([]byte("x"), len(cloneData)))); err != nil {
					t.Fatal(err)
				}
			case "attribute":
				if _, err := s.SetAttribute(ctx, []string{"/clone"}, "org.go-apfs.large", bytes.NewReader(bytes.Repeat([]byte("x"), len(cloneAttribute))), session.AttributeOptions{}); err != nil {
					t.Fatal(err)
				}
			case "missing":
				r.groups[id].Attributes["absent"] = "invalid-lineage"
			case "partial":
				r.groups[id] = &filesystem.CloneStreams{Partial: []string{""}}
			}
			_, err := Plan(ctx, r, BuildOptions{Name: "Clones", Time: builtClock})
			want := filesystem.ErrCorrupt
			if damage == "partial" {
				want = filesystem.ErrUnsupported
			}
			if !errors.Is(err, want) {
				t.Fatal("false clone declaration was admitted", err)
			}
		})
	}
}

func TestAPFSBuildRechecksEveryDeclaredCloneMemberDuringStreaming(t *testing.T) {
	ctx := context.Background()
	r, s := declaredCloneInput(t)
	plan, err := Plan(ctx, r, BuildOptions{Name: "Clones", Time: builtClock})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReplaceData(ctx, "/source", bytes.NewReader(bytes.Repeat([]byte("x"), len(cloneData)))); err != nil {
		t.Fatal(err)
	}
	if err := plan.Write(ctx, io.Discard); !errors.Is(err, filesystem.ErrConflict) {
		t.Fatal("changed clone member hidden by shared physical output", err)
	}
}

func TestAPFSBuildRechecksEmptyCloneStreamsWithoutPhysicalOutputParts(t *testing.T) {
	ctx := context.Background()
	s, err := session.Create(ctx, filepath.Join(t.TempDir(), "empty-clones"), session.Options{Names: filesystem.NameRules{Format: "APFS", NormalizationInsensitive: true}, Time: &builtClock})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Touch(ctx, []string{"/source"}, session.TouchOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Copy(ctx, []string{"/source"}, "/clone", session.CopyOptions{Clone: true}); err != nil {
		t.Fatal(err)
	}
	plan, err := Plan(ctx, s, BuildOptions{Name: "Empty Clones", Time: builtClock})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReplaceData(ctx, "/source", bytes.NewReader([]byte("grew after planning"))); err != nil {
		t.Fatal(err)
	}
	if err := plan.Write(ctx, io.Discard); !errors.Is(err, filesystem.ErrConflict) {
		t.Fatal("empty source growth was hidden", err)
	}
}
