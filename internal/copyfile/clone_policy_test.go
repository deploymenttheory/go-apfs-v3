package copyfile_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"path/filepath"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/copyfile"
	"github.com/deploymenttheory/go-apfs-v3/internal/edit"
	"github.com/deploymenttheory/go-apfs-v3/internal/filesec"
	"github.com/deploymenttheory/go-apfs-v3/session"
)

func TestCloneCopyUpdatesSurvivingAliasChangeTimeAndDoesNotInheritSymlinkACL(t *testing.T) {
	ctx := context.Background()
	before, now := time.Unix(1_700_000_000, 0).UTC(), time.Unix(1_800_000_000, 0).UTC()
	base, err := session.Create(ctx, filepath.Join(t.TempDir(), "source"), session.Options{Names: filesystem.NameRules{Format: "APFS", NormalizationInsensitive: true}, Time: &before})
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	tree, err := edit.New(ctx, base, edit.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	parentACL := make([]byte, 68)
	binary.BigEndian.PutUint32(parentACL, filesec.Magic)
	binary.BigEndian.PutUint32(parentACL[36:], 1)
	binary.BigEndian.PutUint32(parentACL[60:], 1|filesec.File|filesec.Directory)
	binary.BigEndian.PutUint32(parentACL[64:], 0x000a82)
	metadata := filesystem.Metadata{Mode: filesystem.Observed(uint32(0100644)), UID: filesystem.Observed(uint32(501)), GID: filesystem.Observed(uint32(20)), BSDFlags: filesystem.Observed(uint32(0)), BirthTime: filesystem.Observed(before), ModifyTime: filesystem.Observed(before), ChangeTime: filesystem.Observed(before), AccessTime: filesystem.Observed(before)}
	for _, change := range []edit.Change{
		{Op: edit.CreateFile, Path: "/source", Metadata: &metadata, Data: bytes.NewReader([]byte("source"))},
		{Op: edit.CreateFile, Path: "/target", Metadata: &metadata, Data: bytes.NewReader([]byte("old target"))},
		{Op: edit.CreateHardLink, Path: "/target", To: "/old-alias"},
	} {
		if err := tree.ApplyCommand(ctx, change); err != nil {
			t.Fatal(err)
		}
	}
	metadata.Mode.Value = 0040755
	for _, name := range []string{"/tree", "/destination"} {
		change := edit.Change{Op: edit.CreateDirectory, Path: name, Metadata: &metadata}
		if name == "/destination" {
			change.Attributes = map[string]block.Source{filesec.Attribute: bytes.NewReader(parentACL)}
		}
		if err := tree.ApplyCommand(ctx, change); err != nil {
			t.Fatal(err)
		}
	}
	metadata.Mode.Value = 0120777
	if err := tree.ApplyCommand(ctx, edit.Change{Op: edit.CreateSymlink, Path: "/tree/link", Target: "../source", Metadata: &metadata}); err != nil {
		t.Fatal(err)
	}
	metadata.Mode.Value = 0100644
	if err := tree.ApplyCommand(ctx, edit.Change{Op: edit.CreateFile, Path: "/tree/leaf", Metadata: &metadata, Data: bytes.NewReader([]byte("leaf"))}); err != nil {
		t.Fatal(err)
	}
	backend := copyfile.Backend{Tree: tree, Time: now, UID: 0, GID: 20, ActorUID: filesystem.Observed(uint32(0)), CloneNamespace: "immutable-source-revision", Apply: tree.ApplyCommand, Own: func(_ context.Context, value filesystem.Value, _ *int64) (block.Source, error) {
		data, err := io.ReadAll(io.NewSectionReader(value, 0, value.Size()))
		return bytes.NewReader(data), errors.Join(err, value.Close())
	}}
	if err := copyfile.Run(ctx, backend, []string{"/source"}, "/target", copyfile.Options{Clone: true}); err != nil {
		t.Fatal(err)
	}
	id, err := filesystem.Lookup(ctx, tree, "/old-alias")
	if err != nil {
		t.Fatal(err)
	}
	old, err := tree.Stat(ctx, id)
	if err != nil || !old.Metadata.ChangeTime.Value.Equal(now) || !old.Metadata.ModifyTime.Value.Equal(before) || !old.Metadata.AccessTime.Value.Equal(before) || !old.Metadata.BirthTime.Value.Equal(before) || old.Links.Value != 1 {
		t.Error("surviving old alias did not retain inode clocks with updated unlink ctime", err, old.Metadata)
	}
	if err := copyfile.Run(ctx, backend, []string{"/tree"}, "/destination", copyfile.Options{Clone: true, Recursive: true}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"/destination/tree/link", "/destination/tree/leaf", "/destination/tree"} {
		id, err := filesystem.LookupExact(ctx, tree, name)
		if err != nil {
			t.Fatal(err)
		}
		value, err := tree.OpenAttribute(ctx, id, filesec.Attribute)
		if name == "/destination/tree/link" {
			if !errors.Is(err, fs.ErrNotExist) {
				t.Error("recursive symlink inherited regular-file ACL", err)
				if value != nil {
					value.Close()
				}
			}
		} else {
			if err != nil {
				t.Fatal("file/directory inheritance was lost", name, err)
			}
			if err := value.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
}
