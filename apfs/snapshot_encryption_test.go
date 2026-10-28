package apfs

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"slices"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// Synthetic regression for the independently observed native completed-decrypt
// profile: plaintext current mappings/data, retained ONEKEY stream descriptors
// and original encrypted snapshot flags. This fixture is not a native oracle.
func decryptedSnapshotImage(t *testing.T) *cloneMutationDisk {
	t.Helper()
	ctx := context.Background()
	disk := newCloneMutationDisk(builtContainer(t, nil))
	if _, err := Modify(ctx, disk, []Change{{Path: "/payload", Data: bytes.NewReader([]byte("retained plaintext"))}}, builtClock); err != nil {
		t.Fatal(err)
	}
	retainSyntheticSnapshot(t, disk, "")
	if _, err := Modify(ctx, disk, []Change{{Path: "/payload", Data: bytes.NewReader([]byte("live plaintext"))}}, builtClock); err != nil {
		t.Fatal(err)
	}
	m, err := openMutation(ctx, disk)
	if err != nil {
		t.Fatal(err)
	}
	historical := m.ownership.views[0].fs
	if len(historical.nodes) != 1 {
		t.Fatal("regression requires one small historical node")
	}
	var records []buildRecord
	for _, r := range historical.all() {
		r = buildRecord{bytes.Clone(r.key), bytes.Clone(r.value)}
		switch prefix(r.key).kind {
		case 3:
			if err := extendedFields(r.value[92:], func(kind byte, data []byte) error {
				if kind == 8 {
					le.PutUint64(data[16:], 4)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		case 8:
			address := le.Uint64(r.value[8:])
			if address != 0 {
				le.PutUint64(r.value, le.Uint64(r.value)|1<<56)
				le.PutUint64(r.value[16:], address)
			}
		}
		records = append(records, r)
	}
	state := make([]byte, 24)
	le.PutUint32(state, 1)
	records = append(records, buildRecord{buildKey(4, 7, 0), state})
	slices.SortFunc(records, func(a, b buildRecord) int {
		if historical.less(a.key, b.key) {
			return -1
		}
		if historical.less(b.key, a.key) {
			return 1
		}
		return 0
	})
	tree, err := newBuildTree(records, 14, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(tree.nodes) != 1 {
		t.Fatal("historical regression outgrew one node")
	}
	node := tree.root()
	old := historical.rootNode
	node.oid, node.address = old.oid, old.address
	raw, err := m.c.object(PhysicalAddress(old.address), 0)
	if err != nil {
		t.Fatal(err)
	}
	data := tree.nodeBytes(node, true)
	sealObject(data, node.oid, le.Uint64(raw[16:]), 2, 14)
	if _, err = disk.WriteAt(data, int64(node.address)*4096); err != nil {
		t.Fatal(err)
	}
	snapshot := m.ownership.snapshots[0]
	super, err := m.c.object(snapshot.superblock, 13)
	if err != nil {
		t.Fatal(err)
	}
	le.PutUint64(super[264:], 8)
	sealObject(super, le.Uint64(super[8:]), le.Uint64(super[16:]), le.Uint32(super[24:]), le.Uint32(super[28:]))
	if _, err = disk.WriteAt(super, int64(snapshot.superblock)*4096); err != nil {
		t.Fatal(err)
	}
	le.PutUint64(m.super[56:], le.Uint64(m.super[56:])|4)
	sealObject(m.super, le.Uint64(m.super[8:]), le.Uint64(m.super[16:]), le.Uint32(m.super[24:]), le.Uint32(m.super[28:]))
	if _, err = disk.WriteAt(m.super, int64(m.volumeAddress)*4096); err != nil {
		t.Fatal(err)
	}
	return disk
}

func TestCompletedDecryptionReadsAndConvertsRetainedONEKEYDescriptors(t *testing.T) {
	ctx := context.Background()
	disk := decryptedSnapshotImage(t)
	check := func(source block.Source) {
		t.Helper()
		c, err := Open(source)
		if err != nil {
			t.Fatal(err)
		}
		live := &c.Volumes[0]
		historical, err := live.OpenSnapshotName(ctx, "retained-history")
		if err != nil {
			t.Fatal(err)
		}
		for _, view := range []struct {
			reader filesystem.Reader
			want   string
		}{{live, "live plaintext"}, {historical, "retained plaintext"}} {
			id, err := filesystem.Lookup(ctx, view.reader, "/payload")
			if err != nil {
				t.Fatal(err)
			}
			value, err := view.reader.OpenData(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			data := make([]byte, value.Size())
			_, err = value.ReadAt(data, 0)
			closeErr := value.Close()
			if err != nil && !errors.Is(err, io.EOF) || closeErr != nil || string(data) != view.want {
				t.Fatal("retained data interpreted with stale encryption state", string(data), err, closeErr)
			}
		}
	}
	check(disk)
	deletion := newCloneMutationDisk(disk.data)
	if _, err := DeleteSnapshot(ctx, deletion, "", SnapshotSelector{Name: "retained-history"}, builtClock); err != nil {
		t.Fatal("delete completed-decryption history", err)
	}
	deleted, snapshots := deleteTestSnapshots(t, deletion)
	if len(snapshots) != 0 || !bytes.Equal(cloneContents(t, deletion, "/payload", ""), []byte("live plaintext")) {
		t.Fatal("completed-decryption deletion changed the live state", snapshots)
	}
	if _, err := deleted.Volumes[0].OpenSnapshotName(ctx, "retained-history"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("deleted completed-decryption history remains selectable", err)
	}
	if err := ValidateMutation(ctx, deletion); err != nil {
		t.Fatal("completed-decryption deletion ownership", err)
	}
	owner, err := UnlockMutation(ctx, disk)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if err := ValidateMutation(ctx, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := ConvertVolumeEncryption(ctx, owner, "", EncryptionConversion{Encrypt: true, Password: []byte("public-retained-conversion-password")}, builtClock); err != nil {
		t.Fatal(err)
	}
	check(owner)
	if _, err := ConvertVolumeEncryption(ctx, owner, "", EncryptionConversion{}, builtClock); err != nil {
		t.Fatal(err)
	}
	check(owner)
}

func TestHistoricalCryptoFlagsRequireCompletedDecryption(t *testing.T) {
	for _, fault := range []string{"missing completed marker", "active live conversion", "active historical conversion", "non-ONEKEY history"} {
		t.Run(fault, func(t *testing.T) {
			disk := decryptedSnapshotImage(t)
			c, err := Open(disk)
			if err != nil {
				t.Fatal(err)
			}
			v := &c.Volumes[0]
			snapshots, err := v.snapshots(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "missing completed marker":
				v.IncompatibleFeatures &^= 4
			case "active live conversion":
				v.EncryptionRollingStateOID = 1
			default:
				snapshot := snapshots[0]
				super, err := c.object(snapshot.superblock, 13)
				if err != nil {
					t.Fatal(err)
				}
				if fault == "active historical conversion" {
					le.PutUint64(super[976:], 1)
				} else {
					le.PutUint64(super[264:], 0)
				}
				sealObject(super, le.Uint64(super[8:]), le.Uint64(super[16:]), le.Uint32(super[24:]), le.Uint32(super[28:]))
				if _, err := disk.WriteAt(super, int64(snapshot.superblock)*4096); err != nil {
					t.Fatal(err)
				}
			}
			if err := v.ListSnapshots(context.Background(), func(Snapshot) error { return nil }); !errors.Is(err, filesystem.ErrUnsupported) {
				t.Fatal("unqualified historical crypto state admitted", err)
			}
		})
	}
}
