package apfs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// This literal is the original 20-byte j_phys_ext_val_t at physical block
// 347, in retained Apple snapshot XID 15's extent tree (block 17103). Both
// captured macOS 26 name policies encode the same INVALID owner on UPDATE.
// The original failing Go outputs retain these Apple pages unchanged:
// CI 40114548003, macos-26.snapshot-history.{apfs,apfsx}.live.snapshot-edit.UDZO.dmg.
// Their SHA256s are 4db353a8db738d653a1b653a5bdeda048b78626f561ffc937990698c945ff0e3
// and c1a898934c5c67d115b3534a0a347e477b46ebf380e9a29405f8d8b97ba673db.
// Apple's format reference names ~0ULL OWNING_OBJ_ID_INVALID; its prose does
// not specify this UPDATE rule. Native records and fsck's rejection of actual
// ordinary-owner UPDATEs independently establish the admitted encoding.
const nativeSnapshotUpdateValue = "0100000000000020ffffffffffffffffffffffff"

func snapshotExtentRecords(t *testing.T, disk *cloneMutationDisk) []buildRecord {
	t.Helper()
	c, err := Open(disk)
	if err != nil {
		t.Fatal(err)
	}
	s, err := newStorageChecker(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.check(); err != nil {
		t.Fatal(err)
	}
	return s.volumes[0].extents.all()
}

func TestSnapshotLiveMutationEncodesNativeUpdateOwners(t *testing.T) {
	ctx := context.Background()
	native, err := hex.DecodeString(nativeSnapshotUpdateValue)
	if err != nil || len(native) != 20 || le.Uint64(native)>>60 != 2 || int32(le.Uint32(native[16:])) != -1 {
		t.Fatal("invalid retained native UPDATE anchor", err)
	}
	wantOwner := le.Uint64(native[8:])
	original := snapshotMutationImage(t)
	originalSHA := sha256.Sum256(original)
	disk := newCloneMutationDisk(original)
	c, err := Open(disk)
	if err != nil {
		t.Fatal(err)
	}
	uuid := c.Volumes[0].UUID
	history, err := c.Volumes[0].OpenSnapshotName(ctx, "retained-history")
	if err != nil {
		t.Fatal(err)
	}
	wantHistory := snapshotStates(t, history)
	for round := 0; round < 3; round++ {
		data := bytes.Repeat([]byte("live fork replacement"), 800+round)
		if _, err := ModifyVolume(ctx, disk, uuid, []Change{{Path: "/clone-a", ResourceFork: true, Data: bytes.NewReader(data)}}, builtClock); err != nil {
			t.Fatal(err)
		}
		updates, fresh := 0, 0
		for _, r := range snapshotExtentRecords(t, disk) {
			kind, owner := le.Uint64(r.value)>>60, le.Uint64(r.value[8:])
			if kind == 2 {
				updates++
				if owner != wantOwner {
					t.Fatalf("round %d: UPDATE extent %d owner %#x, want native INVALID owner %#x (signed delta %d)", round, prefix(r.key).id, owner, wantOwner, int32(le.Uint32(r.value[16:])))
				}
			} else {
				fresh++
				if kind != 1 || owner == 0 || owner > objectMask {
					t.Fatal("NEW allocation lost its ordinary stream owner", owner)
				}
			}
		}
		if updates == 0 || fresh == 0 {
			t.Fatal("public replacement must exercise both retained UPDATE and fresh NEW allocations", updates, fresh)
		}
		c, err = Open(disk)
		if err != nil {
			t.Fatal(err)
		}
		if got := cloneContents(t, disk, "/clone-a", filesystem.ResourceFork); !bytes.Equal(got, data) {
			t.Fatal("fresh reopen changed replacement fork bytes")
		}
		if got := cloneContents(t, disk, "/clone-alias", filesystem.ResourceFork); !bytes.Equal(got, data) {
			t.Fatal("replacement did not remain visible through its hard-link alias")
		}
		for _, path := range []string{"/source", "/clone-b"} {
			if got := cloneContents(t, disk, path, filesystem.ResourceFork); !bytes.Equal(got, wantHistory[path].Attrs[filesystem.ResourceFork]) {
				t.Fatal("private fork replacement changed an untouched live owner", path)
			}
		}
		if got := cloneContents(t, disk, "/independent", ""); !bytes.Equal(got, wantHistory["/independent"].Data) {
			t.Fatal("fork replacement changed independent file bytes")
		}
		history, err = c.Volumes[0].OpenSnapshotName(ctx, "retained-history")
		if err != nil || !reflect.DeepEqual(snapshotStates(t, history), wantHistory) {
			t.Fatal("UPDATE changed immutable historical objects", err)
		}
	}
	if sha256.Sum256(original) != originalSHA {
		t.Fatal("immutable source bytes changed")
	}
}

func TestSnapshotMutationRejectsUpdateOwnerCorruptionBeforeWrites(t *testing.T) {
	ctx := context.Background()
	valid := newCloneMutationDisk(snapshotMutationImage(t))
	if _, err := ModifyVolume(ctx, valid, "", []Change{{Path: "/clone-a", ResourceFork: true, Data: bytes.NewReader([]byte("private fork"))}}, builtClock); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMutation(ctx, valid); err != nil {
		t.Fatal("native-marker UPDATE control refused", err)
	}
	for _, owner := range []uint64{0, 19, ^uint64(1)} {
		t.Run(fmt.Sprintf("owner-%x", owner), func(t *testing.T) {
			original := bytes.Clone(valid.data)
			digest := sha256.Sum256(original)
			disk := &storageFaultSource{Source: bytes.NewReader(original), patches: map[uint64][]byte{}}
			c, err := Open(disk)
			if err != nil {
				t.Fatal(err)
			}
			storage, err := newStorageChecker(ctx, c)
			if err != nil {
				t.Fatal(err)
			}
			if err := storage.check(); err != nil {
				t.Fatal(err)
			}
			patchStorageRecord(t, disk, storage.volumes[0].extents, func(r buildRecord) bool { return le.Uint64(r.value)>>60 == 2 }, func(r buildRecord) { le.PutUint64(r.value[8:], owner) })
			if err := ValidateMutation(ctx, disk); !errors.Is(err, filesystem.ErrCorrupt) {
				t.Fatal("invalid UPDATE owner admitted", err)
			}
			_, err = ModifyVolume(ctx, disk, c.Volumes[0].UUID, []Change{{Path: "/source", Data: bytes.NewReader([]byte("must never be written"))}}, builtClock)
			if !errors.Is(err, filesystem.ErrCorrupt) || disk.writes != 0 || sha256.Sum256(original) != digest {
				t.Fatal("bad UPDATE reached writes or lost its refusal", disk.writes, err)
			}
		})
	}
}
