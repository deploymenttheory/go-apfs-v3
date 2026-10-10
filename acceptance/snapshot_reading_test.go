package acceptance_test

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

type nativeSnapshots struct {
	EmptyBefore     bool             `json:"emptyBefore"`
	Inventory       string           `json:"inventory"`
	InventorySHA256 string           `json:"inventorySHA256"`
	DeletedName     string           `json:"deletedName"`
	DeletedXID      apfs.XID         `json:"deletedXID"`
	Entries         []nativeSnapshot `json:"entries"`
}
type nativeSnapshot struct {
	Name       string   `json:"name"`
	XID        apfs.XID `json:"xid"`
	UUID       string   `json:"uuid"`
	Attributes struct {
		Name     string `json:"name"`
		CreateNS *int64 `json:"createNS,omitempty"`
		ModifyNS *int64 `json:"modifyNS,omitempty"`
		ChangeNS *int64 `json:"changeNS,omitempty"`
	} `json:"attributes"`
	Files       string `json:"files"`
	FilesSHA256 string `json:"filesSHA256"`
	ReadOnly    bool   `json:"readOnly"`
}
type nativeSnapshotPasswords struct {
	Image                   string `json:"image"`
	Volume                  string `json:"volume"`
	LockedObservation       string `json:"lockedObservation"`
	LockedObservationSHA256 string `json:"lockedObservationSHA256"`
}

// Expected historical files must come from native read-only snapshot mounts of
// the final image. The source-writing recipe and Go-created snapshots cannot
// substitute for this independent evidence. An absent corpus fails the gate.
func TestNativeSnapshotReading(t *testing.T) {
	testFileCorpus(t, "snapshot-reading", "APFS_NATIVE_SNAPSHOTS", "testdata/snapshots", 105, nil)
}

func openSnapshotImage(t *testing.T, path string, passwords *nativeSnapshotPasswords, dir string) *diskimage.Image {
	t.Helper()
	verifyDigest(t, dir, passwords.LockedObservation, passwords.LockedObservationSHA256)
	image, err := diskimage.OpenWithPassword(context.Background(), path, []byte(passwords.Image))
	if err != nil {
		t.Fatal(err)
	}
	return image
}

func unlockSnapshotVolume(t *testing.T, reader filesystem.Reader, passwords *nativeSnapshotPasswords) *apfs.Volume {
	t.Helper()
	v, ok := reader.(*apfs.Volume)
	if !ok || !v.Encrypted {
		t.Fatal("missing independently encrypted snapshot volume")
	}
	if _, err := v.Stat(context.Background(), v.Root()); !errors.Is(err, filesystem.ErrAuthentication) {
		t.Fatal("image unlock unlocked APFS", err)
	}
	unlocked, err := v.Unlock(context.Background(), []byte(passwords.Volume))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unlocked.Close(); err != nil {
			t.Error(err)
		}
	})
	return unlocked
}

func compareSnapshots(t *testing.T, reader filesystem.Reader, live fileObservation, dir string) {
	t.Helper()
	v, ok := reader.(*apfs.Volume)
	if !ok {
		t.Fatal("snapshot case is not APFS")
	}
	want := live.Snapshots
	if want == nil || !want.EmptyBefore || len(want.Entries) != 2 || want.DeletedXID == 0 || want.DeletedName == "" {
		t.Fatal("incomplete snapshot evidence")
	}
	verifyDigest(t, dir, want.Inventory, want.InventorySHA256)
	ctx := context.Background()
	got := map[apfs.XID]apfs.Snapshot{}
	var last apfs.XID
	if err := v.ListSnapshots(ctx, func(s apfs.Snapshot) error {
		if s.XID <= last {
			t.Fatal("unordered or duplicate snapshot")
		}
		last = s.XID
		got[s.XID] = s
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want.Entries) {
		t.Fatal("native snapshot inventory differs", got, want.Entries)
	}
	readers := []filesystem.Reader{reader}
	observations := []fileObservation{live}
	for _, expected := range want.Entries {
		s, found := got[expected.XID]
		if !found || s.Name != expected.Name || expected.Attributes.Name != expected.Name || !expected.ReadOnly || s.UUID.State != filesystem.Present || s.UUID.Value != expected.UUID {
			t.Fatal("snapshot identity differs", s, expected)
		}
		if expected.Attributes.CreateNS != nil && s.CreateTime.UnixNano() != *expected.Attributes.CreateNS {
			t.Fatal("snapshot creation timestamp differs", s, expected.Attributes)
		}
		if expected.Attributes.ChangeNS != nil && s.ChangeTime.UnixNano() != *expected.Attributes.ChangeNS {
			t.Fatal("snapshot change timestamp differs", s, expected.Attributes)
		}
		verifyDigest(t, dir, expected.Files, expected.FilesSHA256)
		var observation fileObservation
		decodeEvidence(t, filepath.Join(dir, expected.Files), &observation)
		if observation.Schema != 1 || observation.Root != "Fixture" || len(observation.Entries) < 105 || len(observation.Lookups) != 6 {
			t.Fatal("incomplete historical file observation")
		}
		r, err := v.OpenSnapshot(ctx, expected.XID)
		if err != nil {
			t.Fatal("native retained snapshot rejected", err)
		}
		if _, ownsKeys := r.(io.Closer); ownsKeys {
			t.Fatal("snapshot reader exposes borrowed key ownership")
		}
		byName, err := v.OpenSnapshotName(ctx, expected.Name)
		if err != nil {
			t.Fatal(err)
		}
		left, err := r.Stat(ctx, r.Root())
		if err != nil {
			t.Fatal(err)
		}
		right, err := byName.Stat(ctx, byName.Root())
		if err != nil || !reflect.DeepEqual(left, right) || left.Identity.View != uint64(expected.XID) || left.Identity.Volume != v.UUID {
			t.Fatal("name and XID selected different views", err, left, right)
		}
		compareFiles(t, r, observation)
		compareHistoricalExtraction(t, r, observation, uint64(expected.XID))
		for _, query := range observation.Lookups {
			id, err := filesystem.Lookup(ctx, r, query.Path)
			if query.Object == 0 {
				if !errors.Is(err, fs.ErrNotExist) {
					t.Fatal("historically absent name resolved", query, err)
				}
			} else if err != nil || id != query.Object {
				t.Fatal("historical lookup differs", query, id, err)
			}
		}
		readers = append(readers, r)
		observations = append(observations, observation)
	}
	for _, xid := range []apfs.XID{0, want.DeletedXID, apfs.XID(^uint64(0))} {
		if r, err := v.OpenSnapshot(ctx, xid); r != nil || !errors.Is(err, fs.ErrNotExist) {
			t.Fatal("missing/deleted snapshot returned a reader", xid, err)
		}
	}
	for _, name := range []string{want.DeletedName, "absent-snapshot"} {
		if r, err := v.OpenSnapshotName(ctx, name); r != nil || !errors.Is(err, fs.ErrNotExist) {
			t.Fatal("missing snapshot name returned a reader", name, err)
		}
	}
	// Open all values before reading any. Reversed reads exercise independent
	// historical roots and the shared image/decompression caches.
	values := make([]filesystem.Value, len(readers))
	expectedValues := make([]nativeValue, len(readers))
	for i, r := range readers {
		for _, e := range observations[i].Entries {
			if e.Path == "Fixture/generation.txt" {
				id, err := filesystem.Lookup(ctx, r, e.Path)
				if err != nil {
					t.Fatal(err)
				}
				values[i], err = r.OpenData(ctx, id)
				if err != nil {
					t.Fatal(err)
				}
				expectedValues[i] = nativeValue{int64(e.Size), e.SHA256}
			}
		}
		if values[i] == nil {
			t.Fatal("missing state-distinguishing file")
		}
	}
	for i := len(values) - 1; i >= 0; i-- {
		compareValue(t, "interleaved snapshot generation", values[i], expectedValues[i])
	}
	if expectedValues[0].SHA256 == expectedValues[1].SHA256 || expectedValues[0].SHA256 == expectedValues[2].SHA256 || expectedValues[1].SHA256 == expectedValues[2].SHA256 {
		t.Fatal("native states do not distinguish historical file contents")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if r, err := v.OpenSnapshot(cancelled, want.Entries[0].XID); r != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("snapshot opening ignored cancellation", err)
	}
	if live.SnapshotPasswords != nil {
		checkSnapshotKeyLifetime(t, v, readers[1], want.Entries[0].XID, live.SnapshotPasswords.Volume)
	}
	t.Logf("matched %d retained snapshots and the live state; missing/deleted selections rejected; source preserved", len(want.Entries))
}

func checkSnapshotKeyLifetime(t *testing.T, owner *apfs.Volume, snapshot filesystem.Reader, xid apfs.XID, password string) {
	t.Helper()
	ctx := context.Background()
	independent, err := owner.Unlock(ctx, []byte(password))
	if err != nil {
		t.Fatal(err)
	}
	defer independent.Close()
	id, err := filesystem.Lookup(ctx, snapshot, "Fixture/compressed")
	if err != nil {
		t.Fatal(err)
	}
	value, err := snapshot.OpenData(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	defer value.Close()
	if _, err := value.ReadAt(make([]byte, 1), 0); err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := value.ReadAt(make([]byte, 1), 0); !errors.Is(err, fs.ErrClosed) {
		t.Fatal("closed unlock served historical cache", err)
	}
	if _, err := snapshot.Stat(ctx, snapshot.Root()); !errors.Is(err, fs.ErrClosed) {
		t.Fatal("snapshot outlived its key owner", err)
	}
	if _, err := independent.OpenSnapshot(ctx, xid); err != nil {
		t.Fatal("closing another unlock invalidated independent snapshot access", err)
	}
}
