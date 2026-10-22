package acceptance_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/native"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

var cloneStages = []string{"clone-shared", "clone-diverged", "clone-truncated", "clone-final-owner"}
var encryptedVolumeStages = []string{"clone-shared", "clone-diverged", "clone-truncated", "clone-final-owner", "encrypted-peer", "password-changed", "converted", "decrypted"}
var snapshotStages = map[string][]string{
	"apfs":  {"before", "after", "live", "api-probe", "aes256-dmg"},
	"apfsx": {"before", "after", "live", "api-probe"},
}

// storageCases makes the bounded capability matrix explicit. Missing producers,
// profiles or stages fail before any subtest runs; an empty selection cannot pass.
func storageCases(t *testing.T, matrix map[string]map[string][]string) []corpus.Case {
	t.Helper()
	cases, _ := loadCorpus(t)
	wanted := map[string]bool{}
	for recipe, profiles := range matrix {
		for profile, stages := range profiles {
			for _, major := range []int{15, 26, 27} {
				for _, stage := range stages {
					wanted[fmt.Sprintf("%d/%s/%s/%s", major, recipe, profile, stage)] = false
				}
			}
		}
	}
	var selected []corpus.Case
	for _, k := range cases {
		key := native.CaseKey(caseRef(k))
		if seen, ok := wanted[key]; ok {
			if seen {
				t.Fatalf("duplicate storage control %s", key)
			}
			wanted[key] = true
			selected = append(selected, k)
		}
	}
	for key, seen := range wanted {
		if !seen {
			t.Errorf("missing storage control %s", key)
		}
	}
	if t.Failed() {
		t.FailNow()
	}
	return selected
}

func storageImageUnchanged(t *testing.T, k corpus.Case) {
	t.Helper()
	path := filepath.Join(k.Dir, k.Observation.Image.File)
	check := func() {
		t.Helper()
		got, err := schema.FileDigest(path)
		if err != nil || got != k.Observation.Image.SHA256 {
			t.Errorf("retained source changed: SHA-256 %s, native %s: %v", got, k.Observation.Image.SHA256, err)
		}
	}
	check()
	t.Cleanup(check)
}

func storagePartition(t *testing.T, img *diskimage.Image) (block.Source, int) {
	t.Helper()
	var found block.Source
	index := -1
	for _, p := range img.Partitions {
		part, err := img.Partition(p.Index)
		if err != nil {
			t.Fatal(err)
		}
		var h [36]byte
		if err = block.ReadFull(part, h[:], 0); err != nil {
			t.Fatal(err)
		}
		if string(h[32:]) == "NXSB" {
			if found != nil {
				t.Fatal("storage control has more than one APFS container")
			}
			found, index = part, p.Index
		}
	}
	if found == nil {
		t.Fatal("storage control has no APFS container")
	}
	return found, index
}

// physicalReads observes public block.Source reads, without interpreting APFS
// records or exposing private reader implementation. Metadata lookups happen
// before begin; only an already opened value's data reads are admitted.
type physicalReads struct {
	block.Source
	mu     sync.Mutex
	armed  bool
	ranges [][2]int64
	writes int
}

func (s *physicalReads) ReadAt(p []byte, off int64) (int, error) {
	n, err := s.Source.ReadAt(p, off)
	s.mu.Lock()
	if s.armed && n > 0 {
		s.ranges = append(s.ranges, [2]int64{off, int64(n)})
	}
	s.mu.Unlock()
	return n, err
}

func (s *physicalReads) WriteAt([]byte, int64) (int, error) {
	s.mu.Lock()
	s.writes++
	s.mu.Unlock()
	return 0, fs.ErrPermission
}

func (s *physicalReads) begin() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ranges, s.armed = nil, true
}

func (s *physicalReads) end() [][2]int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.armed = false
	return append([][2]int64(nil), s.ranges...)
}

// TestCloneReadsUseNativeSharedExtents proves shared data and resource forks,
// partial copy-on-write divergence, truncation and surviving-owner reads. Native
// equal-content ordinary copies and hard links are distinct negative controls.
func TestCloneReadsUseNativeSharedExtents(t *testing.T) {
	cases := storageCases(t, map[string]map[string][]string{"encrypted-volumes": {"apfs": cloneStages, "apfsx": cloneStages}})
	recipes := recipesByName(t)
	for _, k := range cases {
		t.Run(native.CaseKey(caseRef(k)), func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			storageImageUnchanged(t, k)
			img := openImage(t, ctx, k, recipes[k.Recipe])
			defer func() { _ = img.Close() }()
			part, _ := storagePartition(t, img)
			trace := &physicalReads{Source: part}
			container, err := apfs.Open(trace)
			if err != nil {
				t.Fatal(err)
			}
			var volume *apfs.Volume
			for i := range container.Volumes {
				if container.Volumes[i].Name == "Primary" {
					volume = &container.Volumes[i]
				}
			}
			if volume == nil || !volume.Encrypted {
				t.Fatal("clone control lacks the native encrypted Primary volume")
			}
			nativeIndex := -1
			for _, observed := range k.Observation.Volumes {
				if name, _ := observed.Diskutil["VolumeName"].(string); name == "Primary" {
					if nativeIndex >= 0 || observed.APFS == nil || !observed.APFS.Encrypted || strings.ToUpper(observed.APFS.VolumeUUID) != volume.UUID {
						t.Fatal("native Primary volume is ambiguous or has different identity/encryption")
					}
					nativeIndex = observed.Index
				}
			}
			if nativeIndex < 0 {
				t.Fatal("native clone observation lacks Primary")
			}
			unlocked, err := volume.Unlock(ctx, []byte(recipes[k.Recipe].Passwords["primary"]))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = unlocked.Close() }()
			var view *schema.View
			for i := range k.Observation.Views {
				candidate := &k.Observation.Views[i]
				if candidate.Volume == nativeIndex && candidate.Snapshot == "" {
					if view != nil {
						t.Fatal("clone control has duplicate native live views")
					}
					view = candidate
				}
			}
			if view == nil {
				t.Fatal("clone control lacks its live native view")
			}
			if err = native.CheckCloneSharing(*view, k.Stage); err != nil {
				t.Fatal(err)
			}
			// Independent unlocks borrow the same immutable source while owning
			// separate key lifetimes. Closing one owner invalidates its values
			// without unlocking the original or invalidating the surviving view.
			other, err := volume.Unlock(ctx, []byte(recipes[k.Recipe].Passwords["primary"]))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = other.Close() }()
			cloneID, err := filesystem.LookupExact(ctx, other, "Fixture/clone")
			if err != nil {
				t.Fatal(err)
			}
			borrowed, err := other.OpenRawData(ctx, cloneID)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = borrowed.Close() }()
			if err = other.Close(); err != nil {
				t.Fatal(err)
			}
			var probe [1]byte
			if _, err = borrowed.ReadAt(probe[:], 0); !errors.Is(err, fs.ErrClosed) {
				t.Errorf("closing the key owner left a borrowed value readable: %v", err)
			}
			if _, err = other.Stat(ctx, other.Root()); !errors.Is(err, fs.ErrClosed) {
				t.Errorf("closed key owner remains readable: %v", err)
			}
			if _, err = volume.Stat(ctx, volume.Root()); !errors.Is(err, filesystem.ErrAuthentication) {
				t.Errorf("independent unlock changed the original locked volume: %v", err)
			}
			for _, entry := range view.Entries {
				if entry.Extents == nil {
					continue
				}
				id, err := filesystem.LookupExact(ctx, unlocked, entry.Path)
				if err != nil {
					t.Fatal(err)
				}
				if id != entry.ID {
					t.Fatalf("%s: object %d, native %d", entry.Path, id, entry.ID)
				}
				for _, fork := range []struct {
					name string
					runs [][3]int64
				}{
					{"data", entry.Extents.Data}, {"resource", entry.Extents.Resource},
				} {
					var value filesystem.Value
					var sum string
					if fork.name == "data" {
						value, err = unlocked.OpenRawData(ctx, id)
						sum = entry.SHA256
					} else {
						value, err = unlocked.OpenAttribute(ctx, id, filesystem.ResourceFork)
						for _, attr := range entry.Xattrs {
							if attr.Name == filesystem.ResourceFork {
								sum = attr.SHA256
							}
						}
					}
					if err != nil {
						t.Fatalf("%s/%s: %v", entry.Path, fork.name, err)
					}
					checkForkPhysicalReads(t, trace, entry.Path+"/"+fork.name, value, fork.runs, sum)
					if err = value.Close(); err != nil {
						t.Fatal(err)
					}
				}
			}
		})
	}
}

func checkForkPhysicalReads(t *testing.T, trace *physicalReads, label string, value filesystem.Value, runs [][3]int64, sum string) {
	t.Helper()
	if !schema.ValidDigest(sum) || len(runs) == 0 {
		t.Fatalf("%s: native fork has no digest or physical runs", label)
	}
	h := sha256.New()
	var end int64
	for _, run := range runs {
		if run[0] != end || run[1] < 0 || run[2] <= 0 || run[2] > 1<<20 || run[2] > value.Size()-end {
			t.Fatalf("%s: invalid native run %v for fork size %d", label, run, value.Size())
		}
		buf := make([]byte, int(run[2]))
		trace.begin()
		err := block.ReadFull(value, buf, run[0])
		reads := trace.end()
		if err != nil {
			t.Fatalf("%s: read native run %v: %v", label, run, err)
		}
		if err = native.ComparePhysicalRead(reads, run, 512); err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		_, _ = h.Write(buf)
		end += run[2]
	}
	if end != value.Size() || hex.EncodeToString(h.Sum(nil)) != sum {
		t.Fatalf("%s: fork size/digest differs from native read (%d/%d, %x/%s)", label, end, value.Size(), h.Sum(nil), sum)
	}
}

// TestStorageAccountingMatchesNativeAllocation checks the admitted plaintext
// profile against diskutil's independent container size/free-byte controls.
// Pending frees remain allocated in the product's conservative report; diskutil
// includes them in APFSContainerFree and deducts configured volume reserves.
// Historical and checkpoint owners must stay protected, and successful
// accounting never grants writer admission.
func TestStorageAccountingMatchesNativeAllocation(t *testing.T) {
	cases := storageCases(t, map[string]map[string][]string{
		"file-corpus":           {"apfs": {"final"}, "apfsx": {"final"}},
		"snapshot-history":      snapshotStages,
		"apfs-mutation-sources": {"apfs": {"source", "peak", "final", "catalog", "catalog-final"}, "apfsx": {"source", "peak", "final", "catalog", "catalog-final"}},
		"container-volumes":     {"apfs": {"final"}},
	})
	recipes := recipesByName(t)
	for _, k := range cases {
		t.Run(native.CaseKey(caseRef(k)), func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			storageImageUnchanged(t, k)
			img := openImage(t, ctx, k, recipes[k.Recipe])
			defer func() { _ = img.Close() }()
			part, _ := storagePartition(t, img)
			report, err := apfs.InspectStorage(ctx, part)
			if err != nil {
				t.Fatal(err)
			}
			if len(k.Observation.Volumes) == 0 {
				t.Fatal("native allocation control has no volumes")
			}
			inventory, err := fixture.APFSInventory(k.Observation)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.EqualFold(report.ContainerUUID, inventory[0].APFS.ContainerUUID) {
				t.Errorf("accounting container UUID %s, native %s", report.ContainerUUID, inventory[0].APFS.ContainerUUID)
			}
			var snapshots uint64
			var reserved uint64
			for _, volume := range k.Observation.Volumes {
				if volume.APFS != nil {
					reserved += uint64(volume.APFS.ReserveBytes)
				}
			}
			for _, volume := range k.Observation.Volumes {
				if volume.APFS == nil || volume.APFS.Encrypted {
					t.Fatal("plaintext accounting control contains a non-plaintext APFS volume")
				}
				snapshots += uint64(len(volume.APFS.Snapshots))
				size := uint64(number(volume.Diskutil["APFSContainerSize"]))
				free := uint64(number(volume.Diskutil["APFSContainerFree"]))
				blockSize := uint64(number(volume.Diskutil["VolumeAllocationBlockSize"]))
				if size == 0 || free == 0 || blockSize == 0 || uint64(report.BlockSize) != blockSize || report.Blocks*blockSize != size || (report.FreeBlocks+report.PendingFreeBlocks)*blockSize != free+reserved {
					t.Errorf("native size/free/block bytes %d/%d/%d, accounting %+v", size, free, blockSize, report)
				}
			}
			if report.Volumes != len(k.Observation.Volumes) || report.Snapshots != snapshots || report.Transaction == 0 || report.ContainerUUID == "" || report.RetainedCheckpoints < 1 || report.FreeBlocks > report.Blocks || report.ProtectedBlocks == 0 || report.ProtectedBlocks > report.Blocks-report.FreeBlocks || report.CheckpointProtectedBlocks > report.ProtectedBlocks || report.PendingFreeBlocks > report.Blocks-report.FreeBlocks {
				t.Errorf("accounting failed volume/history/protection invariants: %+v; native volumes %d, snapshots %d", report, len(k.Observation.Volumes), snapshots)
			}
			if xid := k.Observation.Checks.SelectedXID; xid != 0 && uint64(report.Transaction) != xid {
				t.Errorf("selected transaction %d, native checker %d", report.Transaction, xid)
			}
		})
	}
}

// TestSnapshotReadersKeepTheirHistoricalOwnership opens live and every retained
// historical value together, then interleaves reads of the same native object
// IDs across different contents. Name/XID selectors must agree, absent history
// must never fall back to live contents, and one value's Close leaves peers open.
func TestSnapshotReadersKeepTheirHistoricalOwnership(t *testing.T) {
	cases := storageCases(t, map[string]map[string][]string{"snapshot-history": snapshotStages})
	recipes := recipesByName(t)
	for _, k := range cases {
		t.Run(native.CaseKey(caseRef(k)), func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			storageImageUnchanged(t, k)
			_, reader, closeImage := openSingleVolume(t, ctx, k, recipes[k.Recipe])
			defer closeImage()
			live, ok := reader.(*apfs.Volume)
			if !ok || len(k.Observation.Volumes) != 1 || k.Observation.Volumes[0].APFS == nil {
				t.Fatal("snapshot control is not a single APFS volume")
			}
			snapshots := k.Observation.Volumes[0].APFS.Snapshots
			if len(snapshots) == 0 {
				t.Fatal("snapshot control has no retained history")
			}
			for _, name := range []string{"missing-native-snapshot", strconv.FormatUint(snapshots[0].XID, 10), strings.ToUpper(snapshots[0].Name)} {
				if r, err := live.OpenSnapshotName(ctx, name); r != nil || !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("missing exact snapshot %q returned reader %v: %v", name, r, err)
				}
			}
			for _, xid := range []apfs.XID{0, ^apfs.XID(0)} {
				if r, err := live.OpenSnapshot(ctx, xid); r != nil || !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("missing snapshot XID %d returned reader %v: %v", xid, r, err)
				}
			}
			views := map[string]filesystem.Reader{"": live}
			observed := append([]schema.View(nil), k.Observation.Views...)
			for _, snapshot := range snapshots {
				byName, err := live.OpenSnapshotName(ctx, snapshot.Name)
				if err != nil {
					t.Fatal(err)
				}
				byXID, err := live.OpenSnapshot(ctx, apfs.XID(snapshot.XID))
				if err != nil {
					t.Fatal(err)
				}
				for _, r := range []filesystem.Reader{byName, byXID} {
					node, err := r.Stat(ctx, r.Root())
					if err != nil || node.Identity.Volume != strings.ToUpper(k.Observation.Volumes[0].APFS.VolumeUUID) || node.Identity.View != snapshot.XID {
						t.Fatalf("snapshot %s lost its native volume/transaction identity: %+v: %v", snapshot.Name, node.Identity, err)
					}
				}
				views[snapshot.Name] = byName
				// Hold the XID-selected values alongside the name-selected values,
				// so agreeing root identities alone cannot hide a selector error.
				for _, view := range k.Observation.Views {
					if view.Snapshot == snapshot.Name {
						view.Snapshot += "/by-xid"
						views[view.Snapshot] = byXID
						observed = append(observed, view)
					}
				}
			}
			if len(snapshots) > 1 {
				for _, path := range []string{"Fixture/example.txt", "Fixture/clone.bin"} {
					digests := map[string]bool{}
					for _, view := range k.Observation.Views {
						for _, entry := range view.Entries {
							if entry.Path == path {
								digests[entry.SHA256] = true
							}
						}
					}
					if len(digests) < 2 {
						t.Fatalf("native history lacks competing contents for %s", path)
					}
				}
			}
			checkInterleavedHistory(t, ctx, observed, views)
		})
	}
}

func checkInterleavedHistory(t *testing.T, ctx context.Context, observed []schema.View, readers map[string]filesystem.Reader) {
	t.Helper()
	type opened struct {
		label string
		value filesystem.Value
		sum   string
		h     hash.Hash
		off   int64
	}
	var values []opened
	allPaths := map[string]bool{}
	for _, view := range observed {
		for _, entry := range view.Entries {
			allPaths[entry.Path] = true
		}
	}
	for _, view := range observed {
		reader, ok := readers[view.Snapshot]
		if !ok {
			t.Fatalf("native view %q has no selected reader", view.Snapshot)
		}
		present := map[string]bool{}
		for _, entry := range view.Entries {
			present[entry.Path] = true
			if entry.Path != "Fixture/example.txt" && entry.Path != "Fixture/clone.bin" {
				continue
			}
			id, err := filesystem.LookupExact(ctx, reader, entry.Path)
			if err != nil || id != entry.ID {
				t.Fatalf("%s/%s: object %d, native %d: %v", view.Snapshot, entry.Path, id, entry.ID, err)
			}
			value, err := reader.OpenData(ctx, id)
			if err != nil || value.Size() != entry.Size {
				t.Fatalf("%s/%s: open native size %d: %v", view.Snapshot, entry.Path, entry.Size, err)
			}
			t.Cleanup(func() { _ = value.Close() })
			values = append(values, opened{label: view.Snapshot + "/" + entry.Path, value: value, sum: entry.SHA256, h: sha256.New()})
		}
		for path := range allPaths {
			if !present[path] {
				if _, err := filesystem.LookupExact(ctx, reader, path); !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("snapshot %q leaked absent native path %s: %v", view.Snapshot, path, err)
				}
			}
		}
	}
	if len(values) != 2*len(observed) {
		t.Fatalf("historical controls need both competing values in every view, opened %d for %d views", len(values), len(observed))
	}
	var buf [4093]byte
	for remaining := len(values); remaining > 0; {
		remaining = 0
		for i := len(values) - 1; i >= 0; i-- {
			v := &values[i]
			if v.off == v.value.Size() {
				continue
			}
			n := min(int64(len(buf)), v.value.Size()-v.off)
			if err := block.ReadFull(v.value, buf[:n], v.off); err != nil {
				t.Fatalf("interleaved %s at %d: %v", v.label, v.off, err)
			}
			_, _ = v.h.Write(buf[:n])
			v.off += n
			remaining++
		}
	}
	for _, value := range values {
		if got := hex.EncodeToString(value.h.Sum(nil)); got != value.sum {
			t.Errorf("interleaved %s: digest %s, native %s", value.label, got, value.sum)
		}
	}
	if err := values[0].value.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := values[0].value.ReadAt(buf[:1], 0); !errors.Is(err, fs.ErrClosed) {
		t.Errorf("closed historical value remains readable: %v", err)
	}
	for _, value := range values[1:] {
		if err := block.ReadFull(value.value, buf[:1], 0); err != nil {
			t.Errorf("closing another value invalidated %s: %v", value.label, err)
		}
	}
}

// TestHistoryAndEncryptedWritersRefuseWithoutPublication checks both the
// low-level zero-write boundary and the public image editor's publication
// contract. These controls have snapshots or encryption; they do not isolate
// the separate plaintext clone-only writer boundary.
func TestHistoryAndEncryptedWritersRefuseWithoutPublication(t *testing.T) {
	cases := storageCases(t, map[string]map[string][]string{
		"snapshot-history":  snapshotStages,
		"encrypted-volumes": {"apfs": encryptedVolumeStages, "apfsx": encryptedVolumeStages},
	})
	recipes := recipesByName(t)
	for _, k := range cases {
		t.Run(native.CaseKey(caseRef(k)), func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			storageImageUnchanged(t, k)
			img := openImage(t, ctx, k, recipes[k.Recipe])
			defer func() { _ = img.Close() }()
			part, index := storagePartition(t, img)
			source := &physicalReads{Source: part}
			container, err := apfs.Open(source)
			if err != nil || len(container.Volumes) == 0 {
				t.Fatalf("open refusal control: %v", err)
			}
			changes := []apfs.Change{{Path: "/Fixture/clone", Data: bytes.NewReader([]byte("refused edit"))}}
			report, err := apfs.ModifyVolume(ctx, source, container.Volumes[0].UUID, changes, fixedClock)
			if !errors.Is(err, filesystem.ErrUnsupported) || source.writes != 0 || !reflect.DeepEqual(report, apfs.ChangeReport{}) {
				t.Errorf("history/encryption mutation was not refused before writing: %+v, %d writes: %v", report, source.writes, err)
			}
			if k.Recipe == "encrypted-volumes" {
				accounting, err := apfs.InspectStorage(ctx, source)
				if !errors.Is(err, filesystem.ErrUnsupported) || accounting != (apfs.StorageReport{}) {
					t.Errorf("encrypted ownership produced a usable accounting report: %+v: %v", accounting, err)
				}
			}
			dir := t.TempDir()
			out := filepath.Join(dir, "refused.dmg")
			options := imageedit.Options{Partition: index, Volume: container.Volumes[0].UUID, Format: "UDZO", Time: fixedClock}
			wantRefusal := filesystem.ErrUnsupported
			if k.Observation.Image.Encryption != nil {
				wantRefusal = filesystem.ErrAuthentication
			}
			if _, err = imageedit.Apply(ctx, k.Image(), out, options, changes); !errors.Is(err, wantRefusal) {
				t.Errorf("public history/encryption edit did not refuse: %v", err)
			}
			if _, err = os.Lstat(out); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("refused edit published a destination: %v", err)
			}
			if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
				t.Errorf("refused edit retained publication scratch: %v: %v", entries, err)
			}
			sentinel := []byte("existing destination must survive")
			if err = os.WriteFile(out, sentinel, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err = imageedit.Apply(ctx, k.Image(), out, options, changes); !errors.Is(err, fs.ErrExist) {
				t.Errorf("existing destination was not rejected: %v", err)
			}
			if got, err := os.ReadFile(out); err != nil || !bytes.Equal(got, sentinel) {
				t.Errorf("refused edit changed the existing destination: %v", err)
			}
		})
	}
}
