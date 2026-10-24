package acceptance_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
	"github.com/deploymenttheory/go-apfs-v3/inspect"
	"github.com/deploymenttheory/go-apfs-v3/pack"
	"github.com/deploymenttheory/go-apfs-v3/session"
)

// TestConstructedContainersMatchNativeVolumes makes fresh allocation trees from
// every retained multi-volume and System/Data source. Each source Fixture is a
// new volume root. All metadata clocks, forks, attributes and hard-link groups
// are preserved; container/volume/group and object identities are freshly built.
func TestConstructedContainersMatchNativeVolumes(t *testing.T) {
	cases, _ := loadCorpus(t)
	recipes := recipesByName(t)
	seen := map[string]bool{}
	for _, k := range cases {
		if (k.Recipe != "container-volumes" && k.Recipe != "volume-groups") || k.Stage != "final" {
			continue
		}
		key := fmt.Sprintf("macos-%d/%s", k.Producer, k.Recipe)
		if seen[key] || k.Profile != "apfs" {
			t.Fatalf("ambiguous native construction source %s/%s", key, k.Profile)
		}
		seen[key] = true
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			img := openImage(t, ctx, k, recipes[k.Recipe])
			defer func() { closeFixture(t, img) }()
			checkSource := func() {
				t.Helper()
				if got, n := hashReaderAt(img, img.Size()); got != k.Observation.Image.DiskSHA256 || n != k.Observation.Image.DiskBytes {
					t.Fatalf("native source bytes changed: %s (%d bytes), expected %s (%d bytes)", got, n, k.Observation.Image.DiskSHA256, k.Observation.Image.DiskBytes)
				}
			}
			checkSource()
			defer checkSource()
			inventory, err := fixture.APFSInventory(k.Observation)
			if err != nil {
				t.Fatal(err)
			}
			report, err := inspect.Image(ctx, img)
			if err != nil {
				t.Fatal(err)
			}
			var volumes []apfs.VolumeSpec
			options := pack.ContainerOptions{APFS: apfs.ContainerBuildOptions{Time: fixedClock, Capacity: 768 << 20}, FileCompression: "preserve"}
			groups := map[string]apfs.VolumeGroupSpec{}
			for i, observed := range inventory {
				name := observed.Diskutil["VolumeName"].(string)
				reader, closeReader := openVolume(t, ctx, report, observed, name, recipes[k.Recipe], img)
				if closeReader != nil {
					defer closeReader()
				}
				root, err := filesystem.LookupExact(ctx, reader, "Fixture")
				if err != nil {
					t.Fatal(name, ":", err)
				}
				role := constructionRole(t, observed.APFS.Role)
				volumes = append(volumes, apfs.VolumeSpec{Reader: buildRoot{reader, root}, Name: name, CaseSensitive: observed.APFS.CaseSensitive, Role: role, Reserve: observed.APFS.ReserveBytes, Quota: observed.APFS.QuotaBytes})
				if id := observed.APFS.GroupUUID; id != "" {
					g, exists := groups[id]
					if !exists {
						g.System, g.Data = -1, -1
					}
					switch role {
					case apfs.VolumeRoleSystem:
						g.System = i
					case apfs.VolumeRoleData:
						g.Data = i
					default:
						t.Fatal("native group member has no System/Data role")
					}
					groups[id] = g
				}
			}
			for _, g := range groups {
				if g.System < 0 || g.Data < 0 {
					t.Fatal("native inventory has an incomplete System/Data group")
				}
				options.APFS.Groups = append(options.APFS.Groups, g)
			}
			expect := schema.Expectation{Subtree: "Fixture", Codesign: []string{"Example.app"}, Container: &schema.ContainerExpectation{CapacityBytes: options.APFS.Capacity}}
			if k.Recipe == "container-volumes" {
				// The captured volume named Empty contains allocation-pressure
				// files by the final observation. Add a genuinely empty input.
				empty, err := session.Create(ctx, filepath.Join(t.TempDir(), "empty-volume"), session.Options{Names: filesystem.NameRules{Format: "APFS", NormalizationInsensitive: true}, UID: 501, GID: 20, Time: &fixedClock})
				if err != nil {
					t.Fatal(err)
				}
				defer func() { closeFixture(t, empty) }()
				volumes = append(volumes, apfs.VolumeSpec{Reader: empty, Name: "Fresh Empty"})
				options.APFS.Capacity = 1600 << 20
				expect.Container.CapacityBytes = options.APFS.Capacity
				expect.Container.EmptyVolumes = []string{"Fresh Empty"}
				expect.Volume = "Reserved"
			} else {
				if len(groups) != 1 {
					t.Fatalf("System/Data construction has %d native groups", len(groups))
				}
				expect.SystemMember = "System"
			}
			layout, err := apfs.PlanContainer(ctx, volumes, options.APFS)
			if err != nil || layout.Size() != options.APFS.Capacity {
				t.Fatalf("native-input container plan: %v (%v)", layout, err)
			}
			checkContainerPublicationControls(t, ctx, k, volumes, options)
			for _, format := range []string{"UDRO", "UDZO"} {
				options.Format = format
				name := outputName(k, "container."+format+".dmg")
				var built pack.ContainerReport
				path := produceTwice(t, name, true, func(p string) error {
					var err error
					if format == "UDRO" {
						// Exercise the caller-owned streaming API as well as the
						// complete-output publication API used for UDZO below.
						out, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
						if err != nil {
							return err
						}
						built, err = pack.WriteContainer(ctx, out, volumes, options)
						return errors.Join(err, out.Close())
					}
					built, err = pack.CreateContainer(ctx, p, volumes, options)
					return err
				})
				info, err := os.Stat(path)
				if err != nil || built.Format != format || built.VolumeCount != len(volumes) || built.ContainerBytes != options.APFS.Capacity || built.FileCompression != "preserve" || built.ImageBytes != info.Size() || built.Encryption != nil {
					t.Fatalf("construction report %+v, stat %v (%v)", built, info, err)
				}
				checkConstructedContainer(t, ctx, path, k, inventory, volumes, options.APFS)
				expect.Continuation = format == "UDZO"
				if k.Recipe == "volume-groups" && expect.Continuation {
					// Native allocation on System is qualified. Existing-image
					// mutation still explicitly refuses nonzero APFS roles.
					expect.ContinuationRefusal = "APFS volume mutation profile: unsupported feature"
					groupImage, err := diskimage.Open(path)
					if err != nil {
						t.Fatal(err)
					}
					groupReport, err := inspect.Image(ctx, groupImage)
					if err != nil {
						closeFixture(t, groupImage)
						t.Fatal(err)
					}
					var systemUUID string
					for _, volume := range groupReport.Partitions[0].APFS.Volumes {
						if volume.Name == "System" {
							systemUUID = volume.UUID
						}
					}
					if err := groupImage.Close(); err != nil || systemUUID == "" {
						t.Fatalf("selecting built System volume: %v", err)
					}
					refused := filepath.Join(t.TempDir(), "group-edit.dmg")
					_, err = imageedit.Edit(ctx, path, refused, imageedit.Options{Volume: systemUUID, Format: "UDZO", Time: fixedClock}, func(*imageedit.Editor) error {
						t.Fatal("role-bearing mutation reached the edit callback")
						return nil
					})
					if !errors.Is(err, filesystem.ErrUnsupported) {
						t.Fatalf("System/Data edit must retain its typed role refusal: %v", err)
					}
					if _, err := os.Lstat(refused); !errors.Is(err, fs.ErrNotExist) {
						t.Fatalf("role refusal published an output: %v", err)
					}
				}
				recordOutput(t, schema.Output{Name: name, File: filepath.Base(path), Operation: "container", Format: format, Source: caseRef(k), Expect: expect})
			}
		})
	}
	for _, producer := range schema.Producers {
		for _, recipe := range []string{"container-volumes", "volume-groups"} {
			if !seen[fmt.Sprintf("macos-%d/%s", producer, recipe)] {
				t.Errorf("no native construction input for macOS %d/%s", producer, recipe)
			}
		}
	}
}

func constructionRole(t *testing.T, role string) uint16 {
	t.Helper()
	switch role {
	case "":
		return apfs.VolumeRoleNone
	case "System":
		return apfs.VolumeRoleSystem
	case "Data":
		return apfs.VolumeRoleData
	default:
		t.Fatalf("native construction role %q is outside the admitted roles", role)
		return 0
	}
}

func checkConstructedContainer(t *testing.T, ctx context.Context, path string, k corpus.Case, inventory []schema.Volume, inputs []apfs.VolumeSpec, options apfs.ContainerBuildOptions) {
	t.Helper()
	img, err := diskimage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { closeFixture(t, img) }()
	report, err := inspect.Image(ctx, img)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Partitions) != 1 || report.Partitions[0].APFS == nil {
		t.Fatalf("fresh image must contain exactly one APFS container: %+v", report)
	}
	c := report.Partitions[0].APFS
	if int64(c.BlockSize)*int64(c.BlockCount) != options.Capacity || len(c.Volumes) != len(inputs) {
		t.Fatalf("constructed container geometry or volume count differs: %+v", c)
	}
	nativeIDs := map[string]bool{}
	for _, v := range inventory {
		nativeIDs[strings.ToUpper(v.APFS.VolumeUUID)] = true
		nativeIDs[strings.ToUpper(v.APFS.ContainerUUID)] = true
		if v.APFS.GroupUUID != "" {
			nativeIDs[strings.ToUpper(v.APFS.GroupUUID)] = true
		}
	}
	seenIDs := map[string]bool{}
	checkFresh := func(id string) {
		t.Helper()
		if id == "" || id == "00000000-0000-0000-0000-000000000000" || nativeIDs[id] || seenIDs[id] {
			t.Errorf("fresh construction reused or omitted identity %q", id)
		}
		seenIDs[id] = true
	}
	checkFresh(c.UUID)
	for i := range c.Volumes {
		v, in := &c.Volumes[i], inputs[i]
		checkFresh(v.UUID)
		if v.Name != in.Name || v.CaseSensitive != in.CaseSensitive || v.Role != in.Role || int64(v.ReserveBlocks)*int64(c.BlockSize) != in.Reserve || int64(v.QuotaBlocks)*int64(c.BlockSize) != in.Quota || v.Encrypted || v.Sealed || v.Snapshots != 0 {
			t.Errorf("volume %d construction metadata differs: %+v, input %+v", i, v, in)
		}
		if i >= len(inventory) {
			if err := v.ReadDir(ctx, v.Root(), func(e filesystem.DirEntry) error { return fmt.Errorf("fresh empty volume enumerates %q", e.Name) }); err != nil {
				t.Error(err)
			}
			continue
		}
		var views []schema.View
		for _, view := range k.Observation.Views {
			if view.Volume == inventory[i].Index && view.Snapshot == "" {
				views = append(views, view)
			}
		}
		if len(views) != 1 {
			t.Fatalf("volume %s has %d native live views", v.Name, len(views))
		}
		compareViewWith(t, ctx, filepath.Base(path)+":"+v.Name, v, views[0], compareOptions{subtree: "Fixture"})
		checkConstructedLinkGroups(t, ctx, v, views[0])
		if err := v.ReadDir(ctx, v.Root(), func(e filesystem.DirEntry) error {
			node, err := v.Stat(ctx, e.Object)
			if err != nil {
				return err
			}
			if node.Identity.Volume != v.UUID {
				t.Errorf("volume %s entry %s belongs to UUID %s", v.Name, e.Name, node.Identity.Volume)
			}
			if v.Role == apfs.VolumeRoleSystem && e.Object < 0x0fffffff00000000 {
				t.Errorf("System entry %s has object %d outside the native System namespace", e.Name, e.Object)
			}
			return nil
		}); err != nil {
			t.Error(err)
		}
	}
	grouped := map[int]bool{}
	for _, g := range options.Groups {
		system, data := &c.Volumes[g.System], &c.Volumes[g.Data]
		if system.VolumeGroup != data.VolumeGroup {
			t.Error("System/Data members have different group identities")
		}
		checkFresh(system.VolumeGroup)
		grouped[g.System], grouped[g.Data] = true, true
	}
	for i, v := range c.Volumes {
		if !grouped[i] && v.VolumeGroup != "00000000-0000-0000-0000-000000000000" {
			t.Errorf("ungrouped volume %s has group %s", v.Name, v.VolumeGroup)
		}
	}
}

// Object numbers change on a fresh build, but their equivalence classes must
// not: every native alias remains linked, and distinct native objects stay so.
func checkConstructedLinkGroups(t *testing.T, ctx context.Context, reader filesystem.Reader, view schema.View) {
	t.Helper()
	forward, reverse := map[uint64]uint64{}, map[uint64]uint64{}
	for _, entry := range view.Entries {
		if !strings.HasPrefix(entry.Path, "Fixture/") {
			continue
		}
		id, err := filesystem.LookupExact(ctx, reader, strings.TrimPrefix(entry.Path, "Fixture/"))
		if err != nil {
			t.Error(err)
			continue
		}
		if other, ok := forward[entry.ID]; ok && other != id {
			t.Errorf("native hard-link group split at %s", entry.Path)
		}
		if other, ok := reverse[id]; ok && other != entry.ID {
			t.Errorf("distinct native objects merged at %s", entry.Path)
		}
		forward[entry.ID], reverse[id] = id, entry.ID
	}
}

func checkContainerPublicationControls(t *testing.T, ctx context.Context, k corpus.Case, inputs []apfs.VolumeSpec, options pack.ContainerOptions) {
	t.Helper()
	type control struct {
		name   string
		change func([]apfs.VolumeSpec, *pack.ContainerOptions)
		want   error
	}
	controls := []control{
		{"insufficient-volume-slots", func(_ []apfs.VolumeSpec, o *pack.ContainerOptions) { o.APFS.Capacity = 512 << 20 }, filesystem.ErrLimit},
		{"quota-below-native-payload", func(v []apfs.VolumeSpec, _ *pack.ContainerOptions) { v[0].Reserve, v[0].Quota = 0, 4096 }, filesystem.ErrLimit},
		{"reservations-exceed-capacity", func(v []apfs.VolumeSpec, o *pack.ContainerOptions) { v[0].Reserve, v[0].Quota = o.APFS.Capacity, 0 }, filesystem.ErrLimit},
		{"duplicate-volume-identity", func(v []apfs.VolumeSpec, _ *pack.ContainerOptions) { v[0].UUID[0], v[1].UUID[0] = 1, 1 }, filesystem.ErrConflict},
		{"source-read-failure", func(v []apfs.VolumeSpec, _ *pack.ContainerOptions) {
			v[0].Reader = failedContainerSource{Reader: v[0].Reader}
		}, errContainerSource},
	}
	if len(options.APFS.Groups) != 0 {
		controls = append(controls, control{"unpaired-system", func(_ []apfs.VolumeSpec, o *pack.ContainerOptions) { o.APFS.Groups = nil }, fs.ErrInvalid})
	}
	for _, tc := range controls {
		t.Run(tc.name, func(t *testing.T) {
			volumes, o := append([]apfs.VolumeSpec(nil), inputs...), options
			tc.change(volumes, &o)
			dir := t.TempDir()
			path := filepath.Join(dir, "refused.dmg")
			_, err := pack.CreateContainer(ctx, path, volumes, o)
			if !errors.Is(err, tc.want) {
				t.Errorf("%s/%s: got %v, expected %v", k.Recipe, tc.name, err, tc.want)
			}
			if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
				t.Errorf("failed construction published output or left scratch: %v (%v)", entries, err)
			}
		})
	}
	t.Run("existing-destination", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "existing.dmg")
		const sentinel = "existing image must survive failed publication"
		if err := os.WriteFile(path, []byte(sentinel), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := pack.CreateContainer(ctx, path, inputs, options); !errors.Is(err, fs.ErrExist) {
			t.Errorf("existing destination: %v", err)
		}
		if got, err := os.ReadFile(path); err != nil || string(got) != sentinel {
			t.Errorf("existing destination changed: %q (%v)", got, err)
		}
		if entries, err := os.ReadDir(dir); err != nil || len(entries) != 1 {
			t.Errorf("existing-destination refusal left scratch: %v (%v)", entries, err)
		}
	})
	t.Run("stream-write-failure", func(t *testing.T) {
		if _, err := pack.WriteContainer(ctx, failedContainerWriter{}, inputs, options); !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("stream failure: %v", err)
		}
	})
}

var errContainerSource = errors.New("native construction input read failed")

type failedContainerSource struct{ filesystem.Reader }

func (failedContainerSource) OpenRawData(context.Context, uint64) (filesystem.Value, error) {
	return nil, errContainerSource
}

type failedContainerWriter struct{}

func (failedContainerWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
