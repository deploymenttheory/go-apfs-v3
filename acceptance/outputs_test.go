package acceptance_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
	"github.com/deploymenttheory/go-apfs-v3/inspect"
	"github.com/deploymenttheory/go-apfs-v3/pack"
)

// fixedClock is the build and edit clock every host uses, so plaintext
// outputs can be byte-identical across Linux, Windows and macOS.
var fixedClock = time.Date(2025, 6, 7, 8, 9, 10, 0, time.UTC)

// outputPassword is the public password every encrypted output uses.
const outputPassword = "public-output-λ-\U0001f600"

var (
	outputsMu   sync.Mutex
	outputsList []schema.Output
	outputsRoot string
	outputsOnce sync.Once
	// Only public fixture passwords belong in the acceptance output manifest.
	outputPasswords = map[string]string{"output": outputPassword}
)

func registerOutputPassword(t *testing.T, ref, value string) {
	t.Helper()
	outputsMu.Lock()
	defer outputsMu.Unlock()
	if ref == "" {
		t.Fatal("empty public output password reference")
	}
	if previous, exists := outputPasswords[ref]; exists && previous != value {
		t.Fatalf("conflicting public output password reference %q", ref)
	}
	outputPasswords[ref] = value
}

// outputDir is where produced images are written. With APFS_OUTPUT_DIR set
// the images and outputs.json are retained for the native verifier;
// otherwise a temporary directory is used and only determinism is checked.
func outputDir(t *testing.T) string {
	t.Helper()
	outputsOnce.Do(func() {
		outputsRoot = os.Getenv("APFS_OUTPUT_DIR")
		if outputsRoot == "" {
			dir, err := os.MkdirTemp("", "apfs-outputs-")
			if err != nil {
				panic(err)
			}
			outputsRoot = dir
			return
		}
		if err := os.MkdirAll(outputsRoot, 0o755); err != nil {
			panic(err)
		}
	})
	return outputsRoot
}

func recordOutput(t *testing.T, out schema.Output) {
	t.Helper()
	sum, err := schema.FileDigest(filepath.Join(outputDir(t), out.File))
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(outputDir(t), out.File))
	if err != nil {
		t.Fatal(err)
	}
	out.SHA256, out.Bytes = sum, info.Size()
	outputsMu.Lock()
	defer outputsMu.Unlock()
	if out.Encrypted {
		if _, ok := outputPasswords[out.Password]; !ok {
			t.Fatalf("encrypted output %s has an unregistered public password reference %q", out.Name, out.Password)
		}
	}
	outputsList = append(outputsList, out)
}

// TestMain writes outputs.json after every test has run.
func TestMain(m *testing.M) {
	code := m.Run()
	if corpusValue != nil {
		if err := corpusValue.Close(); err != nil {
			fmt.Fprintln(os.Stderr, "fixture images:", err)
			code = 1
		}
	}
	if dir := os.Getenv("APFS_OUTPUT_DIR"); dir != "" && len(outputsList) > 0 {
		sort.Slice(outputsList, func(i, j int) bool { return outputsList[i].Name < outputsList[j].Name })
		lock, _ := schema.FileDigest(filepath.Join("fixtures.lock.json"))
		manifest := schema.Outputs{Schema: schema.OutputsSchema, Host: runtime.GOOS, Arch: runtime.GOARCH, Go: runtime.Version(), Commit: os.Getenv("GITHUB_SHA"), Lock: lock, Passwords: outputPasswords, Outputs: outputsList}
		data, err := json.MarshalIndent(manifest, "", "  ")
		if err == nil {
			err = os.WriteFile(filepath.Join(dir, "outputs.json"), append(data, '\n'), 0o644)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "outputs.json:", err)
			if code == 0 {
				code = 1
			}
		}
	}
	if os.Getenv("APFS_OUTPUT_DIR") == "" && outputsRoot != "" {
		if err := os.RemoveAll(outputsRoot); err != nil {
			fmt.Fprintln(os.Stderr, "temporary outputs:", err)
			code = 1
		}
	}
	os.Exit(code)
}

func caseRef(k corpus.Case) schema.CaseRef {
	return schema.CaseRef{Producer: k.Producer, Recipe: k.Recipe, Profile: k.Profile, Stage: k.Stage}
}

func outputName(k corpus.Case, suffix string) string {
	return fmt.Sprintf("macos-%d.%s.%s.%s.%s", k.Producer, k.Recipe, k.Profile, k.Stage, suffix)
}

// buildRoot presents a subtree of a reader as a root for construction.
type buildRoot struct {
	filesystem.Reader
	id uint64
}

func (r buildRoot) Root() uint64 { return r.id }

// openSingleVolume opens a case's image and returns its only volume's
// reader. Multi-volume cases use openVolume by name.
func openSingleVolume(t *testing.T, ctx context.Context, k corpus.Case, recipe schema.Recipe) (*diskimage.Image, filesystem.Reader, func()) {
	t.Helper()
	img := openImage(t, ctx, k, recipe)
	report, err := inspect.Image(ctx, img)
	if err != nil {
		closeFixture(t, img)
		t.Fatalf("inspect: %v", err)
	}
	vol := k.Observation.Volumes[0]
	name, _ := vol.Diskutil["VolumeName"].(string)
	reader, closer := openVolume(t, ctx, report, vol, name, recipe, img)
	return img, reader, func() {
		if closer != nil {
			closer()
		}
		closeFixture(t, img)
	}
}

// produceTwice runs a producer into two files and requires identical bytes
// when deterministic; it returns the first file's path. In CI the repeat
// is skipped: the native tier requires every output to be byte-identical
// on Linux, Windows and macOS (and every encrypted output to differ),
// which covers what a same-process repeat checks and more.
func produceTwice(t *testing.T, name string, deterministic bool, produce func(path string) error) string {
	t.Helper()
	dir := outputDir(t)
	first := filepath.Join(dir, name)
	second := filepath.Join(dir, name+".repeat")
	_ = os.Remove(first)
	_ = os.Remove(second)
	if err := produce(first); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		return first
	}
	if err := produce(second); err != nil {
		t.Fatalf("%s (repeat): %v", name, err)
	}
	a, _ := schema.FileDigest(first)
	b, _ := schema.FileDigest(second)
	_ = os.Remove(second)
	if deterministic && a != b {
		t.Errorf("%s: two builds with the same inputs and clock differ (%s vs %s)", name, a, b)
	}
	if !deterministic && a == b {
		t.Errorf("%s: two encrypted outputs are identical; random material is missing", name)
	}
	return first
}

// TestBuildFromFixtures constructs a fresh image from every fixture
// volume's Fixture subtree in both encodings and with every compression
// policy the fixture exercises. Builds are byte-identical on repeat and
// across hosts; the native tier mounts them and reads the tree back
// against the fixture's own observation.
func TestBuildFromFixtures(t *testing.T) {
	cases, _ := loadCorpus(t)
	recipes := recipesByName(t)
	for _, k := range cases {
		k := k
		if (k.Recipe != "file-corpus" && k.Recipe != "compressed-files") || k.Stage != "final" {
			continue
		}
		t.Run(fmt.Sprintf("macos-%d/%s/%s", k.Producer, k.Recipe, k.Profile), func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			img, reader, closer := openSingleVolume(t, ctx, k, recipes[k.Recipe])
			defer closer()
			_ = img
			root, err := filesystem.LookupExact(ctx, reader, "Fixture")
			if err != nil {
				t.Fatalf("Fixture: %v", err)
			}
			source := buildRoot{reader, root}
			policies := []string{"preserve"}
			if k.Recipe == "compressed-files" {
				// The tree carries decmpfs types 9 to 16 for the readers.
				// Preserving them is refused explicitly (docs/packing.md
				// admits types 1, 3, 4, 7 and 8); the other policies
				// re-encode or decode every file.
				policies = []string{"zlib", "none"}
				options := pack.Options{Format: "UDRO", FileCompression: "preserve", Volume: pack.VolumeOptions{Name: "Example", Time: fixedClock, CaseSensitive: reader.NameRules().CaseSensitive}}
				refused := filepath.Join(outputDir(t), outputName(k, "build.preserve.refused.dmg"))
				_, err := pack.Create(ctx, refused, source, options)
				_ = os.Remove(refused)
				if !errors.Is(err, filesystem.ErrUnsupported) || !preservedTypeOutsideAdmitted(err) {
					t.Errorf("preserving decmpfs types outside 1, 3, 4, 7 and 8 must be refused explicitly, got %v", err)
				}
			}
			for _, format := range []string{"UDRO", "UDZO"} {
				for _, policy := range policies {
					options := pack.Options{Format: format, FileCompression: policy, Volume: pack.VolumeOptions{Name: "Example", Time: fixedClock, CaseSensitive: reader.NameRules().CaseSensitive}}
					if reader.NameRules().CaseSensitive || continuesNatively(format, policy) {
						// Room for the native continuation's writes; an
						// automatically sized image is full by design.
						options.Volume.Capacity = 160 << 20
					}
					name := outputName(k, "build."+policy+"."+format+".dmg")
					path := produceTwice(t, name, true, func(p string) error {
						_, err := pack.Create(ctx, p, source, options)
						return err
					})
					checkBuiltImage(t, ctx, path, k, "Fixture", policy)
					recordOutput(t, schema.Output{Name: name, File: filepath.Base(path), Operation: "build", Format: format, Source: caseRef(k), Expect: schema.Expectation{Subtree: "Fixture", Codesign: builtBundles(k), Continuation: continuesNatively(format, policy), FileCompression: explicitPolicy(policy)}})
				}
			}
			if k.Recipe == "file-corpus" && (k.Profile == "apfs" || k.Profile == "hfsplus") {
				for _, bits := range []uint32{128, 256} {
					options := pack.Options{Format: "UDZO", Encryption: &diskimage.EncryptionOptions{KeyBits: bits, Password: []byte(outputPassword)}, Volume: pack.VolumeOptions{Name: "Example", Time: fixedClock, CaseSensitive: reader.NameRules().CaseSensitive}}
					name := outputName(k, fmt.Sprintf("build.encrypted-%d.UDZO.dmg", bits))
					path := produceTwice(t, name, false, func(p string) error {
						_, err := pack.Create(ctx, p, source, options)
						return err
					})
					if _, err := diskimage.Open(path); !errors.Is(err, filesystem.ErrAuthentication) {
						t.Errorf("%s: opened without a password: %v", name, err)
					}
					enc, err := diskimage.OpenWithPassword(ctx, path, []byte(outputPassword))
					if err != nil {
						t.Fatalf("%s: %v", name, err)
					}
					if enc.Encryption == nil || enc.Encryption.KeyBits != bits {
						t.Errorf("%s: encryption %+v", name, enc.Encryption)
					}
					closeFixture(t, enc)
					recordOutput(t, schema.Output{Name: name, File: filepath.Base(path), Operation: "encrypt", Format: "UDZO", Encrypted: true, Password: "output", Source: caseRef(k), Expect: schema.Expectation{Subtree: "Fixture", Codesign: builtBundles(k)}})
				}
			}
		})
	}
}

// continuesNatively selects the builds the native tier continues writing
// to: one compressed-image build per profile and storage policy that keeps
// compression. The continuation proves macOS can keep writing to Go's
// structures; repeating it for every encoding of the same tree proves
// nothing more.
func continuesNatively(format, policy string) bool {
	return format == "UDZO" && policy != "none"
}

// checkDecryptedDisk opens a produced encrypted image with the output
// password and requires its decoded disk to hash to want. Every host checks
// its own copies here; the native tier has Apple decrypt one host's copy
// of each output, rotating across hosts.
func checkDecryptedDisk(t *testing.T, ctx context.Context, path, want string) {
	t.Helper()
	img, err := diskimage.OpenWithPassword(ctx, path, []byte(outputPassword))
	if err != nil {
		t.Errorf("%s: open with the output password: %v", filepath.Base(path), err)
		return
	}
	defer func() { closeFixture(t, img) }()
	if got, _ := hashReaderAt(img, img.Size()); got != want {
		t.Errorf("%s: decrypted disk %s, want %s", filepath.Base(path), got, want)
	}
}

// explicitPolicy names a build's storage policy for the native verifier;
// preserve keeps the source's storage and needs no relaxation.
func explicitPolicy(policy string) string {
	if policy == "preserve" {
		return ""
	}
	return policy
}

// preservedTypeOutsideAdmitted reports whether a refusal names a decmpfs
// type the builders do not preserve.
func preservedTypeOutsideAdmitted(err error) bool {
	if err == nil {
		return false
	}
	text := err.Error()
	at := strings.Index(text, "compression type ")
	if at < 0 {
		return false
	}
	var kind int
	if _, scanErr := fmt.Sscanf(text[at:], "compression type %d", &kind); scanErr != nil {
		return false
	}
	switch kind {
	case 1, 3, 4, 7, 8:
		return false
	}
	return true
}

func builtBundles(k corpus.Case) []string {
	if k.Recipe != "file-corpus" {
		return nil
	}
	return []string{"Example.app", "Example.framework"}
}

// checkBuiltImage reads a build back with the product and requires the
// subtree it was built from, with identities and times excepted: a fresh
// build assigns its own object IDs and the fixed clock.
func checkBuiltImage(t *testing.T, ctx context.Context, path string, k corpus.Case, subtree, policy string) {
	t.Helper()
	img, err := diskimage.Open(path)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	defer func() { closeFixture(t, img) }()
	report, err := inspect.Image(ctx, img)
	if err != nil {
		t.Fatalf("%s: inspect: %v", path, err)
	}
	var reader filesystem.Reader
	for i := range report.Partitions {
		if report.Partitions[i].APFS != nil && len(report.Partitions[i].APFS.Volumes) > 0 {
			reader = &report.Partitions[i].APFS.Volumes[0]
		} else if report.Partitions[i].HFSPlus != nil {
			reader = report.Partitions[i].HFSPlus
		}
	}
	if reader == nil {
		t.Fatalf("%s: no filesystem", path)
	}
	opts := compareOptions{subtree: subtree, ignoreTimes: map[string]bool{"birth": true, "modify": true, "change": true, "access": true}}
	if policy != "preserve" {
		opts.compression = policy
	}
	compareViewWith(t, ctx, filepath.Base(path), reader, k.Observation.Views[0], opts)
}

// TestRepackPreservesEverySector repacks every retained image into both
// encodings and requires the decoded disk to hash to the digest the kernel
// reported for the attached device on the producing Mac.
func TestRepackPreservesEverySector(t *testing.T) {
	cases, _ := loadCorpus(t)
	recipes := recipesByName(t)
	for _, k := range cases {
		k := k
		if k.Observation.Image.DiskSHA256 == "" {
			continue
		}
		t.Run(fmt.Sprintf("macos-%d/%s/%s/%s", k.Producer, k.Recipe, k.Profile, k.Stage), func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			source := fixtureImage(t, k)
			enc := k.Observation.Image.Encryption
			view := ""
			if recovery := k.Observation.Recovery; recovery != nil {
				view = recovery.ExpectedStage
			}
			for _, format := range []string{"UDRO", "UDZO"} {
				name := outputName(k, "repack."+format+".dmg")
				var report pack.RepackReport
				path := produceTwice(t, name, true, func(p string) error {
					var err error
					if enc != nil {
						password := recipes[k.Recipe].Passwords[enc.Password]
						report, err = pack.RepackWithOptions(ctx, source, p, diskimage.RepackOptions{Format: format, SourcePassword: []byte(password), Decrypt: true})
					} else {
						report, err = pack.Repack(ctx, source, p, format)
					}
					return err
				})
				if report.DiskSHA256 != k.Observation.Image.DiskSHA256 || report.DiskBytes != k.Observation.Image.DiskBytes {
					t.Errorf("%s: repacked disk %s (%d bytes), native device %s (%d bytes)", name, report.DiskSHA256, report.DiskBytes, k.Observation.Image.DiskSHA256, k.Observation.Image.DiskBytes)
				}
				recordOutput(t, schema.Output{Name: name, File: filepath.Base(path), Operation: "repack", Format: format, Source: caseRef(k), Expect: schema.Expectation{View: view, DiskSHA256: k.Observation.Image.DiskSHA256}})
			}
			if enc == nil && strings.HasSuffix(source, ".dmg") {
				name := outputName(k, "repack.encrypted-256.UDZO.dmg")
				var report pack.RepackReport
				path := produceTwice(t, name, false, func(p string) error {
					var err error
					report, err = pack.RepackWithOptions(ctx, source, p, diskimage.RepackOptions{Format: "UDZO", Encryption: &diskimage.EncryptionOptions{KeyBits: 256, Password: []byte(outputPassword)}})
					return err
				})
				if report.DiskSHA256 != k.Observation.Image.DiskSHA256 {
					t.Errorf("%s: encrypted repack disk %s, native %s", name, report.DiskSHA256, k.Observation.Image.DiskSHA256)
				}
				checkDecryptedDisk(t, ctx, path, k.Observation.Image.DiskSHA256)
				recordOutput(t, schema.Output{Name: name, File: filepath.Base(path), Operation: "encrypt", Format: "UDZO", Encrypted: true, Password: "output", Source: caseRef(k), Expect: schema.Expectation{DiskSHA256: k.Observation.Image.DiskSHA256}})
			}
			if enc != nil {
				name := outputName(k, "repack.rewrapped-128.UDZO.dmg")
				password := recipes[k.Recipe].Passwords[enc.Password]
				var report pack.RepackReport
				path := produceTwice(t, name, false, func(p string) error {
					var err error
					report, err = pack.RepackWithOptions(ctx, source, p, diskimage.RepackOptions{Format: "UDZO", SourcePassword: []byte(password), Encryption: &diskimage.EncryptionOptions{KeyBits: 128, Password: []byte(outputPassword)}})
					return err
				})
				if report.DiskSHA256 != k.Observation.Image.DiskSHA256 {
					t.Errorf("%s: rewrapped disk %s, native %s", name, report.DiskSHA256, k.Observation.Image.DiskSHA256)
				}
				checkDecryptedDisk(t, ctx, path, k.Observation.Image.DiskSHA256)
				if _, err := diskimage.OpenWithPassword(ctx, path, []byte(password)); !errors.Is(err, filesystem.ErrAuthentication) {
					t.Errorf("%s: old password still unlocks the rewrapped image: %v", name, err)
				}
				recordOutput(t, schema.Output{Name: name, File: filepath.Base(path), Operation: "encrypt", Format: "UDZO", Encrypted: true, Password: "output", Source: caseRef(k), Expect: schema.Expectation{DiskSHA256: k.Observation.Image.DiskSHA256}})
			}
		})
	}
}

// TestRepackRefusesSignedAndLockedImages requires the refusal controls to
// refuse without publishing anything.
func TestRepackRefusesSignedAndLockedImages(t *testing.T) {
	cases, _ := loadCorpus(t)
	for _, k := range cases {
		k := k
		if k.Recipe != "partitioned-disks" || k.Stage != "signed" {
			continue
		}
		t.Run(fmt.Sprintf("macos-%d/%s", k.Producer, k.Profile), func(t *testing.T) {
			dst := filepath.Join(t.TempDir(), "refused.dmg")
			if _, err := pack.Repack(context.Background(), fixtureImage(t, k), dst, "UDZO"); !errors.Is(err, filesystem.ErrUnsupported) {
				t.Errorf("signed image repacked: %v", err)
			}
			if _, err := os.Stat(dst); err == nil {
				t.Error("refused repack published an output")
			}
		})
	}
	for _, k := range cases {
		k := k
		if k.Observation.Image.Encryption == nil {
			continue
		}
		t.Run(fmt.Sprintf("macos-%d/%s/%s/%s/locked", k.Producer, k.Recipe, k.Profile, k.Stage), func(t *testing.T) {
			dst := filepath.Join(t.TempDir(), "refused.dmg")
			if _, err := pack.Repack(context.Background(), fixtureImage(t, k), dst, "UDZO"); !errors.Is(err, filesystem.ErrUnsupported) {
				t.Errorf("encrypted image repacked without a credential: %v", err)
			}
			if _, err := os.Stat(dst); err == nil {
				t.Error("refused repack published an output")
			}
		})
	}
}

// editPattern is the byte source the edit replays write: the sequence
// pattern with a label, which is what the native stage wrote.
type editPattern struct {
	label string
	size  int64
}

func (p editPattern) cycle() []byte {
	var cycle []byte
	for i := 0; i < 256; i++ {
		cycle = append(cycle, byte(i))
	}
	return append(append(cycle, p.label...), '\n')
}

func (p editPattern) ReadAt(b []byte, off int64) (int, error) {
	if off >= p.size {
		return 0, io.EOF
	}
	cycle := p.cycle()
	n := 0
	for n < len(b) && off+int64(n) < p.size {
		b[n] = cycle[int((off+int64(n))%int64(len(cycle)))]
		n++
	}
	if off+int64(n) >= p.size && n < len(b) {
		return n, io.EOF
	}
	return n, nil
}

func (p editPattern) Size() int64 { return p.size }

// TestExistingImageEditsMatchAppleStates replays the native peak and final
// mutations with the product on the Apple-formatted source and requires
// the resulting volume to read back as the Apple-mutated stage does.
func TestExistingImageEditsMatchAppleStates(t *testing.T) {
	cases, _ := loadCorpus(t)
	byKey := map[string]corpus.Case{}
	for _, k := range cases {
		byKey[fmt.Sprintf("%d/%s/%s/%s", k.Producer, k.Recipe, k.Profile, k.Stage)] = k
	}
	phases := map[string][]filesystem.Change{
		"peak": {
			{Path: "/Fixture/alias", Data: editPattern{"grow", 20 << 20}},
			{Path: "/Fixture/small", Data: editPattern{"small", 7000}},
			{Path: "/Fixture/inline-compressed", Data: editPattern{"inline", 7000}},
			{Path: "/Fixture/resource-compressed", Data: editPattern{"resource", 100000}},
			{Operation: "chmod", Path: "/Fixture/small", Mode: "0755"},
		},
		"final": {
			{Path: "/Fixture/fragmented-data", Data: editPattern{"shrink", 513}},
			{Path: "/Fixture/fragmented-resource", ResourceFork: true, Data: editPattern{"fork", 131073}},
			{Path: "/Fixture/empty", Data: editPattern{"empty", 0}},
			{Path: "/Fixture/independent", Data: editPattern{"independent", 65537}},
		},
	}
	for _, k := range cases {
		k := k
		if (k.Recipe != "apfs-mutation-sources" && k.Recipe != "hfs-mutation-sources") || k.Stage != "source" {
			continue
		}
		t.Run(fmt.Sprintf("macos-%d/%s/%s", k.Producer, k.Recipe, k.Profile), func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			current := fixtureImage(t, k)
			for _, phase := range []string{"peak", "final"} {
				want, ok := byKey[fmt.Sprintf("%d/%s/%s/%s", k.Producer, k.Recipe, k.Profile, phase)]
				if !ok {
					t.Fatalf("corpus has no %s stage for this source", phase)
				}
				name := outputName(k, "edit."+phase+".UDZO.dmg")
				source := current
				path := produceTwice(t, name, true, func(p string) error {
					_, err := imageedit.Apply(ctx, source, p, imageedit.Options{Format: "UDZO", Time: fixedClock}, phases[phase])
					return err
				})
				checkEditedImage(t, ctx, path, want)
				recordOutput(t, schema.Output{Name: name, File: filepath.Base(path), Operation: "edit", Format: "UDZO", Source: caseRef(k), Expect: schema.Expectation{View: phase, IgnoreTimes: []string{"change", "access"}, Codesign: []string{"Fixture/Example.app", "Fixture/Example.framework"}, Continuation: phase == "final"}})
				current = path
			}
		})
	}
}

// checkEditedImage reads an edited image back and compares it with the
// Apple-mutated stage; identities must survive (the editor preserves
// them), and only change and access times may differ.
func checkEditedImage(t *testing.T, ctx context.Context, path string, want corpus.Case) {
	t.Helper()
	img, err := diskimage.Open(path)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	defer func() { closeFixture(t, img) }()
	report, err := inspect.Image(ctx, img)
	if err != nil {
		t.Fatalf("%s: inspect: %v", path, err)
	}
	var reader filesystem.Reader
	for i := range report.Partitions {
		if report.Partitions[i].APFS != nil && len(report.Partitions[i].APFS.Volumes) > 0 {
			reader = &report.Partitions[i].APFS.Volumes[0]
		} else if report.Partitions[i].HFSPlus != nil {
			reader = report.Partitions[i].HFSPlus
		}
	}
	if reader == nil {
		t.Fatalf("%s: no filesystem", path)
	}
	compareViewWith(t, ctx, filepath.Base(path), reader, want.Observation.Views[0], compareOptions{ignoreTimes: map[string]bool{"change": true, "access": true}})
}
