package acceptance_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/inspect"
)

// rootExclusions mirrors the observer: directories macOS creates on every
// mounted volume that the product may enumerate but the kernel view omits.
var rootExclusions = map[string]bool{
	".fseventsd": true, ".Spotlight-V100": true, ".Trashes": true, ".TemporaryItems": true,
	".DocumentRevisions-V100": true, ".DS_Store": true, ".journal": true, ".journal_info_block": true,
	".hotfiles.btree": true, ".HFS+ Private Directory Data\r": true, "\x00\x00\x00\x00HFS+ Private Data": true,
	".PKInstallSandboxManager-SystemSoftware": true, ".metadata_never_index": true, ".apdisk": true,
}

// filesystemOwnedAttributes are listed by the product but hidden by native
// listxattr even with XATTR_SHOWCOMPRESSION. The symlink target is compared
// through Readlink; the security attribute is compared against the ACL the
// observer read through getattrlist.
var filesystemOwnedAttributes = map[string]bool{"com.apple.fs.symlink": true, "com.apple.system.Security": true}

// TestReadParity opens every captured image with the product and requires
// it to report exactly what the kernel reported on the producing Mac: the
// same objects, identities, metadata, bytes, attributes, forks, compression,
// snapshots and name-comparison outcomes, on this host, for every producer.
func TestReadParity(t *testing.T) {
	cases, _ := loadCorpus(t)
	recipes := recipesByName(t)
	for _, k := range cases {
		k := k
		if len(k.Observation.Views) == 0 {
			continue
		}
		t.Run(fmt.Sprintf("macos-%d/%s/%s/%s", k.Producer, k.Recipe, k.Profile, k.Stage), func(t *testing.T) {
			t.Parallel()
			compareCase(t, k, recipes[k.Recipe])
		})
	}
}

func recipesByName(t *testing.T) map[string]schema.Recipe {
	t.Helper()
	list, err := schema.LoadRecipes("recipes")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]schema.Recipe{}
	for _, r := range list {
		out[r.Name] = r
	}
	return out
}

func compareCase(t *testing.T, k corpus.Case, recipe schema.Recipe) {
	ctx := context.Background()
	obs := k.Observation
	img := openImage(t, ctx, k, recipe)
	defer func() { _ = img.Close() }()
	report, err := inspect.Image(ctx, img)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	for _, vol := range obs.Volumes {
		name, _ := vol.Diskutil["VolumeName"].(string)
		reader, closer := openVolume(t, ctx, report, vol, name, recipe)
		if closer != nil {
			defer closer()
		}
		for _, view := range obs.Views {
			if view.Volume != vol.Index {
				continue
			}
			r := reader
			if view.Snapshot != "" {
				av, ok := reader.(*apfs.Volume)
				if !ok {
					t.Errorf("volume %s: snapshot view on a non-APFS volume", name)
					continue
				}
				r, err = av.OpenSnapshotName(ctx, view.Snapshot)
				if err != nil {
					t.Errorf("volume %s: open snapshot %s: %v", name, view.Snapshot, err)
					continue
				}
			}
			label := name
			if view.Snapshot != "" {
				label += "@" + view.Snapshot
			}
			compareView(t, ctx, label, r, view)
			if len(view.Statistics) > 0 {
				compareStatistics(t, ctx, label, r, view.Statistics, nil)
			}
		}
	}
}

func openImage(t *testing.T, ctx context.Context, k corpus.Case, recipe schema.Recipe) *diskimage.Image {
	t.Helper()
	path := k.Image()
	if strings.HasSuffix(path, ".raw.gz") {
		t.Fatalf("raw images are expanded by the corpus resolver before use: %s", path)
	}
	enc := k.Observation.Image.Encryption
	if enc == nil {
		img, err := diskimage.Open(path)
		if err != nil {
			t.Fatalf("open %s: %v", path, err)
		}
		return img
	}
	if _, err := diskimage.Open(path); !errors.Is(err, filesystem.ErrAuthentication) {
		t.Errorf("encrypted image opened without a password: %v", err)
	}
	for _, ref := range enc.Rejected {
		bad, ok := recipe.Passwords[ref]
		if !ok {
			t.Fatalf("recipe %s has no password %q", recipe.Name, ref)
		}
		if _, err := diskimage.OpenWithPassword(ctx, path, []byte(bad)); !errors.Is(err, filesystem.ErrAuthentication) {
			t.Errorf("rejected image password %q was accepted: %v", ref, err)
		}
	}
	password, ok := recipe.Passwords[enc.Password]
	if !ok {
		t.Fatalf("recipe %s has no password %q", recipe.Name, enc.Password)
	}
	img, err := diskimage.OpenWithPassword(ctx, path, []byte(password))
	if err != nil {
		t.Fatalf("open %s with password: %v", path, err)
	}
	if img.Encryption == nil || img.Encryption.Version != 2 {
		t.Errorf("encrypted image reported %+v", img.Encryption)
	}
	return img
}

// openVolume finds the product volume matching an observed volume by name
// and checks the volume-level facts before returning its reader.
func openVolume(t *testing.T, ctx context.Context, report *inspect.Report, vol schema.Volume, name string, recipe schema.Recipe) (filesystem.Reader, func()) {
	t.Helper()
	blockSize := uint32(number(vol.Diskutil["VolumeAllocationBlockSize"]))
	for i := range report.Partitions {
		p := &report.Partitions[i]
		if p.APFS != nil {
			for j := range p.APFS.Volumes {
				v := &p.APFS.Volumes[j]
				if v.Name != name {
					continue
				}
				if vol.APFS == nil {
					t.Fatalf("volume %s: observed as HFS but the image holds APFS", name)
				}
				if v.UUID != strings.ToUpper(vol.APFS.VolumeUUID) {
					t.Errorf("volume %s: UUID %s, native %s", name, v.UUID, vol.APFS.VolumeUUID)
				}
				if v.CaseSensitive != vol.APFS.CaseSensitive {
					t.Errorf("volume %s: caseSensitive %v, native %v", name, v.CaseSensitive, vol.APFS.CaseSensitive)
				}
				if p.APFS.BlockSize != blockSize {
					t.Errorf("volume %s: block size %d, native %d", name, p.APFS.BlockSize, blockSize)
				}
				if got := int64(v.ReserveBlocks) * int64(p.APFS.BlockSize); got != vol.APFS.ReserveBytes {
					t.Errorf("volume %s: reserve %d, native %d", name, got, vol.APFS.ReserveBytes)
				}
				if got := int64(v.QuotaBlocks) * int64(p.APFS.BlockSize); got != vol.APFS.QuotaBytes {
					t.Errorf("volume %s: quota %d, native %d", name, got, vol.APFS.QuotaBytes)
				}
				if v.Encrypted != vol.APFS.Encrypted {
					t.Errorf("volume %s: encrypted %v, native %v", name, v.Encrypted, vol.APFS.Encrypted)
				}
				reader := filesystem.Reader(v)
				var closer func()
				if v.Encrypted {
					if _, err := v.Stat(ctx, v.Root()); !errors.Is(err, filesystem.ErrAuthentication) {
						t.Errorf("volume %s: locked volume readable without a credential: %v", name, err)
					}
					for _, ref := range vol.APFS.Rejected {
						bad, ok := recipe.Passwords[ref]
						if !ok {
							t.Fatalf("recipe %s has no password %q", recipe.Name, ref)
						}
						if _, err := v.Unlock(ctx, []byte(bad)); !errors.Is(err, filesystem.ErrAuthentication) {
							t.Errorf("volume %s: rejected password %q was accepted: %v", name, ref, err)
						}
					}
					password, ok := recipe.Passwords[vol.APFS.Password]
					if !ok {
						t.Fatalf("recipe %s has no password %q", recipe.Name, vol.APFS.Password)
					}
					unlocked, err := v.Unlock(ctx, []byte(password))
					if err != nil {
						t.Fatalf("volume %s: unlock: %v", name, err)
					}
					reader = unlocked
					closer = func() { _ = unlocked.Close() }
					v = unlocked
				}
				compareSnapshots(t, ctx, name, v, vol.APFS.Snapshots)
				return reader, closer
			}
			continue
		}
		if p.HFSPlus != nil && p.HFSPlus.Name == name {
			h := p.HFSPlus
			if vol.HFS == nil {
				t.Fatalf("volume %s: observed as APFS but the image holds HFS", name)
			}
			if h.CaseSensitive != vol.HFS.CaseSensitive || h.Journaled != vol.HFS.Journaled {
				t.Errorf("volume %s: caseSensitive/journaled %v/%v, native %v/%v", name, h.CaseSensitive, h.Journaled, vol.HFS.CaseSensitive, vol.HFS.Journaled)
			}
			if h.BlockSize != blockSize {
				t.Errorf("volume %s: block size %d, native %d", name, h.BlockSize, blockSize)
			}
			return h, nil
		}
	}
	t.Fatalf("volume %s not found in the image's partitions", name)
	return nil, nil
}

func compareSnapshots(t *testing.T, ctx context.Context, name string, v *apfs.Volume, want []schema.Snapshot) {
	t.Helper()
	var got []schema.Snapshot
	err := v.ListSnapshots(ctx, func(s apfs.Snapshot) error {
		got = append(got, schema.Snapshot{Name: s.Name, XID: uint64(s.XID), UUID: s.UUID.Value})
		return nil
	})
	if err != nil {
		t.Errorf("volume %s: list snapshots: %v", name, err)
		return
	}
	sort.Slice(want, func(i, j int) bool { return want[i].XID < want[j].XID })
	if len(got) != len(want) {
		t.Errorf("volume %s: %d snapshots, native %d", name, len(got), len(want))
		return
	}
	for i := range want {
		if got[i].Name != want[i].Name || (want[i].XID != 0 && got[i].XID != want[i].XID) || !strings.EqualFold(got[i].UUID, want[i].UUID) {
			t.Errorf("volume %s: snapshot %d %+v, native %+v", name, i, got[i], want[i])
		}
	}
}

// compareOptions relax a comparison for images the product produced
// rather than read: a build of a subtree has no "Fixture/" prefix, and an
// editor assigns change times from its own clock.
type compareOptions struct {
	subtree     string
	ignoreTimes map[string]bool
	// ignoreTimesFor, when set, replaces ignoreTimes per observed path.
	ignoreTimesFor func(path string) map[string]bool
	// ignoreIDFor, when set, exempts a path's object identity: entries an
	// editor created follow the allocator's policy, not the kernel's.
	ignoreIDFor func(path string) bool
	// compression names the explicit file-compression policy a build used
	// ("zlib" or "none"); empty compares compression exactly. Under a
	// policy only compression-owned storage and UF_COMPRESSED may differ
	// from the source (docs/packing.md).
	compression string
}

// compressionOwned names the attributes a compression policy may add or
// remove; an independent resource fork is still compared.
var compressionOwned = map[string]bool{"com.apple.decmpfs": true, "com.apple.ResourceFork": true}

// emptySHA256 is the digest of zero bytes: what the kernel returns when it
// refuses to decode a malformed active compression record.
const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// compareView walks the product's tree and the observed entries and
// requires the same set of paths and the same facts for each.
func compareView(t *testing.T, ctx context.Context, label string, r filesystem.Reader, view schema.View) {
	compareViewWith(t, ctx, label, r, view, compareOptions{})
}

func compareViewWith(t *testing.T, ctx context.Context, label string, r filesystem.Reader, view schema.View, opts compareOptions) {
	objects := map[string]uint64{}
	var walk func(dir uint64, rel string) error
	walk = func(dir uint64, rel string) error {
		return r.ReadDir(ctx, dir, func(e filesystem.DirEntry) error {
			if rel == "" && rootExclusions[e.Name] {
				return nil
			}
			childRel := e.Name
			if rel != "" {
				childRel = rel + "/" + e.Name
			}
			objects[childRel] = e.Object
			node, err := r.Stat(ctx, e.Object)
			if err != nil {
				return fmt.Errorf("%s: stat: %w", childRel, err)
			}
			if node.Metadata.Mode.Value&0o170000 == 0o040000 {
				return walk(e.Object, childRel)
			}
			return nil
		})
	}
	if err := walk(r.Root(), ""); err != nil {
		t.Errorf("%s: %v", label, err)
		return
	}
	entries := view.Entries
	if opts.subtree != "" {
		entries = nil
		prefix := opts.subtree + "/"
		for _, e := range view.Entries {
			if strings.HasPrefix(e.Path, prefix) {
				e.Path = strings.TrimPrefix(e.Path, prefix)
				entries = append(entries, e)
			}
		}
	}
	observed := map[string]bool{}
	for _, e := range entries {
		observed[e.Path] = true
		if _, ok := objects[e.Path]; !ok {
			t.Errorf("%s: native entry %q is missing from the product's enumeration", label, e.Path)
		}
	}
	for p := range objects {
		if !observed[p] {
			t.Errorf("%s: product enumerates %q which the kernel did not report", label, p)
		}
	}
	for _, e := range entries {
		id, ok := objects[e.Path]
		if !ok {
			continue
		}
		compareEntryWith(t, ctx, label, r, id, e, opts)
	}
	if opts.subtree != "" {
		return
	}
	for _, probe := range view.Lookups {
		query, err := hex.DecodeString(probe.Query)
		if err != nil {
			t.Errorf("%s: lookup query %q: %v", label, probe.Query, err)
			continue
		}
		id, err := filesystem.Lookup(ctx, r, path.Join(probe.Dir, string(query)))
		switch {
		case probe.Result == "found" && err != nil:
			t.Errorf("%s: lookup %s/%q: native found %d, product %v", label, probe.Dir, query, probe.ID, err)
		case probe.Result == "found" && id != probe.ID:
			t.Errorf("%s: lookup %s/%q: native object %d, product %d", label, probe.Dir, query, probe.ID, id)
		case probe.Result != "found" && err == nil:
			t.Errorf("%s: lookup %s/%q: native %s, product found %d", label, probe.Dir, query, probe.Result, id)
		case probe.Result != "found" && !errors.Is(err, fs.ErrNotExist):
			t.Errorf("%s: lookup %s/%q: native %s, product error %v", label, probe.Dir, query, probe.Result, err)
		}
	}
}

func compareEntryWith(t *testing.T, ctx context.Context, label string, r filesystem.Reader, id uint64, e schema.Entry, opts compareOptions) {
	where := label + ":" + e.Path
	node, err := r.Stat(ctx, id)
	if err != nil {
		t.Errorf("%s: stat: %v", where, err)
		return
	}
	if node.Identity.Object != e.ID && opts.subtree == "" && (opts.ignoreIDFor == nil || !opts.ignoreIDFor(e.Path)) {
		t.Errorf("%s: object %d, native %d", where, node.Identity.Object, e.ID)
	}
	kind := "other"
	switch node.Metadata.Mode.Value & 0o170000 {
	case 0o100000:
		kind = "file"
	case 0o040000:
		kind = "dir"
	case 0o120000:
		kind = "symlink"
	}
	if kind != e.Kind {
		t.Errorf("%s: kind %s, native %s", where, kind, e.Kind)
	}
	if got := node.Metadata.Mode.Value & 0o7777; got != e.Mode {
		t.Errorf("%s: mode %o, native %o", where, got, e.Mode)
	}
	if node.Metadata.UID.Value != e.UID || node.Metadata.GID.Value != e.GID {
		t.Errorf("%s: owner %d:%d, native %d:%d", where, node.Metadata.UID.Value, node.Metadata.GID.Value, e.UID, e.GID)
	}
	flagMask := uint32(0xffffffff)
	if opts.compression != "" {
		flagMask &^= 0x20 // UF_COMPRESSED follows the policy
	}
	if node.Metadata.BSDFlags.Value&flagMask != e.Flags&flagMask {
		t.Errorf("%s: flags %#x, native %#x", where, node.Metadata.BSDFlags.Value, e.Flags)
	}
	times := map[string][2]int64{
		"birth":  {node.Metadata.BirthTime.Value.UnixNano(), e.Times.Birth},
		"modify": {node.Metadata.ModifyTime.Value.UnixNano(), e.Times.Modify},
		"change": {node.Metadata.ChangeTime.Value.UnixNano(), e.Times.Change},
		"access": {node.Metadata.AccessTime.Value.UnixNano(), e.Times.Access},
	}
	ignore := opts.ignoreTimes
	if opts.ignoreTimesFor != nil {
		ignore = opts.ignoreTimesFor(e.Path)
	}
	for name, pair := range times {
		if ignore[name] {
			continue
		}
		if pair[0] != pair[1] {
			t.Errorf("%s: %s time %d, native %d", where, name, pair[0], pair[1])
		}
	}
	if kind != "dir" {
		if int64(node.Size) != e.Size {
			t.Errorf("%s: size %d, native %d", where, node.Size, e.Size)
		}
		if node.Links.State == filesystem.Present && node.Links.Value != e.Links {
			t.Errorf("%s: links %d, native %d", where, node.Links.Value, e.Links)
		}
	}
	switch {
	case opts.compression == "none" && node.Compression.State == filesystem.Present:
		t.Errorf("%s: compression type %d remains under the none policy", where, node.Compression.Value.Type)
	case opts.compression == "zlib" && node.Compression.State == filesystem.Present && node.Compression.Value.Type != 3 && node.Compression.Value.Type != 4:
		t.Errorf("%s: compression type %d under the zlib policy, expected 3 or 4", where, node.Compression.Value.Type)
	case opts.compression != "":
		// A file the policy skipped is ordinary storage; the reason is in
		// the build report, and the logical bytes are compared below.
	case e.Compression != nil && node.Compression.State != filesystem.Present:
		t.Errorf("%s: native compression type %d, product reports none", where, e.Compression.Type)
	case e.Compression != nil && node.Compression.Value.Type != e.Compression.Type:
		t.Errorf("%s: compression type %d, native %d", where, node.Compression.Value.Type, e.Compression.Type)
	case e.Compression == nil && node.Compression.State == filesystem.Present:
		t.Errorf("%s: product reports compression type %d, native none", where, node.Compression.Value.Type)
	}
	switch kind {
	case "file":
		sum, n, err := hashValue(ctx, r, id)
		kernelReadNothing := e.Compression != nil && e.SHA256 == emptySHA256 && e.Size > 0
		switch {
		case e.SHA256 != "" && err != nil:
			t.Errorf("%s: read: %v", where, err)
		case e.SHA256 != "" && kernelReadNothing && (sum != e.SHA256 || n != 0):
			// The kernel returned no bytes for a malformed active record
			// whose header still states a size; the product must do the same.
			t.Errorf("%s: data %s (%d bytes), native read nothing of %d stated bytes", where, sum, n, e.Size)
		case e.SHA256 != "" && !kernelReadNothing && (sum != e.SHA256 || n != e.Size):
			t.Errorf("%s: data %s (%d bytes), native %s (%d bytes)", where, sum, n, e.SHA256, e.Size)
		case e.SHA256 == "" && err == nil && e.Compression != nil:
			// The kernel could not read this object (recorded in known
			// drift); the product decoded it. The bytes are checked by
			// the public codec in the native tier.
		}
	case "symlink":
		target, err := r.Readlink(ctx, id)
		if err != nil {
			t.Errorf("%s: readlink: %v", where, err)
		} else if hex.EncodeToString([]byte(target)) != e.Target {
			t.Errorf("%s: target %q, native %q", where, target, e.Target)
		}
	}
	listed := map[string]bool{}
	_ = r.ListAttributes(ctx, id, func(name string) error { listed[name] = true; return nil })
	for _, x := range e.Xattrs {
		if opts.compression != "" && compressionOwned[x.Name] && e.Compression != nil {
			continue // storage the policy re-encoded or removed
		}
		if !listed[x.Name] {
			t.Errorf("%s: native attribute %q not listed by the product", where, x.Name)
			continue
		}
		value, err := r.OpenAttribute(ctx, id, x.Name)
		if err != nil {
			t.Errorf("%s: attribute %q: %v", where, x.Name, err)
			continue
		}
		sum, n := hashReaderAt(value, value.Size())
		_ = value.Close()
		if n != x.Bytes || sum != x.SHA256 {
			t.Errorf("%s: attribute %q %s (%d bytes), native %s (%d bytes)", where, x.Name, sum, n, x.SHA256, x.Bytes)
		}
	}
	if listed["com.apple.system.Security"] || e.ACL != "" {
		value, err := r.OpenAttribute(ctx, id, "com.apple.system.Security")
		switch {
		case err != nil && e.ACL != "":
			t.Errorf("%s: native ACL present but the product has no security attribute: %v", where, err)
		case err == nil:
			sum, n := hashReaderAt(value, value.Size())
			_ = value.Close()
			acl, _ := hex.DecodeString(e.ACL)
			want := sha256.Sum256(filesecDiskOrder(acl))
			if e.ACL == "" {
				t.Errorf("%s: product has a security attribute (%d bytes) but the kernel reported no ACL", where, n)
			} else if sum != hex.EncodeToString(want[:]) || n != int64(len(acl)) {
				t.Errorf("%s: security attribute %s (%d bytes), native ACL %d bytes", where, sum, n, len(acl))
			}
		}
	}
	observedNames := map[string]bool{}
	for _, x := range e.Xattrs {
		observedNames[x.Name] = true
	}
	for name := range listed {
		if observedNames[name] || filesystemOwnedAttributes[name] {
			continue
		}
		if opts.compression != "" && compressionOwned[name] && node.Compression.State == filesystem.Present {
			continue // storage the policy created
		}
		value, err := r.OpenAttribute(ctx, id, name)
		if err == nil {
			size := value.Size()
			_ = value.Close()
			if size == 0 {
				continue // an empty retained record the kernel hides
			}
		}
		t.Errorf("%s: product lists attribute %q the kernel did not report", where, name)
	}
}

func hashValue(ctx context.Context, r filesystem.Reader, id uint64) (string, int64, error) {
	value, err := r.OpenData(ctx, id)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = value.Close() }()
	sum, n := hashReaderAt(value, value.Size())
	return sum, n, nil
}

func hashReaderAt(v io.ReaderAt, size int64) (string, int64) {
	digest := sha256.New()
	n, _ := io.Copy(digest, io.NewSectionReader(v, 0, size))
	return hex.EncodeToString(digest.Sum(nil)), n
}

func number(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int64:
		return float64(n)
	case int:
		return float64(n)
	}
	return 0
}

// filesecDiskOrder converts a kauth_filesec as getattrlist returns it (host
// byte order) to its on-disk big-endian form, which is what the product's
// raw attribute read returns. GUIDs are byte arrays and stay as they are.
func filesecDiskOrder(host []byte) []byte {
	out := append([]byte(nil), host...)
	swap := func(off int) {
		if off+4 <= len(out) {
			out[off], out[off+1], out[off+2], out[off+3] = out[off+3], out[off+2], out[off+1], out[off]
		}
	}
	swap(0)  // fsec_magic
	swap(36) // acl_entrycount
	swap(40) // acl_flags
	for off := 44; off+24 <= len(out); off += 24 {
		swap(off + 16) // ace_flags
		swap(off + 20) // ace_rights
	}
	return out
}
