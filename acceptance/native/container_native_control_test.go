//go:build native && darwin

package native

// This file belongs only to the transient matched native diagnostic. It does
// not change the acceptance workload or provide a production image builder.

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

const matchedNativeCapacity = int64(1600 << 20)

var matchedNativeNames = []string{"Reserved", "Limited", "Empty", "Fresh Empty"}

// copyfile supplies the metadata ditto omits on an already-existing destination
// volume root. setattrlist restores the three preservable timestamps explicitly;
// ctime is deliberately observed and recorded, never manufactured or hidden.
const matchedNativeMetadataSource = `#include <copyfile.h>
#include <sys/attr.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int remove_destination_only_attrs(const char *source, const char *destination) {
    int options = XATTR_NOFOLLOW | XATTR_SHOWCOMPRESSION;
    ssize_t size = listxattr(destination, NULL, 0, options);
    if (size < 0) { perror("list destination root attrs"); return 1; }
    if (size == 0) return 0;
    char *names = malloc((size_t)size);
    if (names == NULL) { perror("allocate root attrs"); return 1; }
    ssize_t count = listxattr(destination, names, (size_t)size, options);
    if (count < 0) { perror("read destination root attrs"); free(names); return 1; }
    for (char *name = names; name < names + count; name += strlen(name) + 1) {
        if (getxattr(source, name, NULL, 0, 0, options) >= 0) continue;
        if (errno != ENOATTR) { perror("read source root attr"); free(names); return 1; }
        if (removexattr(destination, name, XATTR_NOFOLLOW) != 0) {
            perror("remove destination-only root attr"); free(names); return 1;
        }
        fprintf(stderr, "removed destination-only root attr: %s\n", name);
    }
    free(names);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 4) return 2;
    int normalize = strcmp(argv[1], "normalize") == 0;
    if (strcmp(argv[1], "metadata") == 0 || normalize) {
        if (copyfile(argv[2], argv[3], NULL,
            COPYFILE_METADATA | COPYFILE_NOFOLLOW) != 0) {
            perror("copyfile metadata"); return 1;
        }
        if (normalize && remove_destination_only_attrs(argv[2], argv[3]) != 0) return 1;
    } else if (strcmp(argv[1], "times") != 0) return 2;
    struct stat source;
    if (lstat(argv[2], &source) != 0) { perror("lstat source"); return 1; }
    struct attrlist attrs = {0};
    attrs.bitmapcount = ATTR_BIT_MAP_COUNT;
    attrs.commonattr = ATTR_CMN_CRTIME | ATTR_CMN_MODTIME | ATTR_CMN_ACCTIME;
    struct { struct timespec birth, modify, access; } times = {
        source.st_birthtimespec, source.st_mtimespec, source.st_atimespec
    };
    if (setattrlist(argv[3], &attrs, &times, sizeof(times), FSOPT_NOFOLLOW) != 0) {
        perror("setattrlist timestamps"); return 1;
    }
    return 0;
}
`

// buildMatchedNativeContainer creates a new Apple-built control without using
// product writers or altering any pinned evidence. The caller must keep this
// detached source immutable and run workloads on separate private raw copies.
func buildMatchedNativeContainer(ctx context.Context, parent *Verifier, goImage, work string, recipe schema.Recipe) (raw string, before *schema.Observation, resultErr error) {
	if err := fixture.RequireDisposableHost(); err != nil {
		return "", nil, err
	}
	if err := os.MkdirAll(work, 0o755); err != nil {
		return "", nil, err
	}
	v := parent.ForSubtest()
	v.Work = work
	transcript := &fixture.Transcript{}
	rootHistory := map[string]map[string]schema.Entry{}
	setTranscript := func() { v.Disk.(fixture.TranscriptUser).SetTranscript(transcript) }
	setTranscript()
	defer func() {
		if err := writeMatchedNativeJSON(filepath.Join(work, "builder-commands.json"), transcript.Commands); err != nil {
			resultErr = errors.Join(resultErr, err)
		}
		if err := writeMatchedNativeJSON(filepath.Join(work, "root-metadata-history.json"), rootHistory); err != nil {
			resultErr = errors.Join(resultErr, err)
		}
	}()
	run := func(label string, sudo bool, argv ...string) error {
		cmd := fixture.Command{Label: label, Sudo: sudo, Argv: argv, Expected: "0"}
		return transcript.Record(cmd, v.C.Run(ctx, cmd))
	}
	spec := schema.ObserveSpec{RawHeaders: true, Checks: []string{"verify", "fsck"}, Codesign: []string{"Example.app"}, Lookups: []schema.Lookup{{Query: "Name"}, {Query: "name"}}}
	goBefore, err := v.observeImageWithDigest(ctx, "matched-go-before", goImage, "UDZO", nil, spec, recipe, true)
	if err != nil {
		return "", nil, err
	}
	if err := matchedNativePolicy(goBefore); err != nil {
		return "", nil, fmt.Errorf("Go control policy: %w", err)
	}
	setTranscript()
	metadataSource, metadataTool := filepath.Join(work, "root_metadata.c"), filepath.Join(work, "root-metadata")
	if err := os.WriteFile(metadataSource, []byte(matchedNativeMetadataSource), 0o644); err != nil {
		return "", nil, err
	}
	if err := run("build matched root metadata adapter", false, "xcrun", "clang", "-Wall", "-Wextra", "-Werror", metadataSource, "-o", metadataTool); err != nil {
		return "", nil, err
	}
	raw = filepath.Join(work, "apple-native-source.raw")
	if err := v.Disk.CreateRaw(ctx, raw, matchedNativeCapacity); err != nil {
		return "", nil, err
	}
	if err := transcript.RecordFS("create matched raw", []string{raw, fmt.Sprint(matchedNativeCapacity)}, nil, "0"); err != nil {
		return "", nil, err
	}
	apple, err := v.Disk.Attach(ctx, raw, fixture.AttachOptions{Raw: true})
	if err != nil {
		return "", nil, err
	}
	defer func() {
		if apple != nil {
			resultErr = errors.Join(resultErr, v.Disk.Detach(ctx, apple))
		}
	}()
	if err := run("format matched Apple APFS", true, "newfs_apfs", "-b", "4096", "-v", "Primary", apple.RDev); err != nil {
		return "", nil, err
	}
	if err := v.Disk.Refresh(ctx, apple); err != nil {
		return "", nil, err
	}
	primary := apple.Volume("Primary")
	if primary == nil || apple.Container == "" {
		return "", nil, fmt.Errorf("new Apple container or Primary volume was not discovered")
	}
	container := apple.Container
	if err := run("delete initial matched Primary", false, "diskutil", "apfs", "deleteVolume", primary.Dev); err != nil {
		return "", nil, err
	}
	for _, args := range [][]string{
		{"APFS", "Reserved", "-reserve", "1577058304"},
		{"APFSX", "Limited", "-quota", "8388608"},
		{"APFS", "Empty"},
		{"APFS", "Fresh Empty"},
	} {
		argv := append([]string{"diskutil", "apfs", "addVolume", container}, args...)
		argv = append(argv, "-nomount")
		if err := run("add matched volume "+args[1], false, argv...); err != nil {
			return "", nil, err
		}
	}
	if err := v.Disk.Refresh(ctx, apple); err != nil {
		return "", nil, err
	}
	if len(apple.Volumes) != len(matchedNativeNames) {
		return "", nil, fmt.Errorf("Apple control has %d volumes, require four", len(apple.Volumes))
	}
	goSource, err := v.Disk.Attach(ctx, goImage, fixture.AttachOptions{ReadOnly: true})
	if err != nil {
		return "", nil, err
	}
	defer func() {
		if goSource != nil {
			resultErr = errors.Join(resultErr, v.Disk.Detach(ctx, goSource))
		}
	}()
	for i, name := range matchedNativeNames {
		dst, src := apple.Volume(name), goSource.Volume(name)
		if dst == nil || src == nil || apple.Volumes[i].Name != name {
			return "", nil, fmt.Errorf("matched volume %q is missing or out of order", name)
		}
		if err := v.Disk.Mount(ctx, src, "owners,noatime", filepath.Join(work, "go-root", sanitize(name)), true); err != nil {
			return "", nil, err
		}
		if err := v.Disk.Mount(ctx, dst, "owners,noatime", filepath.Join(work, "apple-root", sanitize(name)), false); err != nil {
			return "", nil, err
		}
		rootHistory[name] = map[string]schema.Entry{}
		for label, mount := range map[string]string{"source": src.Mount, "nativeBeforeCopy": dst.Mount} {
			entry, err := readMatchedNativeRoot(v, mount)
			if err != nil {
				return "", nil, err
			}
			rootHistory[name][label] = entry
		}
		volume, err := namedVolume(goBefore, name)
		if err != nil {
			return "", nil, err
		}
		view, err := observedView(goBefore, volume.Index, "")
		if err != nil {
			return "", nil, err
		}
		if name != "Fresh Empty" {
			if err := run("copy matched payload "+name, true, "ditto", "--rsrc", "--extattr", "--acl", "--preserveHFSCompression", src.Mount, dst.Mount); err != nil {
				return "", nil, err
			}
		}
		for _, entry := range view.Entries {
			if err := run("restore copied timestamps "+name+":"+entry.Path, true, metadataTool, "times", filepath.Join(src.Mount, filepath.FromSlash(entry.Path)), filepath.Join(dst.Mount, filepath.FromSlash(entry.Path))); err != nil {
				return "", nil, err
			}
		}
		if err := run("copy existing volume root metadata "+name, true, metadataTool, "metadata", src.Mount, dst.Mount); err != nil {
			return "", nil, err
		}
		entry, err := readMatchedNativeRoot(v, dst.Mount)
		if err != nil {
			return "", nil, err
		}
		rootHistory[name]["nativeAfterCopy"] = entry
	}
	if err := closeMatchedNativeAttachment(ctx, v, goSource); err != nil {
		return "", nil, err
	}
	goSource = nil
	if err := closeMatchedNativeAttachment(ctx, v, apple); err != nil {
		return "", nil, err
	}
	apple = nil
	// First writable mounts can initialize native root attributes and hidden
	// directory entries after the initial copy. Preserve that exact state,
	// then perform one fixed normalization phase on a newly opened image.
	// This is preparation, not a pressure-workload retry or a parity exception.
	initialized := filepath.Join(work, "apple-initialized-source.raw")
	if err := run("retain initialized Apple source", false, "cp", "-p", raw, initialized); err != nil {
		return "", nil, err
	}
	initializedDigest, err := schema.FileDigest(initialized)
	if err != nil {
		return "", nil, err
	}
	if err := writeMatchedNativeJSON(filepath.Join(work, "initialization.json"), map[string]any{"image": filepath.Base(initialized), "bytes": matchedNativeCapacity, "sha256": initializedDigest, "phase": "after initial payload copy and clean close; before fixed metadata normalization"}); err != nil {
		return "", nil, err
	}
	apple, err = v.Disk.Attach(ctx, raw, fixture.AttachOptions{Raw: true})
	if err != nil {
		return "", nil, err
	}
	goSource, err = v.Disk.Attach(ctx, goImage, fixture.AttachOptions{ReadOnly: true})
	if err != nil {
		return "", nil, err
	}
	for _, name := range matchedNativeNames {
		src, dst := goSource.Volume(name), apple.Volume(name)
		if src == nil || dst == nil {
			return "", nil, fmt.Errorf("normalization volume %q is missing", name)
		}
		if err := v.Disk.Mount(ctx, src, "owners,noatime", filepath.Join(work, "go-normalize", sanitize(name)), true); err != nil {
			return "", nil, err
		}
		if err := v.Disk.Mount(ctx, dst, "owners,noatime", filepath.Join(work, "apple-normalize", sanitize(name)), false); err != nil {
			return "", nil, err
		}
		entry, err := readMatchedNativeRoot(v, dst.Mount)
		if err != nil {
			return "", nil, err
		}
		rootHistory[name]["nativeBeforeNormalization"] = entry
		if err := run("normalize initialized volume root metadata "+name, true, metadataTool, "normalize", src.Mount, dst.Mount); err != nil {
			return "", nil, err
		}
		entry, err = readMatchedNativeRoot(v, dst.Mount)
		if err != nil {
			return "", nil, err
		}
		rootHistory[name]["nativeAfterNormalization"] = entry
	}
	if err := closeMatchedNativeAttachment(ctx, v, goSource); err != nil {
		return "", nil, err
	}
	goSource = nil
	if err := closeMatchedNativeAttachment(ctx, v, apple); err != nil {
		return "", nil, err
	}
	apple = nil
	before, err = v.observeImageWithDigest(ctx, "matched-apple-before", raw, "raw", nil, spec, recipe, true)
	if err != nil {
		return "", nil, err
	}
	if err := matchedNativePolicy(before); err != nil {
		return "", nil, fmt.Errorf("Apple control policy: %w", err)
	}
	goInventory, _ := fixture.APFSInventory(goBefore)
	appleInventory, _ := fixture.APFSInventory(before)
	if strings.EqualFold(goInventory[0].APFS.ContainerUUID, appleInventory[0].APFS.ContainerUUID) {
		return "", nil, fmt.Errorf("Apple control reused Go container identity")
	}
	for i := range goInventory {
		if strings.EqualFold(goInventory[i].APFS.VolumeUUID, appleInventory[i].APFS.VolumeUUID) {
			return "", nil, fmt.Errorf("Apple control reused Go volume identity for %q", matchedNativeNames[i])
		}
	}
	setTranscript()
	goRoots, err := matchedNativeRoots(ctx, v, goImage, false, filepath.Join(work, "go-roots"))
	if err != nil {
		return "", nil, err
	}
	appleRoots, err := matchedNativeRoots(ctx, v, raw, true, filepath.Join(work, "apple-roots"))
	if err != nil {
		return "", nil, err
	}
	report := map[string]any{
		"projection":         "fresh container/volume/object IDs and ctime only; original observations unchanged",
		"structuralEvidence": "physical allocation/free/reserve and checkpoint state are retained separately, not equated between formatters; pending-free state remains in the bound prepressure raw images",
		"goRoots":            goRoots, "appleRoots": appleRoots, "goVolumes": goBefore.Volumes, "appleVolumes": before.Volumes,
		"goImage": goBefore.Image, "appleImage": before.Image,
	}
	var diffs []Difference
	var identities, allocations []map[string]any
	for _, name := range matchedNativeNames {
		gvol, _ := namedVolume(goBefore, name)
		avol, _ := namedVolume(before, name)
		gview, _ := observedView(goBefore, gvol.Index, "")
		aview, _ := observedView(before, avol.Index, "")
		gview.Entries = append(append([]schema.Entry(nil), gview.Entries...), goRoots[name])
		aview.Entries = append(append([]schema.Entry(nil), aview.Entries...), appleRoots[name])
		originals := map[string]schema.Entry{}
		for _, entry := range gview.Entries {
			originals[entry.Path] = entry
		}
		for _, entry := range aview.Entries {
			if original, ok := originals[entry.Path]; ok {
				if entry.ID != original.ID || entry.Times.Change != original.Times.Change {
					identities = append(identities, map[string]any{"volume": name, "path": entry.Path, "goID": original.ID, "appleID": entry.ID, "goCtime": original.Times.Change, "appleCtime": entry.Times.Change})
				}
				if entry.Allocated != original.Allocated {
					allocations = append(allocations, map[string]any{"volume": name, "path": entry.Path, "goAllocated": original.Allocated, "appleAllocated": entry.Allocated})
				}
			}
		}
		for _, difference := range matchedNativePayloadDifferences(aview, gview) {
			difference.Path = name + ":" + difference.Path
			diffs = append(diffs, difference)
		}
	}
	report["differences"] = diffs
	report["identityCtimeDifferences"], report["allocationDifferences"] = identities, allocations
	if err := writeMatchedNativeJSON(filepath.Join(work, "parity.json"), report); err != nil {
		return "", nil, err
	}
	if len(diffs) != 0 {
		return "", nil, fmt.Errorf("matched Apple/Go prepressure parity refused: %v", diffs)
	}
	if sum, err := schema.FileDigest(goImage); err != nil || sum != goBefore.Image.SHA256 {
		return "", nil, fmt.Errorf("read-only Go source changed: digest %q, error %v", sum, err)
	}
	if sum, err := schema.FileDigest(raw); err != nil || sum != before.Image.SHA256 {
		return "", nil, fmt.Errorf("read-only Apple source changed: digest %q, error %v", sum, err)
	}
	return raw, before, nil
}

func closeMatchedNativeAttachment(ctx context.Context, v *Verifier, att *fixture.Attachment) error {
	for _, volume := range att.Volumes {
		if volume.Mount != "" {
			if err := v.Disk.Unmount(ctx, volume); err != nil {
				return err
			}
		}
	}
	return v.Disk.Detach(ctx, att)
}

func matchedNativePolicy(obs *schema.Observation) error {
	if obs.Image.DiskBytes != matchedNativeCapacity || obs.Image.PartitionMap != "none" || obs.Image.Encryption != nil || len(obs.Views) != 4 {
		return fmt.Errorf("requires unpartitioned unencrypted 1600 MiB image and four live views")
	}
	volumes, err := fixture.APFSInventory(obs)
	if err != nil {
		return err
	}
	if len(volumes) != len(matchedNativeNames) {
		return fmt.Errorf("requires four volumes")
	}
	ids := map[string]bool{}
	containerID := ""
	for i, volume := range volumes {
		a := volume.APFS
		reserve, quota := int64(0), int64(0)
		if i == 0 {
			reserve = 1504 << 20
		}
		if i == 1 {
			quota = 8 << 20
		}
		if volumeName(volume) != matchedNativeNames[i] || a == nil || a.CaseSensitive != (i == 1) || a.ReserveBytes != reserve || a.QuotaBytes != quota || a.Role != "" || a.GroupUUID != "" || a.Encrypted || len(a.Snapshots) != 0 {
			return fmt.Errorf("volume %d has mismatched name/order/case/reserve/quota/role/group/encryption/snapshots: %+v", i, volume)
		}
		id := strings.ToUpper(a.VolumeUUID)
		if id == "" || id == "00000000-0000-0000-0000-000000000000" || ids[id] || a.ContainerUUID == "" || (containerID != "" && !strings.EqualFold(containerID, a.ContainerUUID)) {
			return fmt.Errorf("unidentified, duplicate or cross-container volume %q", volumeName(volume))
		}
		ids[id], containerID = true, a.ContainerUUID
		header, err := hex.DecodeString(volume.RawHeader)
		if err != nil || len(header) != 4096 || string(header[32:36]) != "NXSB" || binary.LittleEndian.Uint32(header[36:40]) != 4096 || binary.LittleEndian.Uint64(header[40:48])*4096 != uint64(matchedNativeCapacity) {
			return fmt.Errorf("volume %q lacks the required 4 KiB/1600 MiB native container header", volumeName(volume))
		}
		view, err := observedView(obs, volume.Index, "")
		if err != nil || (i == 3 && len(view.Entries) != 0) {
			return fmt.Errorf("volume %q lacks its live view or Fresh Empty contains payload: %v", volumeName(volume), err)
		}
	}
	if len(obs.Checks.Codesign) != 2 {
		return fmt.Errorf("requires signatures verified on both populated bundle volumes")
	}
	for _, signature := range obs.Checks.Codesign {
		if signature.Status != 0 {
			return fmt.Errorf("signature verification failed: %+v", signature)
		}
	}
	return nil
}

func matchedNativeRoots(ctx context.Context, v *Verifier, image string, raw bool, work string) (roots map[string]schema.Entry, resultErr error) {
	att, err := v.Disk.Attach(ctx, image, fixture.AttachOptions{ReadOnly: true, Raw: raw})
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, closeMatchedNativeAttachment(ctx, v, att)) }()
	roots = map[string]schema.Entry{}
	for _, name := range matchedNativeNames {
		volume := att.Volume(name)
		if volume == nil {
			return nil, fmt.Errorf("missing root volume %q", name)
		}
		if err := v.Disk.Mount(ctx, volume, "owners,noatime", filepath.Join(work, sanitize(name)), true); err != nil {
			return nil, err
		}
		entry, err := readMatchedNativeRoot(v, volume.Mount)
		if err != nil {
			return nil, err
		}
		roots[name] = entry
	}
	return roots, nil
}

func readMatchedNativeRoot(v *Verifier, mount string) (schema.Entry, error) {
	stat, err := v.Vol.Lstat(mount)
	if err != nil {
		return schema.Entry{}, err
	}
	entry := schema.Entry{Path: "", Kind: stat.Kind, ID: stat.Ino, Mode: stat.Mode, UID: stat.UID, GID: stat.GID, Flags: stat.Flags, Times: schema.Times{Birth: stat.Birth, Modify: stat.Modify, Change: stat.Change, Access: stat.Access}}
	names, err := v.Vol.Listxattr(mount, true)
	if err != nil {
		return schema.Entry{}, err
	}
	sort.Strings(names)
	for _, attr := range names {
		data, err := v.Vol.Getxattr(mount, attr, true)
		if err != nil {
			return schema.Entry{}, err
		}
		entry.Xattrs = append(entry.Xattrs, schema.Xattr{Name: attr, Bytes: int64(len(data)), SHA256: fmt.Sprintf("%x", sha256.Sum256(data))})
	}
	acl, err := v.Vol.ACL(mount)
	if err != nil {
		return schema.Entry{}, err
	}
	entry.ACL = hex.EncodeToString(acl)
	return entry, nil
}

func matchedNativePayloadDifferences(got, want schema.View) []Difference {
	diffs := CompareViews(got, want, CompareOptions{IgnoreIdentity: true, IgnoreTimes: map[string]bool{"change": true}})
	expected := map[string]schema.Entry{}
	for _, entry := range want.Entries {
		expected[entry.Path] = entry
	}
	for _, entry := range got.Entries {
		original, ok := expected[entry.Path]
		if ok && entry.RawSHA256 != original.RawSHA256 {
			diffs = append(diffs, Difference{Path: entry.Path, Field: "stored payload", Got: entry.RawSHA256, Want: original.RawSHA256})
		}
	}
	aliases := func(view schema.View, probe schema.Probe) []string {
		var paths []string
		for _, entry := range view.Entries {
			if entry.ID == probe.ID && probe.Result == "found" {
				paths = append(paths, entry.Path)
			}
		}
		sort.Strings(paths)
		return paths
	}
	if len(got.Lookups) != len(want.Lookups) {
		diffs = append(diffs, Difference{Field: "case lookup count", Got: fmt.Sprint(len(got.Lookups)), Want: fmt.Sprint(len(want.Lookups))})
	} else {
		for i, probe := range want.Lookups {
			actual := got.Lookups[i]
			if actual.Dir != probe.Dir || actual.Query != probe.Query || actual.Result != probe.Result || !reflect.DeepEqual(aliases(got, actual), aliases(want, probe)) {
				diffs = append(diffs, Difference{Path: probe.Dir, Field: "case lookup " + probe.Query, Got: fmt.Sprint(actual.Result, aliases(got, actual)), Want: fmt.Sprint(probe.Result, aliases(want, probe))})
			}
		}
	}
	return diffs
}

func writeMatchedNativeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}
