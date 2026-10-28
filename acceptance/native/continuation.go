package native

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// Continuation performs the native write sequence on a writable raw copy
// of an output, checks the volume with fsck, runs a further edit with the
// product binary, and checks again. It returns the observation of the
// final state. The sequence exercises the allocator past the object IDs a
// builder assigned, which is where the System volume object-ID namespace
// once panicked the kernel.
func (v *Verifier) Continuation(ctx context.Context, p Paired, k schemaCase) (observed *schema.Observation, resultErr error) {
	out := p.Output
	image := filepath.Join(p.Dirs[p.Primary], p.ByHost[p.Primary].File)
	work := filepath.Join(v.Work, "continuation", sanitize(out.Name))
	if err := os.MkdirAll(work, 0o755); err != nil {
		return nil, err
	}
	finishCommands := v.recordContinuationCommands(work)
	defer finishCommands(&resultErr)
	initialCommands := &fixture.Transcript{}
	v.setTranscript(initialCommands)
	// Successful continuations release their writable copies. Failed states
	// remain available in the native diagnostics artifact.
	defer func() {
		if resultErr == nil || onlyKnownLimit(resultErr) {
			if err := os.RemoveAll(work); err != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("release completed continuation scratch %s: %w", work, err))
			}
			return
		}
		commands, err := json.MarshalIndent(initialCommands.Commands, "", "  ")
		if err == nil {
			err = os.WriteFile(filepath.Join(work, "commands.json"), commands, 0o644)
		}
		if err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("continuation %s: retain initial native commands: %w", out.Name, err))
		}
	}()
	envelope, err := v.envelopeForContinuation(ctx, p, image)
	if err != nil {
		return nil, err
	}
	raw := filepath.Join(work, "writable.raw")
	// A raw copy, not a shadow: HFS shadow writes left a stale alternate
	// header in the retired harness.
	att, err := v.Disk.Attach(ctx, image, fixture.AttachOptions{ReadOnly: true, Password: envelope.password})
	if err != nil {
		return nil, err
	}
	_, _, err = v.Disk.DeviceDigest(ctx, att.RDev, raw+".gz")
	err = errors.Join(err, v.Disk.Detach(ctx, att))
	if err != nil {
		return nil, err
	}
	if err := corpus.ExpandGzip(raw+".gz", raw); err != nil {
		return nil, err
	}
	_ = os.Remove(raw + ".gz")
	att, err = v.Disk.Attach(ctx, raw, fixture.AttachOptions{Raw: true})
	if err != nil {
		return nil, err
	}
	if len(att.Volumes) == 0 {
		return nil, errors.Join(fmt.Errorf("continuation %s: no volume discovered on the writable copy", out.Name), v.Disk.Detach(ctx, att))
	}
	volume := att.Volumes[0]
	multiVolume := len(att.Volumes) > 1
	selected := out.Expect.Volume
	if out.Expect.SystemMember != "" {
		selected = out.Expect.SystemMember
	}
	if selected != "" {
		volume = att.Volume(selected)
		if volume == nil {
			return nil, errors.Join(fmt.Errorf("continuation %s: selected volume %q is missing", out.Name, selected), v.Disk.Detach(ctx, att))
		}
	}
	reference := out.Source
	if out.Expect.View != "" {
		reference.Stage = out.Expect.View
	}
	expectedObservation := v.Cases[CaseKey(reference)].Observation
	if out.Operation == "create-encrypted" {
		expectedObservation, err = encryptedConstructionReference(att, expectedObservation, out)
		if err != nil {
			return nil, errors.Join(err, v.Disk.Detach(ctx, att))
		}
	}
	if err := v.unlockContinuationVolumes(ctx, att, expectedObservation, k.recipe); err != nil {
		return nil, errors.Join(err, v.Disk.Detach(ctx, att))
	}
	for _, vol := range att.Volumes {
		if vol.Locked {
			continue
		}
		if err := v.Disk.Mount(ctx, vol, "owners,noatime", filepath.Join(work, "mnt", sanitize(vol.Name)), false); err != nil {
			return nil, errors.Join(err, v.Disk.Detach(ctx, att))
		}
	}
	if volume.Mount == "" {
		return nil, errors.Join(fmt.Errorf("continuation %s: volume %s is not mounted", out.Name, volume.Name), v.Disk.Detach(ctx, att))
	}
	if out.Expect.Container != nil {
		if err := v.containerWrites(ctx, att, out); err != nil {
			return nil, errors.Join(fmt.Errorf("continuation %s: container writes: %w", out.Name, err), v.Disk.Detach(ctx, att))
		}
	}
	if out.Source.Recipe == "apfs-clones" {
		if err := v.continueCloneWrites(ctx, volume.Mount, filepath.Join(work, "clone-native-source")); err != nil {
			return nil, errors.Join(fmt.Errorf("continuation %s: native clone writes: %w", out.Name, err), v.Disk.Detach(ctx, att))
		}
	}
	if usesCloneCopyContinuation(out) {
		source, sibling := cloneCopyContinuationPeers(out)
		if err := v.continueCloneWritesFrom(ctx, volume.Mount, filepath.Join(work, "clone-native-source"), source, sibling); err != nil {
			_ = v.Disk.Detach(ctx, att)
			return nil, fmt.Errorf("continuation %s: native clone-copy writes: %w", out.Name, err)
		}
	}
	if err := v.nativeWrites(ctx, volume.Mount, filepath.Join(work, "native-source")); err != nil {
		return nil, errors.Join(fmt.Errorf("continuation %s: native writes: %w", out.Name, err), v.Disk.Detach(ctx, att))
	}
	for _, vol := range att.Volumes {
		if vol.Mount != "" {
			if err := v.Disk.Unmount(ctx, vol); err != nil {
				return nil, errors.Join(err, v.Disk.Detach(ctx, att))
			}
		}
	}
	if err := v.Disk.Detach(ctx, att); err != nil {
		return nil, err
	}
	if err := v.fsckContinuation(ctx, raw, volume.FS, expectedObservation, k.recipe); err != nil {
		return nil, fmt.Errorf("continuation %s after native writes: %w", out.Name, err)
	}
	sourceObservation, err := snapshotOutputReference(out, v.Cases[CaseKey(out.Source)].Observation)
	if err != nil {
		return nil, err
	}
	nativeSpec := schema.ObserveSpec{Snapshots: hasHistoricalViews(sourceObservation) || len(out.Expect.DeletedSnapshots) > 0}
	if requiresPreservedForkSharing(out) {
		nativeSpec.Extents, nativeSpec.Samples = conversionExtentPaths(sourceObservation), 8
	}
	nativeSpec.Unlock, nativeSpec.Rejected = volumeCredentials(expectedObservation)
	if out.Source.Recipe == "apfs-clones" {
		nativeSpec.Extents, nativeSpec.Samples = append(cloneExtentPaths(), retainedPartialClone), 12
	}
	if usesCloneCopyContinuation(out) {
		nativeSpec.Extents, nativeSpec.Samples = append(cloneCopyExtentPaths(out.Expect.Subtree), retainedPartialClone), 12
	}
	before, err := v.observeImage(ctx, out.Name+".native-state", raw, "raw", nil, nativeSpec, k.recipe)
	if err != nil {
		return nil, fmt.Errorf("continuation %s: native state: %w", out.Name, err)
	}
	if nativeSpec.Snapshots {
		if err := compareHistoricalViews(before, sourceObservation); err != nil {
			return before, fmt.Errorf("continuation %s after native writes: %w", out.Name, err)
		}
	}
	if requiresPreservedForkSharing(out) {
		if err := checkConvertedSharing(before, sourceObservation); err != nil {
			return before, err
		}
	}
	if len(out.Expect.DeletedSnapshots) > 0 {
		d, err := comparePreservedVolumeMetadata(before, sourceObservation)
		if err != nil || len(d) != 0 {
			return before, fmt.Errorf("snapshot deletion metadata after native writes: %v: %v", d, err)
		}
	}
	var cloneBefore schema.View
	if out.Source.Recipe == "apfs-clones" {
		cloneBefore, err = onlyLiveView(before)
		if err == nil {
			err = requireRetainedPartialClone(cloneBefore)
		}
		if err != nil {
			return nil, fmt.Errorf("continuation %s: native partial clone input: %w", out.Name, err)
		}
	}
	if usesCloneCopyContinuation(out) {
		cloneBefore, err = onlyLiveView(before)
		if err == nil {
			source, _ := cloneCopyContinuationPeers(out)
			err = requireCloneCopyPartial(cloneBefore, source)
		}
		if err != nil {
			return nil, fmt.Errorf("continuation %s: native partial clone-copy input: %w", out.Name, err)
		}
	}
	partition, err := continuationPartition(envelope.imageinfo, before, volume.UUID)
	if err != nil {
		return nil, fmt.Errorf("continuation %s: select native filesystem partition: %w", out.Name, err)
	}
	// The product edits the natively modified volume into a new image.
	editSource, imageArgs, err := v.prepareEncryptedContinuation(ctx, envelope, raw, work)
	if err != nil {
		return nil, err
	}
	edited := filepath.Join(work, "edited.dmg")
	argv := []string{v.Product, "edit", "--image", editSource, "--output", edited, "--format", "UDZO", "--time", "2025-06-07T08:09:10Z", "--partition", strconv.Itoa(partition)}
	argv = append(argv, imageArgs...)
	volumeArgs, err := continuationVolumeArguments(work, volume.UUID, expectedObservation, k.recipe)
	if err != nil {
		return nil, err
	}
	argv = append(argv, volumeArgs...)
	if out.Expect.SystemMember != "" || multiVolume {
		argv = append(argv, "--volume", volume.UUID)
	}
	argv = append(argv, "--", "mkdir", "/native-continuation/go", "--next", "cp", "--from-host", filepath.Join(work, "go-payload"), "/native-continuation/go/payload", "--next", "rm", "/native-continuation/entry-00001", "--next", "ln", "/native-continuation/go/payload", "/native-continuation/go/alias")
	if hasEncryptedVolumes(expectedObservation) {
		argv = append(argv, "--next", "cp", "--resource-fork", "--from-host", filepath.Join(work, "go-payload"), "/native-continuation/go/payload", "--next", "xattr", "-w", "--value-file", filepath.Join(work, "go-payload"), "org.go-apfs.encrypted", "/native-continuation/go/payload")
	}
	if err := os.WriteFile(filepath.Join(work, "go-payload"), []byte(strings.Repeat("continued by the product\n", 400)), 0o644); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	var refusalSource string
	if out.Expect.ContinuationRefusal != "" {
		refusalSource, err = schema.FileDigest(editSource)
		if err != nil {
			return nil, err
		}
	}
	outb, err := cmd.CombinedOutput()
	if writeErr := os.WriteFile(filepath.Join(work, "product-edit.log"), outb, 0o644); writeErr != nil {
		return nil, writeErr
	}
	if refusal := out.Expect.ContinuationRefusal; refusal != "" {
		if err == nil {
			return nil, fmt.Errorf("continuation %s: the product edit succeeded although %q was expected; the limit is lifted, so remove the expected refusal", out.Name, refusal)
		}
		if !strings.Contains(string(outb), refusal) {
			return nil, fmt.Errorf("continuation %s: product edit failed differently from the tracked limit %q: %v\n%s", out.Name, refusal, err, outb)
		}
		if _, statErr := os.Lstat(edited); !errors.Is(statErr, fs.ErrNotExist) {
			return nil, fmt.Errorf("continuation %s: refused edit published a destination: %v", out.Name, statErr)
		}
		if digest, digestErr := schema.FileDigest(editSource); digestErr != nil || digest != refusalSource {
			return nil, fmt.Errorf("continuation %s: refused edit changed its native input: %v", out.Name, digestErr)
		}
		return nil, KnownLimit{Refusal: refusal}
	}
	if err != nil {
		return nil, fmt.Errorf("continuation %s: product edit: %v\n%s", out.Name, err, outb)
	}
	if err := v.checkContinuationEnvelope(ctx, envelope, edited); err != nil {
		return nil, fmt.Errorf("continuation %s: %w", out.Name, err)
	}
	spec := nativeSpec
	spec.Checks, spec.Codesign = []string{"verify", "fsck"}, out.Expect.Codesign
	obs, err := v.observeImage(ctx, out.Name+".continued", edited, "UDZO", envelope.password, spec, k.recipe)
	if err != nil {
		return nil, err
	}
	if requiresPreservedForkSharing(out) {
		if err := checkConvertedSharing(obs, sourceObservation); err != nil {
			return obs, err
		}
	}
	if hasEncryptedVolumes(expectedObservation) {
		if err := checkEncryptedContinuationStreams(obs, volume.Name); err != nil {
			return obs, err
		}
	}
	if err := compareContinuedContainer(before, obs, volume.Name); err != nil {
		return obs, fmt.Errorf("continuation %s: %w", out.Name, err)
	}
	if out.Source.Recipe == "apfs-clones" {
		differences, err := cloneOutputDifferences(obs, cloneBefore)
		if err != nil {
			return obs, fmt.Errorf("continuation %s: continued clone sharing: %w", out.Name, err)
		}
		if len(differences) != 0 {
			return obs, fmt.Errorf("continuation %s: continued clone sharing differs: %v", out.Name, differences)
		}
	}
	if usesCloneCopyContinuation(out) {
		if err := compareCloneCopyContinuation(obs, before, out); err != nil {
			return obs, fmt.Errorf("continuation %s: continued clone-copy sharing: %w", out.Name, err)
		}
	}
	paths := map[string]bool{}
	for _, vw := range obs.Views {
		for _, e := range vw.Entries {
			paths[e.Path] = true
		}
	}
	var missing []string
	for _, want := range []string{"native-continuation/go/payload", "native-continuation/go/alias", "native-continuation/reused", "native-continuation/renamed"} {
		if !paths[want] {
			missing = append(missing, want)
		}
	}
	if len(missing) > 0 {
		var seen []string
		for _, vw := range obs.Views {
			name := ""
			if vw.Volume < len(obs.Volumes) {
				name, _ = obs.Volumes[vw.Volume].Diskutil["VolumeName"].(string)
			}
			seen = append(seen, fmt.Sprintf("%s:%d entries", name, len(vw.Entries)))
		}
		return obs, fmt.Errorf("continuation %s: %v missing after the product edit of volume %s (%s); observed %v", out.Name, missing, volume.Name, volume.UUID, seen)
	}
	if paths["native-continuation/entry-00001"] {
		return obs, fmt.Errorf("continuation %s: entry removed by the product still present", out.Name)
	}
	return v.nativeWriteAfterEdit(ctx, out, edited, work, volume.Name, obs, k.recipe, envelope)
}

// KnownLimit reports that the continuation's native writes passed and the
// product edit failed exactly as a tracked product limit predicts.
type KnownLimit struct{ Refusal string }

func (k KnownLimit) Error() string { return "product edit refused by a tracked limit: " + k.Refusal }

// onlyKnownLimit keeps an independently failed cleanup or cancellation fatal
// when it is joined with a tracked product refusal. errors.As alone would find
// that refusal anywhere in the error tree and hide the other failures.
func onlyKnownLimit(err error) bool {
	switch value := err.(type) {
	case KnownLimit:
		return true
	case *KnownLimit:
		return value != nil
	case interface{ Unwrap() []error }:
		children := value.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !onlyKnownLimit(child) {
				return false
			}
		}
		return true
	case interface{ Unwrap() error }:
		return onlyKnownLimit(value.Unwrap())
	default:
		return false
	}
}

// schemaCase carries the recipe an output's source came from.
type schemaCase struct{ recipe schema.Recipe }

// nativeWrites is the continuation sequence: bulk creation past the
// builder's object IDs, growth, links, renames, removal, reuse, large
// attributes, a resource fork and native compression.
func (v *Verifier) nativeWrites(ctx context.Context, mount, stage string) error {
	root := filepath.Join(mount, "native-continuation")
	if err := v.writableDirectory(ctx, root); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(stage, "tree"), 0o755); err != nil {
		return err
	}
	return v.writeContinuationTree(ctx, root, stage)
}

func (v *Verifier) writableDirectory(ctx context.Context, root string) error {
	if err := v.Vol.Mkdir(root, 0o755); errors.Is(err, fs.ErrPermission) {
		// A volume root owned by another user (as Apple's own fixtures
		// are) takes the continuation directory the way recipes create
		// theirs: as root, then handed to the runner's user.
		t := &fixture.Transcript{}
		v.setTranscript(t)
		for _, argv := range [][]string{{"mkdir", root}, {"chown", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), root}} {
			cmd := fixture.Command{Argv: argv, Sudo: true, Expected: "0"}
			if err := t.Record(cmd, v.C.Run(ctx, cmd)); err != nil {
				return err
			}
		}
	} else if err != nil {
		return err
	}
	return nil
}

func (v *Verifier) writeContinuationTree(ctx context.Context, root, stage string) error {
	for i := 0; i < 2000; i++ {
		dir := filepath.Join(stage, "tree", fmt.Sprintf("d%02d", i%64))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%05d", i)), []byte(fmt.Sprintf("native %d\n", i)), 0o644); err != nil {
			return err
		}
	}
	t := &fixture.Transcript{}
	v.setTranscript(t)
	run := func(argv ...string) error {
		cmd := fixture.Command{Argv: argv, Expected: "0", Timeout: 5 * time.Minute}
		return t.Record(cmd, v.C.Run(ctx, cmd))
	}
	if err := run("ditto", filepath.Join(stage, "tree"), filepath.Join(root, "tree")); err != nil {
		return err
	}
	for i := 0; i < 96; i++ {
		if err := v.Vol.WriteFile(filepath.Join(root, fmt.Sprintf("entry-%05d", i)), make([]byte, 8193), true); err != nil {
			return err
		}
	}
	grow := filepath.Join(root, "grow")
	if err := v.Vol.WriteFile(grow, make([]byte, 512<<10), true); err != nil {
		return err
	}
	if err := v.Vol.AppendFile(grow, make([]byte, 1<<20)); err != nil {
		return err
	}
	if err := v.Vol.Fullfsync(grow); err != nil {
		return err
	}
	if err := run("ln", grow, filepath.Join(root, "alias")); err != nil {
		return err
	}
	if err := v.Vol.AppendFile(filepath.Join(root, "alias"), []byte("written through the alias\n")); err != nil {
		return err
	}
	if err := run("mv", filepath.Join(root, "alias"), filepath.Join(root, "Alias")); err != nil {
		return err
	}
	if err := run("mv", filepath.Join(root, "Alias"), filepath.Join(root, "renamed")); err != nil {
		return err
	}
	if err := run("mv", filepath.Join(root, "tree", "d00"), filepath.Join(root, "moved")); err != nil {
		return err
	}
	for i := 0; i < 96; i += 2 {
		if err := v.Vol.Remove(filepath.Join(root, fmt.Sprintf("entry-%05d", i))); err != nil {
			return err
		}
	}
	if err := run("rm", "-r", filepath.Join(root, "tree", "d01")); err != nil {
		return err
	}
	if err := v.Vol.WriteFile(filepath.Join(root, "reused"), make([]byte, 512<<10), true); err != nil {
		return err
	}
	large := make([]byte, 32<<10)
	for i := range large {
		large[i] = byte(i)
	}
	if err := v.Vol.Setxattr(grow, "org.go-apfs.continuation", large, ""); err != nil {
		return err
	}
	if err := v.Vol.Setxattr(grow, "org.go-apfs.removed", []byte("x"), ""); err != nil {
		return err
	}
	if err := v.Vol.Removexattr(grow, "org.go-apfs.removed"); err != nil {
		return err
	}
	if err := v.Vol.WriteFile(filepath.Join(root, "reused", "..namedfork", "rsrc"), []byte("resource fork after native writes"), false); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(stage, "compressible"), []byte(strings.Repeat("native compression after portable construction\n", 4096)), 0o644); err != nil {
		return err
	}
	return run("ditto", "--hfsCompression", "--noclone", filepath.Join(stage, "compressible"), filepath.Join(root, "compressed"))
}

func (v *Verifier) fsckRaw(ctx context.Context, raw, fs string) error {
	att, err := v.Disk.Attach(ctx, raw, fixture.AttachOptions{Raw: true, ReadOnly: true})
	if err != nil {
		return err
	}
	rdev := att.RDev
	if fs != "apfs" {
		if len(att.Volumes) == 0 {
			return errors.Join(fmt.Errorf("fsck %s: no %s volume discovered on the attached copy", raw, fs), v.Disk.Detach(ctx, att))
		}
		rdev = att.Volumes[0].RDev
	}
	_, err = v.Disk.Fsck(ctx, fs, rdev)
	err = errors.Join(err, v.Disk.Detach(ctx, att))
	return err
}
