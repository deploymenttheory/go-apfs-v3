package native

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// Continuation performs the native write sequence on a writable raw copy
// of an output, checks the volume with fsck, runs a further edit with the
// product binary, and checks again. It returns the observation of the
// final state. The sequence exercises the allocator past the object IDs a
// builder assigned, which is where the System volume object-ID namespace
// once panicked the kernel.
func (v *Verifier) Continuation(ctx context.Context, p Paired, k schemaCase) (*schema.Observation, error) {
	out := p.Output
	image := filepath.Join(p.Dirs[p.Primary], p.ByHost[p.Primary].File)
	work := filepath.Join(v.Work, "continuation", sanitize(out.Name))
	if err := os.MkdirAll(work, 0o755); err != nil {
		return nil, err
	}
	raw := filepath.Join(work, "writable.raw")
	// A raw copy, not a shadow: HFS shadow writes left a stale alternate
	// header in the retired harness.
	att, err := v.Disk.Attach(ctx, image, fixture.AttachOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	info, err := v.Disk.Info(ctx, att.Dev)
	if err == nil {
		_, err = v.Disk.DeviceDigest(ctx, att.RDev, int64(number(info["TotalSize"])), raw+".gz")
	}
	if derr := v.Disk.Detach(ctx, att); err == nil {
		err = derr
	}
	if err != nil {
		return nil, err
	}
	if err := gunzip(raw+".gz", raw); err != nil {
		return nil, err
	}
	att, err = v.Disk.Attach(ctx, raw, fixture.AttachOptions{Raw: true})
	if err != nil {
		return nil, err
	}
	volume := att.Volumes[0]
	if out.Expect.SystemMember != "" {
		if vol := att.Volume(out.Expect.SystemMember); vol != nil {
			volume = vol
		}
	}
	for _, vol := range att.Volumes {
		if vol.Locked {
			continue
		}
		if err := v.Disk.Mount(ctx, vol, "owners,noatime", filepath.Join(work, "mnt", sanitize(vol.Name)), false); err != nil {
			_ = v.Disk.Detach(ctx, att)
			return nil, err
		}
	}
	if volume.Mount == "" {
		_ = v.Disk.Detach(ctx, att)
		return nil, fmt.Errorf("continuation %s: volume %s is not mounted", out.Name, volume.Name)
	}
	if err := v.nativeWrites(ctx, volume.Mount); err != nil {
		_ = v.Disk.Detach(ctx, att)
		return nil, fmt.Errorf("continuation %s: native writes: %w", out.Name, err)
	}
	for _, vol := range att.Volumes {
		if vol.Mount != "" {
			if err := v.Disk.Unmount(ctx, vol); err != nil {
				_ = v.Disk.Detach(ctx, att)
				return nil, err
			}
		}
	}
	if err := v.Disk.Detach(ctx, att); err != nil {
		return nil, err
	}
	if err := v.fsckRaw(ctx, raw, volume.FS); err != nil {
		return nil, fmt.Errorf("continuation %s after native writes: %w", out.Name, err)
	}
	// The product edits the natively modified volume into a new image.
	edited := filepath.Join(work, "edited.dmg")
	argv := []string{v.Product, "edit", "--image", raw, "--output", edited, "--format", "UDZO", "--time", "2025-06-07T08:09:10Z"}
	if out.Expect.SystemMember != "" {
		argv = append(argv, "--volume", volume.UUID)
	}
	argv = append(argv, "--", "mkdir", "/native-continuation/go", "--next", "cp", "--from-host", filepath.Join(work, "go-payload"), "/native-continuation/go/payload", "--next", "rm", "/native-continuation/entry-00001", "--next", "ln", "/native-continuation/go/payload", "/native-continuation/go/alias")
	if err := os.WriteFile(filepath.Join(work, "go-payload"), []byte(strings.Repeat("continued by the product\n", 400)), 0o644); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	if outb, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("continuation %s: product edit: %v\n%s", out.Name, err, outb)
	}
	spec := schema.ObserveSpec{Checks: []string{"verify", "fsck"}, Codesign: out.Expect.Codesign}
	obs, err := v.observeImage(ctx, out.Name+".continued", edited, "UDZO", nil, spec, k.recipe)
	if err != nil {
		return nil, err
	}
	paths := map[string]bool{}
	for _, vw := range obs.Views {
		for _, e := range vw.Entries {
			paths[e.Path] = true
		}
	}
	for _, want := range []string{"native-continuation/go/payload", "native-continuation/go/alias", "native-continuation/reused", "native-continuation/renamed"} {
		if !paths[want] {
			return obs, fmt.Errorf("continuation %s: %s missing after the product edit", out.Name, want)
		}
	}
	if paths["native-continuation/entry-00001"] {
		return obs, fmt.Errorf("continuation %s: entry removed by the product still present", out.Name)
	}
	return obs, nil
}

// schemaCase carries the recipe an output's source came from.
type schemaCase struct{ recipe schema.Recipe }

// nativeWrites is the continuation sequence: bulk creation past the
// builder's object IDs, growth, links, renames, removal, reuse, large
// attributes, a resource fork and native compression.
func (v *Verifier) nativeWrites(ctx context.Context, mount string) error {
	root := filepath.Join(mount, "native-continuation")
	if err := v.Vol.Mkdir(root, 0o755); err != nil {
		return err
	}
	stage := filepath.Join(v.Work, "stage-"+filepath.Base(mount))
	if err := os.MkdirAll(filepath.Join(stage, "tree"), 0o755); err != nil {
		return err
	}
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
	rdev := att.Volumes[0].RDev
	if fs == "apfs" {
		rdev = att.RDev
	}
	_, err = v.Disk.Fsck(ctx, fs, rdev)
	if derr := v.Disk.Detach(ctx, att); err == nil {
		err = derr
	}
	return err
}
