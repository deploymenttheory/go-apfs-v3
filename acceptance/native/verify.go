package native

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// Verifier holds what one macOS job needs: the corpus, every host's
// outputs, the recipes (for passwords) and the product binary.
type Verifier struct {
	Major    int
	Corpus   *corpus.Corpus
	Cases    map[string]corpus.Case // producer/recipe/profile/stage
	Recipes  map[string]schema.Recipe
	Drift    *schema.KnownDrift
	Product  string // path to the product command-line binary
	Work     string
	Disk     fixture.Disk
	Vol      fixture.Volume
	C        fixture.Commander
	Producer schema.Producer
}

// ForSubtest returns a copy of the verifier with its own disk transcript,
// so subtests can run in parallel without sharing recorder state.
func (v *Verifier) ForSubtest() *Verifier {
	c := *v
	c.Disk = &fixture.HostDisk{C: v.C, T: &fixture.Transcript{}}
	return &c
}

// CaseKey names a corpus case the way outputs refer to it.
func CaseKey(ref schema.CaseRef) string {
	return fmt.Sprintf("%d/%s/%s/%s", ref.Producer, ref.Recipe, ref.Profile, ref.Stage)
}

// expectedView returns the observation view an output must match.
func (v *Verifier) expectedView(out schema.Output) (corpus.Case, schema.View, error) {
	ref := out.Source
	if out.Expect.View != "" {
		ref.Stage = out.Expect.View
	}
	k, ok := v.Cases[CaseKey(ref)]
	if !ok {
		return corpus.Case{}, schema.View{}, fmt.Errorf("output %s expects case %s which the corpus lacks", out.Name, CaseKey(ref))
	}
	volume := 0
	if out.Expect.Volume != "" {
		for _, vol := range k.Observation.Volumes {
			if name, _ := vol.Diskutil["VolumeName"].(string); name == out.Expect.Volume {
				volume = vol.Index
			}
		}
	}
	for _, view := range k.Observation.Views {
		if view.Volume == volume && view.Snapshot == "" {
			return k, view, nil
		}
	}
	return corpus.Case{}, schema.View{}, fmt.Errorf("output %s: case %s has no live view for volume %d", out.Name, CaseKey(ref), volume)
}

// observeImage attaches an image read-only and records it with the same
// observer the capture tool uses.
func (v *Verifier) observeImage(ctx context.Context, label, image, format string, password []byte, spec schema.ObserveSpec, recipe schema.Recipe) (*schema.Observation, error) {
	raw := strings.HasSuffix(image, ".raw")
	att, err := v.Disk.Attach(ctx, image, fixture.AttachOptions{ReadOnly: true, Raw: raw, Password: password})
	if err != nil {
		return nil, err
	}
	work := filepath.Join(v.Work, "observe", sanitize(label))
	_ = os.RemoveAll(work)
	t := &fixture.Transcript{}
	vars := &fixture.Vars{Passwords: recipe.Passwords}
	obs, err := fixture.Observe(ctx, fixture.ObserveInput{Recipe: &recipe, Profile: schema.Profile{ID: "output"}, Stage: label, Spec: spec, Image: image, Format: format, Password: password, Att: att, Disk: v.Disk, Vol: v.Vol, Vars: vars, T: t, Work: work, Out: filepath.Join(v.Work, "exports"), Prefix: sanitize(label), Producer: v.Producer})
	if derr := v.Disk.Detach(ctx, att); err == nil {
		err = derr
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	return obs, nil
}

// VerifyOutput checks one paired output with Apple tools and returns the
// differences from its expectation; integrity failures are errors.
func (v *Verifier) VerifyOutput(ctx context.Context, p Paired) ([]Difference, error) {
	out := p.Output
	k, want, err := v.expectedView(out)
	if err != nil {
		return nil, err
	}
	recipe := v.Recipes[k.Recipe]
	var password []byte
	var digests []string
	if out.Encrypted {
		pw, ok := p.Passwords[out.Password]
		if !ok {
			return nil, fmt.Errorf("output %s: password %q unknown", out.Name, out.Password)
		}
		password = []byte(pw)
		// Every host's ciphertext must decrypt to the same device bytes.
		for host, o := range p.ByHost {
			att, err := v.Disk.Attach(ctx, filepath.Join(p.Dirs[host], o.File), fixture.AttachOptions{ReadOnly: true, Password: password})
			if err != nil {
				return nil, fmt.Errorf("output %s on %s: %w", out.Name, host, err)
			}
			info, err := v.Disk.Info(ctx, att.Dev)
			if err == nil {
				var d string
				d, err = v.Disk.DeviceDigest(ctx, att.RDev, int64(number(info["TotalSize"])), "")
				digests = append(digests, d)
			}
			if derr := v.Disk.Detach(ctx, att); err == nil {
				err = derr
			}
			if err != nil {
				return nil, fmt.Errorf("output %s on %s: %w", out.Name, host, err)
			}
		}
		for _, d := range digests[1:] {
			if d != digests[0] {
				return nil, fmt.Errorf("output %s: encrypted copies decrypt to different devices", out.Name)
			}
		}
	}
	image := filepath.Join(p.Dirs[p.Primary], p.ByHost[p.Primary].File)
	if out.Expect.DiskSHA256 != "" && out.Operation != "edit" {
		return v.verifyContainer(ctx, out, image, password, digests)
	}
	spec := schema.ObserveSpec{Checks: []string{"verify", "fsck"}, Codesign: out.Expect.Codesign}
	if k.Observation.Volumes[0].APFS != nil && k.Observation.Volumes[0].APFS.Encrypted {
		spec.Unlock = map[string]string{"*": k.Observation.Volumes[0].APFS.Password}
		spec.Rejected = map[string][]string{"*": k.Observation.Volumes[0].APFS.Rejected}
	}
	obs, err := v.observeImage(ctx, out.Name, image, out.Format, password, spec, recipe)
	if err != nil {
		return nil, err
	}
	var diffs []Difference
	if out.Expect.DiskSHA256 != "" && obs.Image.DiskSHA256 != out.Expect.DiskSHA256 {
		diffs = append(diffs, Difference{Path: "", Field: "image.diskSHA256", Got: obs.Image.DiskSHA256, Want: out.Expect.DiskSHA256})
	}
	for _, c := range obs.Checks.Codesign {
		if c.Status != 0 {
			diffs = append(diffs, Difference{Path: c.Path, Field: "codesign", Got: fmt.Sprint(c.Status), Want: "0"})
		}
	}
	if len(obs.Checks.Codesign) != len(out.Expect.Codesign) {
		diffs = append(diffs, Difference{Field: "codesign", Got: fmt.Sprint(len(obs.Checks.Codesign)), Want: fmt.Sprint(len(out.Expect.Codesign))})
	}
	if out.Expect.DiskSHA256 == "" || out.Operation == "edit" {
		ignore := map[string]bool{}
		for _, name := range out.Expect.IgnoreTimes {
			ignore[name] = true
		}
		opts := CompareOptions{Subtree: out.Expect.Subtree, IgnoreTimes: ignore, IgnoreIdentity: out.Operation == "build" || out.Operation == "encrypt"}
		if opts.IgnoreIdentity {
			for _, name := range []string{"birth", "modify", "change", "access"} {
				opts.IgnoreTimes[name] = true
			}
		}
		view := schema.View{}
		for _, vw := range obs.Views {
			if vw.Snapshot == "" {
				view = vw
				break
			}
		}
		diffs = append(diffs, CompareViews(view, want, opts)...)
	}
	return diffs, nil
}

// verifyContainer judges a sector-preserving output: its sectors equal
// Apple's own image, which the producing Mac mounted and checked, so what
// Apple must still accept is the container. hdiutil verifies the UDIF
// checksums and the attached device must hash to the source disk; an
// encrypted output's copies were already decrypted on every host.
func (v *Verifier) verifyContainer(ctx context.Context, out schema.Output, image string, password []byte, encrypted []string) ([]Difference, error) {
	if err := v.Disk.Verify(ctx, image, password); err != nil {
		return nil, fmt.Errorf("output %s: %w", out.Name, err)
	}
	digests := encrypted
	if len(digests) == 0 {
		att, err := v.Disk.Attach(ctx, image, fixture.AttachOptions{ReadOnly: true})
		if err != nil {
			return nil, fmt.Errorf("output %s: %w", out.Name, err)
		}
		info, err := v.Disk.Info(ctx, att.Dev)
		if err == nil {
			var d string
			d, err = v.Disk.DeviceDigest(ctx, att.RDev, int64(number(info["TotalSize"])), "")
			digests = append(digests, d)
		}
		if derr := v.Disk.Detach(ctx, att); err == nil {
			err = derr
		}
		if err != nil {
			return nil, fmt.Errorf("output %s: %w", out.Name, err)
		}
	}
	var diffs []Difference
	for _, d := range digests {
		if d != out.Expect.DiskSHA256 {
			diffs = append(diffs, Difference{Field: "image.diskSHA256", Got: d, Want: out.Expect.DiskSHA256})
		}
	}
	return diffs, nil
}

// CrossVersionDrift mounts a fixture captured on another macOS version,
// observes it on this one and returns the differences that are not in the
// allow-list.
func (v *Verifier) CrossVersionDrift(ctx context.Context, k corpus.Case) ([]Difference, []Difference, error) {
	recipe := v.Recipes[k.Recipe]
	var password []byte
	if enc := k.Observation.Image.Encryption; enc != nil {
		password = []byte(recipe.Passwords[enc.Password])
	}
	spec := schema.ObserveSpec{}
	if a := k.Observation.Volumes[0].APFS; a != nil && a.Encrypted {
		spec.Unlock = map[string]string{"*": a.Password}
	}
	image := k.Image()
	obs, err := v.observeImage(ctx, fmt.Sprintf("drift-%d-%s-%s-%s", k.Producer, k.Recipe, k.Profile, k.Stage), image, k.Observation.Image.Format, password, spec, recipe)
	if err != nil {
		return nil, nil, err
	}
	var known, unknown []Difference
	for _, want := range k.Observation.Views {
		for _, got := range obs.Views {
			if got.Volume != want.Volume || got.Snapshot != want.Snapshot {
				continue
			}
			for _, d := range CompareViews(got, want, CompareOptions{}) {
				if KnownDrift(v.Drift, k.Recipe, k.Profile, d, [2]int{v.Major, k.Producer}) {
					known = append(known, d)
				} else {
					unknown = append(unknown, d)
				}
			}
			gk, wk := kernelReads(got), kernelReads(want)
			for path, w := range wk {
				if g, ok := gk[path]; ok && g != w {
					d := Difference{Path: path, Field: "compression.kernelRead", Got: g, Want: w}
					if KnownDrift(v.Drift, k.Recipe, k.Profile, d, [2]int{v.Major, k.Producer}) {
						known = append(known, d)
					} else {
						unknown = append(unknown, d)
					}
				}
			}
		}
	}
	return known, unknown, nil
}

func kernelReads(view schema.View) map[string]string {
	out := map[string]string{}
	for _, e := range view.Entries {
		if e.Compression != nil {
			out[e.Path] = e.Compression.KernelRead
		}
	}
	return out
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

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '/' || r == ' ' || r == 0 {
			return '_'
		}
		return r
	}, s)
}
