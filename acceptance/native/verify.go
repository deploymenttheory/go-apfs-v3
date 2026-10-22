package native

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// Verifier holds what one macOS job needs: the corpus, every host's
// outputs, the recipes (for passwords) and the product binary.
type Verifier struct {
	Major             int
	Corpus            *corpus.Corpus
	Cases             map[string]corpus.Case // producer/recipe/profile/stage
	Recipes           map[string]schema.Recipe
	Drift             *schema.KnownDrift
	Product           string // path to the product command-line binary
	Work              string
	Disk              fixture.Disk
	Vol               fixture.Volume
	C                 fixture.Commander
	Producer          schema.Producer
	AppleDoubleUnpack string // guarded public copyfile(3) adapter, built once
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
		found := false
		for _, vol := range k.Observation.Volumes {
			if name, _ := vol.Diskutil["VolumeName"].(string); name == out.Expect.Volume {
				if found {
					return corpus.Case{}, schema.View{}, fmt.Errorf("output %s: duplicate expected volume %q", out.Name, name)
				}
				volume = vol.Index
				found = true
			}
		}
		if !found {
			return corpus.Case{}, schema.View{}, fmt.Errorf("output %s: expected volume %q is absent", out.Name, out.Expect.Volume)
		}
	}
	for _, view := range k.Observation.Views {
		if view.Volume == volume && view.Snapshot == out.Expect.Snapshot {
			return k, view, nil
		}
	}
	return corpus.Case{}, schema.View{}, fmt.Errorf("output %s: case %s has no view for volume %d snapshot %q", out.Name, CaseKey(ref), volume, out.Expect.Snapshot)
}

// observeImage attaches an image read-only and records it with the same
// observer the capture tool uses.
func (v *Verifier) observeImage(ctx context.Context, label, image, format string, password []byte, spec schema.ObserveSpec, recipe schema.Recipe) (*schema.Observation, error) {
	return v.observeImageWithDigest(ctx, label, image, format, password, spec, recipe, false)
}

// observeImageWithDigest keeps complete file hashes while allowing transient
// readbacks to omit an unasserted whole-device hash. Captures retain both hashes.
func (v *Verifier) observeImageWithDigest(ctx context.Context, label, image, format string, password []byte, spec schema.ObserveSpec, recipe schema.Recipe, deviceDigest bool) (*schema.Observation, error) {
	t := &fixture.Transcript{}
	if disk, ok := v.Disk.(fixture.TranscriptUser); ok {
		disk.SetTranscript(t)
	}
	raw := strings.HasSuffix(image, ".raw")
	att, err := v.Disk.Attach(ctx, image, fixture.AttachOptions{ReadOnly: true, Raw: raw, Password: password})
	if err != nil {
		return nil, err
	}
	if len(att.Volumes) == 0 {
		_ = v.Disk.Detach(ctx, att)
		return nil, fmt.Errorf("%s: no volume discovered on the attached image", label)
	}
	work := filepath.Join(v.Work, "observe", sanitize(label))
	_ = os.RemoveAll(work)
	vars := &fixture.Vars{Passwords: recipe.Passwords}
	obs, err := fixture.Observe(ctx, fixture.ObserveInput{Recipe: &recipe, Profile: schema.Profile{ID: "output"}, Stage: label, Spec: spec, Image: image, Format: format, Password: password, Att: att, Disk: v.Disk, Vol: v.Vol, Vars: vars, T: t, Work: work, Out: filepath.Join(v.Work, "exports"), Prefix: sanitize(label), Producer: v.Producer, OmitDeviceDigest: !deviceDigest})
	if derr := v.Disk.Detach(ctx, att); err == nil {
		err = derr
	}
	if obs != nil {
		obs.Commands = t.Commands
		data, writeErr := json.MarshalIndent(obs, "", "  ")
		if writeErr == nil {
			writeErr = os.MkdirAll(work, 0o755)
		}
		if writeErr == nil {
			writeErr = os.WriteFile(filepath.Join(work, "observation.json"), append(data, '\n'), 0o644)
		}
		if err == nil {
			err = writeErr
		}
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
	if out.Expect.CommandClockNS != 0 && (out.Source.Recipe != "clone-copy" || out.Operation != "edit" && out.Operation != "build") {
		return nil, fmt.Errorf("output %s declares an unqualified command clock", out.Name)
	}
	k, want, err := v.expectedView(out)
	if err != nil {
		return nil, err
	}
	if out.Expect.AppleDouble != nil {
		return v.verifyAppleDouble(ctx, p, k, want)
	}
	if out.Expect.Workspace != nil {
		sourceOutput := out
		sourceOutput.Expect.View = ""
		_, sourceView, err := v.expectedView(sourceOutput)
		if err != nil {
			return nil, fmt.Errorf("workspace source: %w", err)
		}
		var identity *workspaceSourceIdentity
		if out.Expect.Snapshot != "" {
			identity, err = historicalWorkspaceIdentity(v.Cases[CaseKey(out.Source)], sourceView, out.Expect)
			if err != nil {
				return nil, err
			}
		}
		// Preservation manifests retain host availability/default provenance.
		// Judge every host's actual bytes independently against the same Apple
		// view, including all logical/raw data and attributes.
		var diffs []Difference
		var hosts []string
		for host := range p.ByHost {
			hosts = append(hosts, host)
		}
		slices.Sort(hosts)
		for _, host := range hosts {
			o := p.ByHost[host]
			filename := filepath.Join(p.Dirs[host], o.File)
			if sum, err := schema.FileDigest(filename); err != nil || sum != o.SHA256 {
				return nil, fmt.Errorf("%s: workspace archive digest mismatch (%v)", host, err)
			}
			d, err := verifyWorkspaceArchive(filename, out.Source.Profile, sourceView, want, out.Expect, identity)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", host, err)
			}
			for _, difference := range d {
				difference.Path = host + ":" + difference.Path
				diffs = append(diffs, difference)
			}
		}
		return diffs, nil
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
		// Every selected host's ciphertext must decrypt to the same device
		// bytes.
		for host, o := range p.ByHost {
			if len(p.DecryptHosts) > 0 && !slices.Contains(p.DecryptHosts, host) {
				continue
			}
			att, err := v.Disk.Attach(ctx, filepath.Join(p.Dirs[host], o.File), fixture.AttachOptions{ReadOnly: true, Password: password, NoInventory: true})
			if err != nil {
				return nil, fmt.Errorf("output %s on %s: %w", out.Name, host, err)
			}
			d, _, err := v.Disk.DeviceDigest(ctx, att.RDev, "")
			digests = append(digests, d)
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
	isRecovery := strings.HasPrefix(out.Operation, "recover-")
	if out.Expect.DiskSHA256 != "" && out.Operation != "edit" && !isRecovery {
		if len(p.DecryptHosts) > 0 {
			image = filepath.Join(p.Dirs[p.DecryptHosts[0]], p.ByHost[p.DecryptHosts[0]].File)
		}
		return v.verifyContainer(ctx, out, image, password, digests, !p.SkipChecksums)
	}
	spec := schema.ObserveSpec{Checks: []string{"verify", "fsck"}, Codesign: out.Expect.Codesign}
	if out.Source.Recipe == "apfs-clones" {
		spec.Extents, spec.Samples = cloneExtentPaths(), 12
	}
	if out.Source.Recipe == "clone-copy" && (out.Operation == "edit" || out.Operation == "build") {
		spec.Extents, spec.Samples = cloneCopyExtentPaths(out.Expect.Subtree), 8
	}
	spec.Unlock, spec.Rejected = volumeCredentials(k.Observation)
	obs, err := v.observeImageWithDigest(ctx, out.Name, image, out.Format, password, spec, recipe, out.Expect.DiskSHA256 != "" || out.Expect.Container != nil)
	if err != nil {
		return nil, err
	}
	var diffs []Difference
	if err := v.checkEncryptedEditPolicy(out, obs); err != nil {
		return nil, err
	}
	if err := v.checkReplacedImagePassword(ctx, p, image); err != nil {
		return nil, err
	}
	if out.Expect.SelectedXID != 0 && obs.Checks.SelectedXID != out.Expect.SelectedXID {
		diffs = append(diffs, Difference{Field: "checks.selectedXID", Got: fmt.Sprint(obs.Checks.SelectedXID), Want: fmt.Sprint(out.Expect.SelectedXID)})
	}
	if out.Expect.DiskSHA256 != "" && obs.Image.DiskSHA256 != out.Expect.DiskSHA256 {
		diffs = append(diffs, Difference{Path: "", Field: "image.diskSHA256", Got: obs.Image.DiskSHA256, Want: out.Expect.DiskSHA256})
	}
	for _, c := range obs.Checks.Codesign {
		if c.Status != 0 {
			diffs = append(diffs, Difference{Path: c.Path, Field: "codesign", Got: fmt.Sprint(c.Status), Want: "0"})
		}
	}
	if out.Expect.Container == nil && len(obs.Checks.Codesign) != len(out.Expect.Codesign) {
		diffs = append(diffs, Difference{Field: "codesign", Got: fmt.Sprint(len(obs.Checks.Codesign)), Want: fmt.Sprint(len(out.Expect.Codesign))})
	}
	if out.Expect.Container != nil {
		d, err := v.compareConstructedContainer(obs, k, out)
		return append(diffs, d...), err
	}
	if out.Expect.DiskSHA256 == "" || out.Operation == "edit" || isRecovery {
		ignore := map[string]bool{}
		for _, name := range out.Expect.IgnoreTimes {
			ignore[name] = true
		}
		opts := CompareOptions{Subtree: out.Expect.Subtree, IgnoreTimes: ignore, IgnoreIdentity: out.Operation == "build" || out.Operation == "encrypt", FileCompression: out.Expect.FileCompression}
		if out.Expect.NewIdentities {
			opts.Existing = v.existingPaths(out.Source, want.Volume)
		}
		if opts.IgnoreIdentity && out.Expect.CommandClockNS == 0 {
			for _, name := range []string{"birth", "modify", "change", "access"} {
				opts.IgnoreTimes[name] = true
			}
		}
		if opts.IgnoreIdentity {
			if out.Source.Recipe == "clone-copy" {
				var err error
				want, err = v.cloneCopyClockView(out, k.Observation)
				if err != nil {
					return nil, err
				}
			}
			view, err := onlyLiveView(obs)
			if err != nil {
				return nil, err
			}
			diffs = append(diffs, CompareViews(view, want, opts)...)
		} else {
			d, err := v.compareEditedVolumes(obs, k, out, opts)
			if err != nil {
				return nil, err
			}
			diffs = append(diffs, d...)
		}
	}
	if out.Source.Recipe == "apfs-clones" && out.Operation == "edit" {
		sharing, err := cloneOutputDifferences(obs, want)
		if err != nil {
			return nil, err
		}
		diffs = append(diffs, sharing...)
	}
	if out.Source.Recipe == "clone-copy" && (out.Operation == "edit" || out.Operation == "build") {
		sharing, err := cloneCopyOutputDifferences(obs, want, out.Expect.Subtree)
		if err != nil {
			return nil, err
		}
		diffs = append(diffs, sharing...)
	}
	return diffs, nil
}

// verifyContainer judges a sector-preserving output: its sectors equal
// Apple's own image, which the producing Mac mounted and checked, so what
// Apple must still accept is the container. hdiutil verifies the UDIF
// checksums and the attached device must hash to the source disk; an
// encrypted output's copies were already decrypted on every host.
func (v *Verifier) verifyContainer(ctx context.Context, out schema.Output, image string, password []byte, encrypted []string, checksums bool) ([]Difference, error) {
	if checksums {
		if err := v.Disk.Verify(ctx, image, password); err != nil {
			return nil, fmt.Errorf("output %s: %w", out.Name, err)
		}
	}
	digests := encrypted
	read := ""
	if len(digests) == 0 {
		att, err := v.Disk.Attach(ctx, image, fixture.AttachOptions{ReadOnly: true, NoInventory: true})
		if err != nil {
			return nil, fmt.Errorf("output %s: %w", out.Name, err)
		}
		d, n, err := v.Disk.DeviceDigest(ctx, att.RDev, "")
		digests = append(digests, d)
		read = fmt.Sprintf(" (read %d bytes from %s)", n, att.RDev)
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
			diffs = append(diffs, Difference{Field: "image.diskSHA256", Got: d + read + v.locateDifference(ctx, out, image, password), Want: out.Expect.DiskSHA256})
		}
	}
	return diffs, nil
}

// locateDifference attaches the output and its source fixture one after
// the other and reports where their devices first differ, so a container
// mismatch can be diagnosed from the job log.
func (v *Verifier) locateDifference(ctx context.Context, out schema.Output, image string, password []byte) string {
	k, ok := v.Cases[CaseKey(out.Source)]
	if !ok {
		return " (source case missing)"
	}
	var sourcePassword []byte
	if enc := k.Observation.Image.Encryption; enc != nil {
		sourcePassword = []byte(v.Recipes[k.Recipe].Passwords[enc.Password])
	}
	got, err := v.blockDigests(ctx, image, password)
	if err != nil {
		return " (output blocks: " + err.Error() + ")"
	}
	want, err := v.blockDigests(ctx, k.Image(), sourcePassword)
	if err != nil {
		return " (source blocks: " + err.Error() + ")"
	}
	first, count := -1, 0
	for i := 0; i < len(got) || i < len(want); i++ {
		if i >= len(got) || i >= len(want) || got[i] != want[i] {
			if first < 0 {
				first = i
			}
			count++
		}
	}
	return fmt.Sprintf(" (device %d bytes, source %d bytes; %d of %d MiB blocks differ, first at offset %d)", len(got)<<20, len(want)<<20, count, max(len(got), len(want)), int64(first)<<20)
}

// blockDigests attaches an image read-only and hashes its device in 1 MiB
// blocks.
func (v *Verifier) blockDigests(ctx context.Context, image string, password []byte) ([][32]byte, error) {
	att, err := v.Disk.Attach(ctx, image, fixture.AttachOptions{ReadOnly: true, Raw: strings.HasSuffix(image, ".raw"), Password: password, NoInventory: true})
	if err != nil {
		return nil, err
	}
	defer func() { _ = v.Disk.Detach(ctx, att) }()
	f, err := os.Open(att.RDev)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var blocks [][32]byte
	buf := make([]byte, 1<<20)
	for {
		n, err := io.ReadFull(f, buf)
		if n > 0 {
			blocks = append(blocks, sha256.Sum256(buf[:n]))
		}
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return blocks, nil
			}
			return blocks, err
		}
	}
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
	for _, view := range k.Observation.Views {
		spec.Snapshots = spec.Snapshots || view.Snapshot != ""
	}
	spec.Unlock, spec.Rejected = volumeCredentials(k.Observation)
	image := k.Image()
	obs, err := v.observeImage(ctx, fmt.Sprintf("drift-%d-%s-%s-%s", k.Producer, k.Recipe, k.Profile, k.Stage), image, k.Observation.Image.Format, password, spec, recipe)
	if err != nil {
		return nil, nil, err
	}
	var known, unknown []Difference
	viewDiffs, err := compareObservationViews(obs, k.Observation, CompareOptions{})
	if err != nil {
		return nil, nil, err
	}
	for _, d := range viewDiffs {
		if KnownDrift(v.Drift, k.Recipe, k.Profile, d, [2]int{v.Major, k.Producer}) {
			known = append(known, d)
		} else {
			unknown = append(unknown, d)
		}
	}
	return known, unknown, nil
}

// volumeCredentials names each locked volume's own password and rejected
// passwords, as the observation recorded them; volumes of one container
// carry different credentials.
func volumeCredentials(obs *schema.Observation) (map[string]string, map[string][]string) {
	unlock := map[string]string{}
	rejected := map[string][]string{}
	for _, vol := range obs.Volumes {
		if vol.APFS == nil || vol.APFS.Password == "" {
			continue
		}
		name, _ := vol.Diskutil["VolumeName"].(string)
		unlock[name] = vol.APFS.Password
		if len(vol.APFS.Rejected) > 0 {
			rejected[name] = vol.APFS.Rejected
		}
	}
	if len(unlock) == 0 {
		return nil, nil
	}
	return unlock, rejected
}

// existingPaths lists the entries of a source case's live view of one
// volume, the identities an edit must preserve.
func (v *Verifier) existingPaths(source schema.CaseRef, volume int) map[string]bool {
	out := map[string]bool{}
	k, ok := v.Cases[CaseKey(source)]
	if !ok {
		return out
	}
	for _, view := range k.Observation.Views {
		if view.Volume == volume && view.Snapshot == "" {
			for _, e := range view.Entries {
				out[e.Path] = true
			}
		}
	}
	return out
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '/' || r == ' ' || r == 0 {
			return '_'
		}
		return r
	}, s)
}
