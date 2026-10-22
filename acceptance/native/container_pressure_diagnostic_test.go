//go:build native && darwin

package native

// TRANSIENT DIAGNOSTIC ONLY. Never merge this file or the diagnostic workflow.
// Both builders run the ORIGINAL 576a476 workload, once, in separate VMs.
import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

const originalPressureCommit = "576a4760203cb1f65ebf6c0137c16568c91df98d"

func TestMatchedContainerPressureDiagnostic(t *testing.T) {
	v := newVerifier(t) // Requires the guarded disposable VM and exact kernel.
	if nativeGroup(t) != "main" {
		t.Fatal("matched diagnostic requires complete main producer inventories")
	}
	builder := os.Getenv("APFS_CONTAINER_BUILDER")
	if builder != "go" && builder != "apple" {
		t.Fatal("APFS_CONTAINER_BUILDER must be go or apple")
	}
	ctx := context.Background()
	v.Work = filepath.Join(v.Work, "matched-container-pressure", builder)
	if err := os.MkdirAll(v.Work, 0o755); err != nil {
		t.Fatal(err)
	}
	traceFile, err := os.Create(filepath.Join(v.Work, "operations.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	trace := &containerPressureTrace{encoder: json.NewEncoder(traceFile)}
	defer func() {
		if err := traceFile.Close(); err != nil {
			t.Error(err)
		}
		if trace.err != nil {
			t.Error("diagnostic trace: ", trace.err)
		}
	}()
	v.C = containerPressureCommander{Commander: v.C, trace: trace}
	v.Disk = &fixture.HostDisk{C: v.C, T: &fixture.Transcript{}}
	// Instrumentation returns the original syscall errors without substitution.
	v.Vol = containerPressureVolume{Volume: v.Vol, trace: trace}
	var pairs []Paired
	for _, hosts := range outputGroups(t, v.Major) {
		group, err := Pair(hosts)
		if err != nil {
			t.Fatal(err)
		}
		pairs = append(pairs, group...)
	}
	for _, require := range []func([]Paired, map[string]corpus.Case, int) error{
		requirePreservationSourceOutputs, requireContainerOutputs,
		requireAppleDoubleOutputs, requireWorkspaceOutputs,
	} {
		if err := require(pairs, v.Cases, v.Major); err != nil {
			t.Fatal(err)
		}
	}
	wanted := fmt.Sprintf("macos-%d.container-volumes.apfs.final.container.UDZO.dmg", v.Major)
	var selected *Paired
	for i := range pairs {
		if pairs[i].Name == wanted {
			if selected != nil {
				t.Fatal("ambiguous ordinary container output")
			}
			selected = &pairs[i]
		}
	}
	if selected == nil {
		t.Fatalf("required ordinary container %q missing", wanted)
	}
	out := selected.Output
	if out.Source != (schema.CaseRef{Producer: v.Major, Recipe: "container-volumes", Profile: "apfs", Stage: "final"}) || out.Operation != "container" || out.Format != "UDZO" || out.Encrypted || out.Expect.Container == nil || out.Expect.Container.CapacityBytes != 1600<<20 || len(out.Expect.Container.EmptyVolumes) != 1 || out.Expect.Container.EmptyVolumes[0] != "Fresh Empty" {
		t.Fatalf("unexpected matched source contract: %+v", out)
	}
	originals := map[string]string{}
	for host, hostOut := range selected.ByHost {
		path := filepath.Join(selected.Dirs[host], hostOut.File)
		sum, err := schema.FileDigest(path)
		if err != nil || sum != hostOut.SHA256 {
			t.Fatalf("%s producer bytes/digest: %s, %v", host, sum, err)
		}
		originals[path] = sum
	}
	defer func() {
		for path, want := range originals {
			got, err := schema.FileDigest(path)
			if err != nil || got != want {
				t.Errorf("original producer artifact changed: %s: %s, %v", path, got, err)
			}
		}
	}()
	goImage := filepath.Join(selected.Dirs[selected.Primary], selected.ByHost[selected.Primary].File)
	var goRaw, appleRaw string
	var before *schema.Observation
	if !t.Run("matched-input-preparation", func(t *testing.T) {
		// Retain a pristine raw Go input for structural/checkpoint comparison.
		goRaw = filepath.Join(v.Work, "go-before-pressure.raw")
		if err := materializePressureInput(ctx, v, goImage, false, goRaw); err != nil {
			t.Fatal(err)
		}
		appleRaw, before, err = buildMatchedNativeContainer(ctx, v, goImage, filepath.Join(v.Work, "apple-control"), v.Recipes["container-volumes"])
		if err != nil {
			t.Fatal("Apple/Go prepressure parity is required: ", err)
		}
		if before == nil || before.Image.DiskBytes != 1600<<20 {
			t.Fatal("missing matched Apple before observation")
		}
		for _, raw := range []string{goRaw, appleRaw} {
			info, err := os.Stat(raw)
			if err != nil || info.Size() != 1600<<20 {
				t.Fatalf("matched raw geometry: %s: %v, %v", raw, info, err)
			}
			if err := retainPressureHeader(raw); err != nil {
				t.Fatal(err)
			}
		}
	}) {
		return
	}
	manifest := map[string]any{
		"diagnosticOnly": true, "fullCI": false, "performanceQualification": false,
		"workloadCommit":                    originalPressureCommit,
		"containerContinuationSourceSHA256": "59b62d08f610d5121cb58e188b2d92e7bd1e6406ef64a63f14cf3e25114f2496",
		"frozenFunctionSHA256":              map[string]string{"containerWrites": "28d928e7aa3cdfa35dac90fdecf67508e098c2a42e28431ddcb50175d84492f3", "pressureVolume": "87789567090db3bee10bb783dd59b8849e2ea48163e19d4e18ade10b47afdf55", "fillVolume": "e82822f2d1bc8a61812cafe901db09daf5ed394132d8d219cf690d09c7d49419", "writableDirectory": "5415f5b3e8f67d8965f69014425c5cb2893d7f094b53368e32007c7f5d3f32e5"}, "producerRun": int64(39724863344),
		"producerInventoryPairs": len(pairs), "kernelMajor": v.Major, "builder": builder,
		"capacityBytes": int64(1600 << 20), "originalProducerFiles": originals,
		"goBeforeRaw": goRaw, "appleBeforeRaw": appleRaw,
		"scope":            "original containerWrites pressure workload only; excludes bulk nativeWrites, Go edit and later continuation",
		"originalProtocol": "quota fill/truncate/unlink/reuse; unreserved single-file fill; zero proof/sync; truncate/unlink pressure; DELETE proof; peer writes/sync; close/fsck on success",
	}
	baselineDigests := map[string]string{}
	for name, path := range map[string]string{"goBeforeSHA256": goRaw, "appleBeforeSHA256": appleRaw} {
		sum, err := schema.FileDigest(path)
		if err != nil {
			t.Fatal(err)
		}
		manifest[name] = sum
		baselineDigests[path] = sum
	}
	defer func() {
		for path, want := range baselineDigests {
			got, err := schema.FileDigest(path)
			if err != nil || got != want {
				t.Errorf("pristine before-pressure image changed: %s: %s, %v", path, got, err)
			}
		}
	}()
	writeManifest := func() {
		t.Helper()
		b, err := json.MarshalIndent(manifest, "", "  ")
		if err == nil {
			err = os.WriteFile(filepath.Join(v.Work, "diagnostic.json"), append(b, '\n'), 0o644)
		}
		if err != nil {
			t.Error(err)
		}
	}
	writeManifest()
	if t.Failed() {
		return
	}
	t.Logf("DIAGNOSTIC ONLY: original workload %s; builder %s; exact matched 1600MiB/four volumes; complete %d paired outputs", originalPressureCommit, builder, len(pairs))
	t.Run("original-pressure-workload", func(t *testing.T) {
		source := goRaw
		if builder == "apple" {
			source = appleRaw
		}
		raw := filepath.Join(v.Work, builder+"-pressure-working.raw")
		if err := copyPressureRaw(source, raw); err != nil {
			t.Fatal(err)
		}
		actualSum, err := schema.FileDigest(raw)
		expectedSum, wantErr := schema.FileDigest(source)
		if err != nil || wantErr != nil || actualSum != expectedSum {
			t.Fatalf("private input copy mismatch: %s, %s, %v, %v", actualSum, expectedSum, err, wantErr)
		}
		att, err := mountPressureDiagnostic(ctx, v, raw)
		if err != nil {
			t.Fatal("private input writable attach/mount: ", err)
		}
		captureFailure := func() {
			// Evidence acquisition only: no unmount, sync, repair or retry after
			// a failed original operation. This is a nonquiescent device copy.
			sum, n, captureErr := v.Disk.DeviceDigest(ctx, att.RDev, raw+".failure-device.gz")
			manifest["failureAcquisition"] = map[string]any{"nonquiescent": true, "sha256": sum, "bytes": n, "error": pressureError(captureErr)}
			writeManifest()
		}
		trace.record(map[string]any{"phase": "original-workload-start", "builder": builder, "attachment": att})
		original := &originalContainerPressure{Verifier: v}
		started := time.Now()
		workloadErr := original.containerWrites(ctx, att, out)
		manifest["workloadDurationNs"] = time.Since(started).Nanoseconds()
		manifest["workloadError"] = pressureError(workloadErr)
		manifest["lastOperation"] = trace.lastOperation
		trace.record(map[string]any{"phase": "original-workload-result", "error": pressureError(workloadErr)})
		writeManifest()
		if workloadErr != nil {
			captureFailure()
			t.Fatalf("ORIGINAL WORKLOAD FAILED (%s), last operation %v: %v", builder, trace.lastOperation, workloadErr)
		}
		// Readback is recorded only after the unchanged original workload has
		// returned success. It never substitutes for its writes or sync calls.
		for _, volume := range att.Volumes {
			path := filepath.Join(volume.Mount, "container-continuation", "peer")
			want := []byte(volume.Name + "\n")
			sum, n, err := v.Vol.Hash(path)
			if err != nil || n != int64(len(want)) || sum != pressureDigest(want) {
				captureFailure()
				t.Fatalf("peer readback %q: %s/%d, %v", volume.Name, sum, n, err)
			}
		}
		// Preserve the original successful continuation close order exactly.
		for _, volume := range att.Volumes {
			if volume.Mount != "" {
				if err := v.Disk.Unmount(ctx, volume); err != nil {
					manifest["closeError"] = err.Error()
					manifest["closeVolume"] = volume.Name
					captureFailure()
					t.Fatal("original pressure success unmount: ", err)
				}
			}
		}
		if err := v.Disk.Detach(ctx, att); err != nil {
			manifest["closeError"] = err.Error()
			captureFailure()
			t.Fatal("original success clean close: ", err)
		}
		if err := v.fsckRaw(ctx, raw, "apfs"); err != nil {
			manifest["fsckError"] = err.Error()
			writeManifest()
			t.Fatal("original success readonly fsck: ", err)
		}
		manifest["result"] = "original containerWrites pressure workload, peer readback, ordered unmount/detach and readonly fsck passed"
		writeManifest()
	})
}

func materializePressureInput(ctx context.Context, v *Verifier, image string, rawInput bool, raw string) error {
	att, err := v.Disk.Attach(ctx, image, fixture.AttachOptions{ReadOnly: true, Raw: rawInput})
	if err != nil {
		return err
	}
	sum, size, readErr := v.Disk.DeviceDigest(ctx, att.RDev, raw+".gz")
	closeErr := v.Disk.Detach(ctx, att)
	if err := errors.Join(readErr, closeErr); err != nil {
		return err
	}
	if size != 1600<<20 {
		return fmt.Errorf("source geometry %d, require 1600MiB", size)
	}
	if err := corpus.ExpandGzip(raw+".gz", raw); err != nil {
		return err
	}
	actual, err := schema.FileDigest(raw)
	if err != nil {
		return err
	}
	if actual != sum {
		return fmt.Errorf("materialized raw does not match source device digest")
	}
	return nil
}

func copyPressureRaw(source, target string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	return errors.Join(copyErr, out.Close())
}

func retainPressureHeader(raw string) error {
	f, err := os.Open(raw)
	if err != nil {
		return err
	}
	b := make([]byte, 4096)
	_, readErr := io.ReadFull(f, b)
	if err := errors.Join(readErr, f.Close()); err != nil {
		return err
	}
	return os.WriteFile(raw+".nx-superblock.hex", []byte(hex.EncodeToString(b)+"\n"), 0o644)
}

func mountPressureDiagnostic(ctx context.Context, v *Verifier, raw string) (*fixture.Attachment, error) {
	att, err := v.Disk.Attach(ctx, raw, fixture.AttachOptions{Raw: true})
	if err != nil {
		return nil, err
	}
	if _, err := containerMountInventory(att); err != nil {
		return att, err
	}
	names := []string{"Reserved", "Limited", "Empty", "Fresh Empty"}
	if len(att.Volumes) != len(names) {
		return att, fmt.Errorf("private copy has %d volumes, require four", len(att.Volumes))
	}
	for i, volume := range att.Volumes {
		if volume.Name != names[i] || volume.Role != "" {
			return att, fmt.Errorf("private copy volume%d: %+v", i, volume)
		}
		if err := v.Disk.Mount(ctx, volume, "owners,noatime", filepath.Join(v.Work, "mnt", sanitize(volume.Name)), false); err != nil {
			return att, err
		}
	}
	return att, nil
}

func pressureDigest(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }
func pressureError(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

type containerPressureTrace struct {
	encoder       *json.Encoder
	err           error
	lastOperation map[string]any
}

func (t *containerPressureTrace) record(row map[string]any) {
	row["observedAtUTC"] = time.Now().UTC().Format(time.RFC3339Nano)
	if t.err == nil {
		t.err = t.encoder.Encode(row)
	}
}

type containerPressureCommander struct {
	fixture.Commander
	trace *containerPressureTrace
}

func (c containerPressureCommander) Run(ctx context.Context, cmd fixture.Command) fixture.Result {
	result := c.Commander.Run(ctx, cmd)
	c.trace.record(map[string]any{"command": cmd.Argv, "label": cmd.Label, "sudo": cmd.Sudo, "status": result.Status, "stdout": string(result.Stdout), "stderr": string(result.Stderr), "error": pressureError(result.Err), "durationNs": result.Duration.Nanoseconds()})
	return result
}

type containerPressureVolume struct {
	fixture.Volume
	trace *containerPressureTrace
}

func (v containerPressureVolume) call(operation, path string, n int64, data []byte, fn func() error) error {
	started := time.Now()
	err := fn() // Exactly one original native call; return its error unchanged.
	row := map[string]any{"operation": operation, "path": path, "bytes": n, "error": pressureError(err), "durationNs": time.Since(started).Nanoseconds()}
	if data != nil {
		row["dataSHA256"] = pressureDigest(data)
	}
	v.trace.lastOperation = row
	v.trace.record(row)
	return err
}
func (v containerPressureVolume) WriteFile(p string, b []byte, x bool) error {
	return v.call("write-exclusive="+fmt.Sprint(x), p, int64(len(b)), b, func() error { return v.Volume.WriteFile(p, b, x) })
}
func (v containerPressureVolume) AppendFile(p string, b []byte) error {
	return v.call("append", p, int64(len(b)), b, func() error { return v.Volume.AppendFile(p, b) })
}
func (v containerPressureVolume) Truncate(p string, n int64) error {
	return v.call("truncate", p, n, nil, func() error { return v.Volume.Truncate(p, n) })
}
func (v containerPressureVolume) Fullfsync(p string) error {
	return v.call("fullfsync", p, 0, nil, func() error { return v.Volume.Fullfsync(p) })
}
func (v containerPressureVolume) Remove(p string) error {
	return v.call("unlink", p, 0, nil, func() error { return v.Volume.Remove(p) })
}
func (v containerPressureVolume) Mkdir(p string, n uint32) error {
	return v.call("mkdir", p, int64(n), nil, func() error { return v.Volume.Mkdir(p, n) })
}

// Frozen from originalPressureCommit. The four following methods differ from
// that source ONLY in the receiver type, enabling transparent call tracing.
type originalContainerPressure struct{ *Verifier }

func (v *originalContainerPressure) containerWrites(ctx context.Context, att *fixture.Attachment, out schema.Output) error {
	for _, volume := range att.Volumes {
		if volume.Mount == "" {
			return fmt.Errorf("peer %q is not mounted", volume.Name)
		}
		if err := v.writableDirectory(ctx, filepath.Join(volume.Mount, "container-continuation")); err != nil {
			return err
		}
	}
	if out.Source.Recipe == "container-volumes" {
		limited, reserved := att.Volume("Limited"), att.Volume("Reserved")
		if limited == nil || reserved == nil || len(out.Expect.Container.EmptyVolumes) != 1 {
			return fmt.Errorf("missing quota, reserved or empty volume")
		}
		empty := att.Volume(out.Expect.Container.EmptyVolumes[0])
		if empty == nil {
			return fmt.Errorf("missing empty pressure volume")
		}
		if err := v.pressureVolume(ctx, limited, 16<<20); err != nil {
			return fmt.Errorf("quota: %w", err)
		}
		// The unreserved peer must run out before consuming the reserved
		// allocation. Keep the pressure file until the reserved write is synced.
		pressure := filepath.Join(empty.Mount, "container-continuation", "pressure")
		if err := v.fillVolume(ctx, pressure, 256<<20); err != nil {
			return fmt.Errorf("reservation pressure: %w", err)
		}
		proof := filepath.Join(reserved.Mount, "container-continuation", "reservation-proof")
		if err := v.Vol.WriteFile(proof, make([]byte, 1<<20), true); err != nil {
			return fmt.Errorf("reserved volume lost protected allocation: %w", err)
		}
		if err := v.Vol.Fullfsync(proof); err != nil {
			return err
		}
		if err := v.Vol.Truncate(pressure, 0); err != nil {
			return err
		}
		if err := v.Vol.Remove(pressure); err != nil {
			return err
		}
		if err := v.Vol.Remove(proof); err != nil {
			return err
		}
	}
	for _, volume := range att.Volumes {
		if volume.Mount == "" {
			return fmt.Errorf("peer %q is not mounted", volume.Name)
		}
		// Identical names hold distinct contents on each volume, so an
		// accidental selection or cross-volume alias cannot pass readback.
		filename := filepath.Join(volume.Mount, "container-continuation", "peer")
		if err := v.Vol.WriteFile(filename, []byte(volume.Name+"\n"), true); err != nil {
			return err
		}
		if err := v.Vol.Fullfsync(filename); err != nil {
			return err
		}
	}
	return nil
}

func (v *originalContainerPressure) pressureVolume(ctx context.Context, volume *fixture.AttachedVolume, bound int64) error {
	filename := filepath.Join(volume.Mount, "container-continuation", "pressure")
	if err := v.fillVolume(ctx, filename, bound); err != nil {
		return err
	}
	if err := v.Vol.Truncate(filename, 0); err != nil {
		return err
	}
	if err := v.Vol.Remove(filename); err != nil {
		return err
	}
	// Reusing quota after removing the last owner is a separate required result.
	if err := v.Vol.WriteFile(filename, make([]byte, 32<<10), true); err != nil {
		return fmt.Errorf("reusing released quota: %w", err)
	}
	if err := v.Vol.Fullfsync(filename); err != nil {
		return err
	}
	return v.Vol.Remove(filename)
}

func (v *originalContainerPressure) fillVolume(ctx context.Context, filename string, bound int64) error {
	if err := v.Vol.WriteFile(filename, nil, true); err != nil {
		return err
	}
	chunk := make([]byte, 512<<10)
	for written := int64(0); written < bound; written += int64(len(chunk)) {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := v.Vol.AppendFile(filename, chunk)
		if err == nil {
			err = v.Vol.Fullfsync(filename)
		}
		if errors.Is(err, syscall.EDQUOT) || errors.Is(err, syscall.ENOSPC) {
			return nil
		}
		if err != nil {
			return err
		}
	}
	return fmt.Errorf("native allocation pressure did not reach EDQUOT/ENOSPC within %d bytes", bound)
}

func (v *originalContainerPressure) writableDirectory(ctx context.Context, root string) error {
	if err := v.Vol.Mkdir(root, 0o755); errors.Is(err, fs.ErrPermission) {
		// A volume root owned by another user (as Apple's own fixtures
		// are) takes the continuation directory the way recipes create
		// theirs: as root, then handed to the runner's user.
		for _, argv := range [][]string{{"mkdir", root}, {"chown", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), root}} {
			cmd := fixture.Command{Argv: argv, Sudo: true, Expected: "0"}
			if err := (&fixture.Transcript{}).Record(cmd, v.C.Run(ctx, cmd)); err != nil {
				return err
			}
		}
	} else if err != nil {
		return err
	}
	return nil
}
