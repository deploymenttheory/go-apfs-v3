//go:build native && darwin

package native

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"syscall"
	"time"
	"unsafe"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
	"golang.org/x/sys/unix"
)

type forkMappingCall struct {
	Operation, Path, Started, Error string
	SinceStartNS, DurationNS        int64
	Errno                           uint64
	Input, Output                   string
	Offset                          int64
	Stat                            *forkMappingStat `json:",omitempty"`
}

type forkMappingStat struct {
	Device, Inode, Links uint64
	Mode                 uint16
	Size                 int64
}

type forkMappingFork struct {
	Path, SHA256 string
	Bytes        int64
	Runs         [][3]int64
	LogicalRuns  [][3]int64
	Stat         forkMappingStat
	Calls        []forkMappingCall
	Error        string
}

type forkMappingSnapshot struct {
	Point, Started, Error string
	SinceStartNS          int64
	Files                 map[string]nativeCloneState
	Forks                 map[string]forkMappingFork
}

type forkMappingOriginal struct {
	State nativeCloneState
	Error string
}

type forkMappingArm struct {
	Target, Raw, InitialSHA256, ClosedSHA256, ReopenedSHA256 string
	Original                                                 *forkMappingOriginal
	Snapshots                                                []forkMappingSnapshot
	Extra                                                    []forkMappingCall
	WriterCalls                                              []forkMappingCall
	WriterMaps                                               []forkMappingFork
	Commands                                                 []schema.Command
	Fsck, Error, CleanupError                                string
}

type forkMappingPairReceipt struct {
	Schema                                      int
	Commit, RunID, RunAttempt, Go, RecipeSHA256 string
	Producer                                    schema.Producer
	Input                                       schema.Output
	Primary                                     string
	InputSHA256, InputAfterSHA256               string
	RawSHA256                                   string
	RawBytes                                    int64
	ToolsSHA256                                 map[string]string
	Arms                                        []forkMappingArm
	Conclusion, Error                           string
}

// cloneForkMappingPair is a bounded diagnostic inside the unchanged native
// matrix. It does not qualify a new backend or substitute for Continuation.
func (v *Verifier) cloneForkMappingPair(ctx context.Context, p Paired, recipe schema.Recipe) (resultErr error) {
	if err := fixture.RequireDisposableHost(); err != nil {
		return err // Before any native syscall, attachment or fixture expansion.
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if v.Major != 26 {
		return fmt.Errorf("paired fork mapping is bounded to the macOS26 native case")
	}
	if err := requireCloneForkMappingInput([]Paired{p}, v.Major); err != nil {
		return err
	}
	if recipe.Name != "clone-copy" {
		return errors.New("paired fork mapping requires the declared clone-copy recipe")
	}
	work := filepath.Join(v.Work, "fork-mapping-pair")
	if err := os.Mkdir(work, 0o700); err != nil {
		return err // Never overwrite evidence from another invocation.
	}
	receipt := forkMappingPairReceipt{Schema: 1, Commit: os.Getenv("GITHUB_SHA"), RunID: os.Getenv("GITHUB_RUN_ID"), RunAttempt: os.Getenv("GITHUB_RUN_ATTEMPT"), Go: runtime.Version(), Producer: v.Producer, Input: p.Output, Primary: p.Primary}
	image := filepath.Join(p.Dirs[p.Primary], p.ByHost[p.Primary].File)
	transcript := &fixture.Transcript{}
	v.setTranscript(transcript)
	defer func() {
		var err error
		receipt.InputAfterSHA256, err = schema.FileDigest(image)
		if err != nil || receipt.InputAfterSHA256 != receipt.InputSHA256 {
			resultErr = errors.Join(resultErr, fmt.Errorf("paired source preservation: %w", errors.Join(err, errors.New("source digest must remain unchanged"))))
		}
		if resultErr != nil {
			receipt.Error = resultErr.Error()
		}
		// Retain successful and failing arms. Root's existing artifact upload
		// includes this bounded directory even when all predicates pass.
		for name, value := range map[string]any{"pair.json": receipt, "source-commands.json": transcript.Commands} {
			resultErr = errors.Join(resultErr, writeForkMappingJSON(filepath.Join(work, name), value))
		}
	}()
	var err error
	receipt.InputSHA256, err = schema.FileDigest(image)
	if err != nil || receipt.InputSHA256 != p.Output.SHA256 || receipt.InputSHA256 != p.ByHost[p.Primary].SHA256 {
		return errors.Join(errors.New("paired input differs from the verified portable manifest"), err)
	}
	encoded, err := json.Marshal(recipe)
	if err != nil {
		return err
	}
	receipt.RecipeSHA256 = fmt.Sprintf("%x", sha256.Sum256(encoded))
	receipt.ToolsSHA256 = map[string]string{}
	for _, tool := range []string{"/usr/bin/hdiutil", "/usr/sbin/diskutil", fixture.ResolveProgram("fsck_apfs")} {
		digest, err := schema.FileDigest(tool)
		if err != nil {
			return err
		}
		receipt.ToolsSHA256[tool] = digest
	}
	att, err := v.Disk.Attach(ctx, image, fixture.AttachOptions{ReadOnly: true, NoInventory: true})
	if err != nil {
		return err
	}
	compressed := filepath.Join(work, "source.raw.gz")
	receipt.RawSHA256, receipt.RawBytes, err = v.Disk.DeviceDigest(ctx, att.RDev, compressed)
	err = errors.Join(err, v.Disk.Detach(ctx, att))
	if err != nil {
		return err
	}
	if receipt.RawBytes <= 0 || receipt.RawBytes > 256<<20 {
		return fmt.Errorf("paired raw input outside the 256MiB diagnostic bound: %d", receipt.RawBytes)
	}
	// Publish BOTH independent raw copies before attaching either one.
	for _, target := range []string{"data", "resource"} {
		arm := forkMappingArm{Target: target, Raw: filepath.Join(work, target, "writable.raw")}
		if err := corpus.ExpandGzipContext(ctx, compressed, arm.Raw); err != nil {
			return err
		}
		arm.InitialSHA256, err = schema.FileDigest(arm.Raw)
		if err != nil || arm.InitialSHA256 != receipt.RawSHA256 {
			return errors.Join(fmt.Errorf("%s paired input is not byte-identical", target), err)
		}
		receipt.Arms = append(receipt.Arms, arm)
	}
	resultErr = runForkMappingArms(ctx, func(i int) (error, error) {
		child := v.ForSubtest()
		arm := &receipt.Arms[i]
		err, cleanupErr := child.runForkMappingArm(ctx, arm)
		if err != nil {
			arm.Error = err.Error()
		}
		if cleanupErr != nil {
			arm.CleanupError = cleanupErr.Error()
		}
		return err, cleanupErr
	})
	receipt.Conclusion = "Diagnostic observations only; a single pair cannot establish universal fork synchronization semantics or product qualification. Original verdicts remain fatal. Read probes, ambient I/O and operation latency remain confounds: a transition before intervention, convergence in both arms or non-reproduction is inconclusive. Offline independent selected-XID/catalog analysis is required."
	return resultErr
}

func (v *Verifier) runForkMappingArm(ctx context.Context, arm *forkMappingArm) (resultErr, cleanupErr error) {
	if err := fixture.RequireDisposableHost(); err != nil {
		return err, err
	}
	stage := filepath.Dir(arm.Raw)
	t := &fixture.Transcript{}
	previous := v.continuationLog
	commands := &continuationCommands{positions: map[*fixture.Transcript]int{}}
	v.continuationLog = commands
	v.setTranscript(t)
	defer func() {
		commands.flush()
		v.continuationLog = previous
		arm.Commands = append([]schema.Command(nil), commands.commands...)
		if resultErr != nil {
			arm.Error = resultErr.Error()
		}
		if cleanupErr != nil {
			arm.CleanupError = cleanupErr.Error()
		}
		resultErr = errors.Join(resultErr, writeForkMappingJSON(filepath.Join(stage, "arm.json"), arm))
	}()
	att, err := v.Disk.Attach(ctx, arm.Raw, fixture.AttachOptions{Raw: true})
	if err != nil {
		return err, err // Failed attachment cannot certify backing release.
	}
	if len(att.Volumes) != 1 || att.Volumes[0].FS != "apfs" || att.Volumes[0].Locked {
		cleanupErr = closeForkMappingAttachment(ctx, v.Disk, att)
		return errors.Join(errors.New("paired input requires one unlocked APFS volume"), cleanupErr), cleanupErr
	}
	volume := att.Volumes[0]
	mount := filepath.Join(stage, "mnt")
	if err := v.Disk.Mount(ctx, volume, "owners,noatime", mount, false); err != nil {
		cleanupErr = closeForkMappingAttachment(ctx, v.Disk, att)
		return errors.Join(err, cleanupErr), cleanupErr
	}
	start := time.Now()
	baseVolume := v.Vol
	v.Vol = &forkMappingVolume{Volume: baseVolume, arm: arm, start: start, ctx: ctx}
	defer func() { v.Vol = baseVolume }()
	source, sibling := "Fixture/followed", "Fixture/overwrite"
	checkpoint := func(point string, original *nativeCloneState, verdict error) error {
		if original != nil {
			if arm.Original != nil {
				return errors.New("paired original verdict recorded more than once")
			}
			arm.Original = &forkMappingOriginal{State: *original}
			if verdict != nil {
				arm.Original.Error = verdict.Error()
			}
			// O_EXCL and checked close make this a separate immutable receipt,
			// written BEFORE the controlled additional operation.
			if err := writeForkMappingJSON(filepath.Join(stage, "original-verdict.json"), arm.Original); err != nil {
				return err
			}
		}
		err := v.captureForkMapping(ctx, arm, start, mount, point, source, sibling)
		if original == nil || err != nil {
			return err
		}
		path := filepath.Join(mount, retainedPartialClone)
		if arm.Target == "resource" {
			path = filepath.Join(path, "..namedfork", "rsrc")
		}
		arm.Extra, err = probeForkMappingFlush(ctx, start, path)
		// Even a failed additional flush stays fatal while a later read-only
		// snapshot can preserve what the kernel reported; no retry follows.
		return errors.Join(err, v.captureForkMapping(ctx, arm, start, mount, "after-extra-"+arm.Target+"-sync", source, sibling))
	}
	resultErr = v.continueCloneWritesObserved(ctx, mount, filepath.Join(stage, "clone-writer"), source, sibling, checkpoint)
	// One normal cleanup, regardless of the original physical verdict.
	cleanupErr = closeForkMappingAttachment(ctx, v.Disk, att)
	resultErr = errors.Join(resultErr, cleanupErr)
	if cleanupErr != nil || ctx.Err() != nil {
		return errors.Join(resultErr, ctx.Err()), cleanupErr
	}
	arm.ClosedSHA256, err = schema.FileDigest(arm.Raw)
	resultErr = errors.Join(resultErr, err)
	if err != nil {
		return resultErr, nil
	}
	// The exact closed raw remains for independent OFFLINE APFS catalog/XID
	// inspection. No product decoder participates in this native oracle.
	read, err := v.Disk.Attach(ctx, arm.Raw, fixture.AttachOptions{Raw: true, ReadOnly: true})
	if err != nil {
		return errors.Join(resultErr, err), err
	}
	if len(read.Volumes) != 1 || read.Volumes[0].UUID != volume.UUID || read.Volumes[0].Name != volume.Name || read.Volumes[0].FS != volume.FS {
		cleanupErr = closeForkMappingAttachment(ctx, v.Disk, read)
		return errors.Join(resultErr, errors.New("paired readonly reopen changed selected volume identity"), cleanupErr), cleanupErr
	}
	arm.Fsck, err = v.Disk.Fsck(ctx, "apfs", read.RDev)
	resultErr = errors.Join(resultErr, err)
	if err == nil {
		err = v.Disk.Mount(ctx, read.Volumes[0], "owners,noatime", filepath.Join(stage, "readonly"), true)
		if err == nil {
			err = v.captureForkMapping(ctx, arm, start, read.Volumes[0].Mount, "readonly-reopened", source, sibling)
		}
		resultErr = errors.Join(resultErr, err)
	}
	cleanupErr = closeForkMappingAttachment(ctx, v.Disk, read)
	resultErr = errors.Join(resultErr, cleanupErr)
	if cleanupErr == nil {
		arm.ReopenedSHA256, err = schema.FileDigest(arm.Raw)
		resultErr = errors.Join(resultErr, err)
		if arm.ReopenedSHA256 != arm.ClosedSHA256 {
			resultErr = errors.Join(resultErr, errors.New("readonly paired reopen changed the closed raw bytes"))
		}
	}
	return resultErr, cleanupErr
}

func closeForkMappingAttachment(ctx context.Context, disk fixture.Disk, att *fixture.Attachment) error {
	var result error
	for _, volume := range att.Volumes {
		if volume.Mount != "" {
			result = errors.Join(result, disk.Unmount(ctx, volume))
		}
	}
	return errors.Join(result, disk.Detach(ctx, att))
}

func (v *Verifier) captureForkMapping(ctx context.Context, arm *forkMappingArm, start time.Time, mount, point, source, sibling string) error {
	if err := fixture.RequireDisposableHost(); err != nil {
		return err
	}
	snapshot := forkMappingSnapshot{Point: point, Started: time.Now().UTC().Format(time.RFC3339Nano), SinceStartNS: time.Since(start).Nanoseconds(), Files: map[string]nativeCloneState{}, Forks: map[string]forkMappingFork{}}
	var result error
	// Fixed order in BOTH arms. These read probes can themselves affect timing;
	// non-reproduction is inconclusive, not a reason to keep trying.
	for _, file := range []struct{ name, relative string }{{"source", source}, {"sibling", sibling}, {"partial", retainedPartialClone}} {
		path := filepath.Join(mount, file.relative)
		state, err := v.cloneNativeState(path)
		result = errors.Join(result, err)
		snapshot.Files[file.name] = state
		for _, fork := range []string{"data", "resource"} {
			target := path
			if fork == "resource" {
				target = filepath.Join(path, "..namedfork", "rsrc")
			}
			proof, err := probeForkMapping(ctx, start, target, true)
			snapshot.Forks[file.name+"/"+fork] = proof
			result = errors.Join(result, err)
			if err == nil {
				wantHash, wantBytes := state.Data, state.Stat.Size
				if fork == "resource" {
					data := state.Attrs["com.apple.ResourceFork"]
					wantHash, wantBytes = fmt.Sprintf("%x", sha256.Sum256(data)), int64(len(data))
				}
				if proof.SHA256 != wantHash || proof.Bytes != wantBytes {
					result = errors.Join(result, fmt.Errorf("%s %s descriptor readback disagrees with native Hash/Getxattr", file.name, fork))
				}
			}
		}
	}
	if result != nil {
		snapshot.Error = result.Error()
	}
	arm.Snapshots = append(arm.Snapshots, snapshot)
	return result
}

func probeForkMapping(ctx context.Context, start time.Time, path string, readback bool) (proof forkMappingFork, resultErr error) {
	proof.Path = path
	defer func() {
		if resultErr != nil {
			proof.Error = resultErr.Error()
		}
	}()
	if err := fixture.RequireDisposableHost(); err != nil {
		return proof, err
	}
	if err := ctx.Err(); err != nil {
		return proof, err
	}
	now := time.Now()
	f, err := os.Open(path)
	proof.Calls = append(proof.Calls, forkMappingResult(start, now, "open-readonly", path, err))
	if err != nil {
		return proof, err
	}
	defer func() {
		now := time.Now()
		err := f.Close()
		proof.Calls = append(proof.Calls, forkMappingResult(start, now, "close", path, err))
		resultErr = errors.Join(resultErr, err)
	}()
	var st unix.Stat_t
	now = time.Now()
	err = unix.Fstat(int(f.Fd()), &st)
	proof.Calls = append(proof.Calls, forkMappingResult(start, now, "fstat", path, err))
	if err != nil {
		return proof, err
	}
	proof.Stat = statForkMapping(st)
	proof.Bytes = st.Size
	if st.Size <= 0 || st.Size > 1<<20 {
		return proof, fmt.Errorf("dense fork outside bounded 1MiB measurement: %s (%d)", path, st.Size)
	}
	if readback {
		data := make([]byte, st.Size)
		now = time.Now()
		n, err := f.ReadAt(data, 0)
		proof.Calls = append(proof.Calls, forkMappingResult(start, now, "pread", path, err))
		if err != nil || int64(n) != st.Size {
			return proof, errors.Join(fmt.Errorf("fork readback incomplete: %s", path), err)
		}
		proof.SHA256 = fmt.Sprintf("%x", sha256.Sum256(data))
	}
	// Exactly the existing packed20-byte ABI, preserving both original input
	// and kernel-written output, without silently clipping the raw result.
	for offset := int64(0); offset < st.Size; {
		if err := ctx.Err(); err != nil {
			return proof, err
		}
		if len(proof.Runs) == 4096 {
			return proof, errors.New("fork physical measurement exceeds4096runs")
		}
		var arg [20]byte
		binary.LittleEndian.PutUint64(arg[4:12], uint64(st.Size-offset))
		binary.LittleEndian.PutUint64(arg[12:20], uint64(offset))
		input := hex.EncodeToString(arg[:])
		now := time.Now()
		_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), unix.F_LOG2PHYS_EXT, uintptr(unsafe.Pointer(&arg[0])))
		var callErr error
		if errno != 0 {
			callErr = errno
		}
		call := forkMappingResult(start, now, "F_LOG2PHYS_EXT", path, callErr)
		call.Errno, call.Input, call.Output = uint64(errno), input, hex.EncodeToString(arg[:])
		proof.Calls = append(proof.Calls, call)
		if callErr != nil {
			return proof, callErr
		}
		length := int64(binary.LittleEndian.Uint64(arg[4:12]))
		physical := int64(binary.LittleEndian.Uint64(arg[12:20]))
		if length <= 0 || physical < 0 || length > (1<<63-1)-offset || physical > (1<<63-1)-length {
			return proof, errors.New("fork physical measurement returned invalid range")
		}
		proof.Runs = append(proof.Runs, [3]int64{offset, physical, length})
		logical := min(length, st.Size-offset)
		proof.LogicalRuns = append(proof.LogicalRuns, [3]int64{offset, physical, logical})
		offset += length
	}
	return proof, nil
}

func probeForkMappingFlush(ctx context.Context, start time.Time, path string) (calls []forkMappingCall, resultErr error) {
	if err := fixture.RequireDisposableHost(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	now := time.Now()
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	calls = append(calls, forkMappingResult(start, now, "open-readonly", path, err))
	if err != nil {
		return calls, err
	}
	defer func() {
		now := time.Now()
		err := f.Close()
		calls = append(calls, forkMappingResult(start, now, "close", path, err))
		resultErr = errors.Join(resultErr, err)
	}()
	var st unix.Stat_t
	now = time.Now()
	err = unix.Fstat(int(f.Fd()), &st)
	call := forkMappingResult(start, now, "fstat", path, err)
	stat := statForkMapping(st)
	call.Stat = &stat
	calls = append(calls, call)
	if err != nil {
		return calls, err
	}
	if err := ctx.Err(); err != nil {
		return calls, err
	}
	now = time.Now()
	_, err = unix.FcntlInt(f.Fd(), unix.F_FULLFSYNC, 0)
	calls = append(calls, forkMappingResult(start, now, "F_FULLFSYNC", path, err))
	return calls, err
}

// This wrapper is installed only in the guarded pair. Its ordinary writer
// operations have the same target, flags and one close as HostVolume; it keeps
// actual syscall results instead of inferring what the kernel did from paths.
type forkMappingVolume struct {
	fixture.Volume
	arm   *forkMappingArm
	start time.Time
	ctx   context.Context
}

func (v *forkMappingVolume) Listxattr(path string, showCompression bool) ([]string, error) {
	if err := fixture.RequireDisposableHost(); err != nil {
		return nil, err
	}
	if err := v.ctx.Err(); err != nil {
		return nil, err
	}
	names, err := v.Volume.Listxattr(path, showCompression)
	// Only this diagnostic wrapper normalizes subsequent Getxattr read order.
	// The ordinary HostVolume and nil-observer writer remain unchanged.
	names = append([]string(nil), names...)
	sort.Strings(names)
	return names, err
}

func (v *forkMappingVolume) Pwrite(path string, offset int64, data []byte) (resultErr error) {
	if err := fixture.RequireDisposableHost(); err != nil {
		return err
	}
	if err := v.ctx.Err(); err != nil {
		return err
	}
	now := time.Now()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0o644)
	v.arm.WriterCalls = append(v.arm.WriterCalls, forkMappingResult(v.start, now, "open-write-create", path, err))
	if err != nil {
		return err
	}
	defer func() {
		now := time.Now()
		err := f.Close()
		v.arm.WriterCalls = append(v.arm.WriterCalls, forkMappingResult(v.start, now, "close", path, err))
		resultErr = errors.Join(resultErr, err)
	}()
	var st unix.Stat_t
	now = time.Now()
	err = unix.Fstat(int(f.Fd()), &st)
	call := forkMappingResult(v.start, now, "fstat", path, err)
	stat := statForkMapping(st)
	call.Stat = &stat
	v.arm.WriterCalls = append(v.arm.WriterCalls, call)
	if err != nil {
		return err
	}
	now = time.Now()
	n, err := f.WriteAt(data, offset)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	call = forkMappingResult(v.start, now, "pwrite", path, err)
	call.Offset, call.Input = offset, hex.EncodeToString(data)
	call.Output = fmt.Sprint(n)
	v.arm.WriterCalls = append(v.arm.WriterCalls, call)
	return err
}

func (v *forkMappingVolume) Fullfsync(path string) error {
	calls, err := probeForkMappingFlush(v.ctx, v.start, path)
	v.arm.WriterCalls = append(v.arm.WriterCalls, calls...)
	return err
}

func (v *forkMappingVolume) Extents(path, fork string) ([][3]int64, error) {
	if fork == "rsrc" {
		path = filepath.Join(path, "..namedfork", "rsrc")
	}
	proof, err := probeForkMapping(v.ctx, v.start, path, false)
	v.arm.WriterMaps = append(v.arm.WriterMaps, proof)
	return proof.Runs, err
}

func statForkMapping(st unix.Stat_t) forkMappingStat {
	return forkMappingStat{Device: uint64(st.Dev), Inode: st.Ino, Links: uint64(st.Nlink), Mode: st.Mode, Size: st.Size}
}

func forkMappingResult(start, now time.Time, operation, path string, err error) forkMappingCall {
	call := forkMappingCall{Operation: operation, Path: path, Started: now.UTC().Format(time.RFC3339Nano), SinceStartNS: now.Sub(start).Nanoseconds(), DurationNS: time.Since(now).Nanoseconds()}
	if err != nil {
		call.Error = err.Error()
		var errno syscall.Errno
		if errors.As(err, &errno) {
			call.Errno = uint64(errno)
		}
	}
	return call
}

func writeForkMappingJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	n, err := f.Write(append(data, '\n'))
	if err == nil && n != len(data)+1 {
		err = io.ErrShortWrite
	}
	return errors.Join(err, f.Close())
}
