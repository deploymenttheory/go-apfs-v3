//go:build native && darwin

package native

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"golang.org/x/sys/unix"
)

type forkMappingDescriptor struct {
	id, key, path string
	file          *os.File
	stat          forkMappingStat
	wantHash      string
	wantBytes     int64
}

// All handles are acquired after the original writer has returned. Opening a
// fresh descriptor is an observation, not a promise to invalidate vnode caches.
func (v *Verifier) measureForkDescriptors(ctx context.Context, arm *forkMappingArm, start time.Time, mount, source, sibling string) (resultErr, cleanupErr error) {
	if err := fixture.RequireDisposableHost(); err != nil {
		return err, err
	}
	if err := ctx.Err(); err != nil {
		return err, nil
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(arm.Raw), "clone-writer", "clone-continuation.json"))
	if err != nil {
		return err, nil
	}
	if len(raw) > forkMappingReceiptMemberLimit {
		return errForkMappingEvidence, nil
	}
	var original struct{ States map[string]nativeCloneState }
	if err := json.Unmarshal(raw, &original); err != nil {
		return err, nil
	}
	expected := map[string]nativeCloneState{"source": original.States["before/source"], "sibling": original.States["before/sibling"], "partial": arm.Original.State}
	var retained, fresh []*forkMappingDescriptor
	var failedClose error
	nextID := 0
	// Failed measurements still check every close before normal image cleanup.
	defer func() {
		cleanupErr = errors.Join(failedClose, closeForkDescriptors(start, "failure-close-fresh", arm, fresh), closeForkDescriptors(start, "failure-close-retained", arm, retained))
	}()
	open := func(phase string) ([]*forkMappingDescriptor, error) {
		var descriptors []*forkMappingDescriptor
		for _, item := range []struct{ name, relative string }{{"source", source}, {"sibling", sibling}, {"partial", retainedPartialClone}} {
			want := expected[item.name]
			if want.Stat.Ino == 0 {
				return descriptors, errors.New("original writer omitted expected descriptor identity")
			}
			for _, fork := range []string{"data", "resource"} {
				if err := ctx.Err(); err != nil {
					return descriptors, err
				}
				path := filepath.Join(mount, item.relative)
				wantHash, wantBytes := want.Data, want.Stat.Size
				if fork == "resource" {
					path = filepath.Join(path, "..namedfork", "rsrc")
					payload := want.Attrs["com.apple.ResourceFork"]
					wantHash, wantBytes = fmt.Sprintf("%x", sha256.Sum256(payload)), int64(len(payload))
				}
				nextID++
				d := &forkMappingDescriptor{id: fmt.Sprintf("fd-%03d", nextID), key: item.name + "/" + fork, path: path, wantHash: wantHash, wantBytes: wantBytes}
				now := time.Now()
				d.file, err = os.OpenFile(path, os.O_RDONLY, 0)
				call := forkMappingResult(start, now, "open-readonly", path, err)
				call.DescriptorID, call.Phase, call.Input = d.id, phase, fmt.Sprint(os.O_RDONLY)
				if err == nil {
					call.Output = fmt.Sprint(d.file.Fd())
				}
				arm.DescriptorCalls = append(arm.DescriptorCalls, call)
				if err != nil {
					return descriptors, err
				}
				descriptors = append(descriptors, d)
				var st unix.Stat_t
				now = time.Now()
				err = unix.Fstat(int(d.file.Fd()), &st)
				d.stat = statForkMapping(st)
				call = forkMappingResult(start, now, "fstat-open", path, err)
				call.DescriptorID, call.Phase, call.Stat = d.id, phase, &d.stat
				arm.DescriptorCalls = append(arm.DescriptorCalls, call)
				if err != nil {
					return descriptors, err
				}
				if d.stat.Inode != want.Stat.Ino || d.stat.Size != wantBytes || d.stat.Links != uint64(want.Stat.Nlink) || uint32(d.stat.Mode)&07777 != want.Stat.Mode {
					return descriptors, fmt.Errorf("%s opened descriptor differs from original identity/size", d.key)
				}
				for _, bound := range retained {
					if bound.key == d.key && bound.stat != d.stat {
						return descriptors, fmt.Errorf("%s reopened descriptor changed its bound identity", d.key)
					}
				}
				if len(descriptors) > 1 && descriptors[0].stat.Device != d.stat.Device {
					return descriptors, errors.New("paired descriptors crossed filesystem devices")
				}
			}
		}
		return descriptors, nil
	}
	measure := func(phase string, descriptors []*forkMappingDescriptor, readback bool) error {
		snapshot := forkMappingSnapshot{Point: phase, Started: time.Now().UTC().Format(time.RFC3339Nano), SinceStartNS: time.Since(start).Nanoseconds(), Forks: map[string]forkMappingFork{}}
		var result error
		for _, d := range descriptors {
			proof, err := probeOpenedForkMapping(ctx, start, d.path, d.id, phase, d.file, readback)
			snapshot.Forks[d.key] = proof
			result = errors.Join(result, err)
			if err == nil && (proof.Stat != d.stat || (readback && (proof.SHA256 != d.wantHash || proof.Bytes != d.wantBytes))) {
				result = errors.Join(result, fmt.Errorf("%s descriptor identity or logical bytes changed at %s", d.key, phase))
			}
		}
		if result != nil {
			snapshot.Error = result.Error()
		}
		arm.Snapshots = append(arm.Snapshots, snapshot)
		return result
	}
	resultErr = runForkMappingMeasurements(ctx, func(phase forkMappingPhase) error {
		switch phase.Action {
		case "open-retained":
			retained, err = open(phase.Name)
			return err
		case "open-fresh":
			fresh, err = open(phase.Name)
			return err
		case "map-retained":
			return measure(phase.Name, retained, false)
		case "map-fresh":
			return measure(phase.Name, fresh, false)
		case "read-retained":
			return measure(phase.Name, retained, true)
		case "read-fresh":
			return measure(phase.Name, fresh, true)
		case "close-fresh":
			err := closeForkDescriptors(start, phase.Name, arm, fresh)
			failedClose = errors.Join(failedClose, err)
			return err
		case "close-retained":
			err := closeForkDescriptors(start, phase.Name, arm, retained)
			failedClose = errors.Join(failedClose, err)
			return err
		case "flush":
			for _, d := range retained {
				if d.key != "partial/"+arm.Target {
					continue
				}
				now := time.Now()
				_, err := unix.FcntlInt(d.file.Fd(), unix.F_FULLFSYNC, 0)
				call := forkMappingResult(start, now, "F_FULLFSYNC", d.path, err)
				call.DescriptorID, call.Phase = d.id, phase.Name
				arm.Extra = append(arm.Extra, call)
				return err
			}
			return errors.New("paired target descriptor absent")
		default:
			return fmt.Errorf("unknown paired descriptor action %s", phase.Action)
		}
	})
	return resultErr, nil
}

func closeForkDescriptors(start time.Time, phase string, arm *forkMappingArm, descriptors []*forkMappingDescriptor) error {
	if err := fixture.RequireDisposableHost(); err != nil {
		return err
	}
	var result error
	for _, d := range descriptors {
		if d.file == nil {
			continue
		}
		now := time.Now()
		err := d.file.Close()
		d.file = nil // Exactly one checked close, including a failed close.
		call := forkMappingResult(start, now, "close", d.path, err)
		call.DescriptorID, call.Phase = d.id, phase
		arm.DescriptorCalls = append(arm.DescriptorCalls, call)
		result = errors.Join(result, err)
	}
	return result
}
