//go:build native && darwin

package native

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
)

// Diagnostic only: identical copies of the original failing pair input.
// One added operation after data-fork synchronization: none, resource open,
// or explicit resource-fork synchronization. Original verdicts are retained.
func TestNativeCloneForkSynchronization(t *testing.T) {
	if err := fixture.RequireDisposableHost(); err != nil {
		t.Fatal(err)
	}
	major, _ := strconv.Atoi(os.Getenv("APFS_EXPECT_MAJOR"))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	producer, err := fixture.IdentifyProducer(ctx, fixture.Exec{}, major, "")
	if err != nil {
		t.Fatal(err)
	}
	root := os.Getenv("APFS_NATIVE_WORK")
	source := filepath.Join(root, "original-source.raw.gz")
	before, err := schemaDigest(source)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		after, err := schemaDigest(source)
		if err != nil || after != before {
			t.Error("original source changed", err)
		}
	}()
	counts := map[string]int{}
	completed := map[string]int{}
	for round := 0; round < 24; round++ {
		modes := []string{"original", "open-resource", "sync-resource"}
		if round%2 != 0 {
			modes[0], modes[2] = modes[2], modes[0]
		}
		for _, mode := range modes {
			work := filepath.Join(root, fmt.Sprintf("%s-%02d", mode, round))
			if err := os.MkdirAll(work, 0700); err != nil {
				t.Fatal(err)
			}
			raw := filepath.Join(work, "writable.raw")
			if err := corpus.ExpandGzipContext(ctx, source, raw); err != nil {
				t.Fatal(err)
			}
			volume := &forkSyncProbeVolume{HostVolume: fixture.HostVolume{}, mode: mode}
			disk := &fixture.HostDisk{C: fixture.Exec{}, T: &fixture.Transcript{}}
			v := &Verifier{C: fixture.Exec{}, Disk: disk, Vol: volume, Work: root, Major: major, Producer: producer}
			var state *nativeCloneState
			runErr := func() (resultErr error) {
				att, err := disk.Attach(ctx, raw, fixture.AttachOptions{Raw: true})
				if err != nil {
					return err
				}
				defer func() {
					cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), fixture.DefaultTimeout)
					defer cancel()
					resultErr = errors.Join(resultErr, closeForkMappingAttachment(cleanup, disk, att))
				}()
				if len(att.Volumes) != 1 {
					return fmt.Errorf("expected one original volume")
				}
				mount := filepath.Join(work, "mnt")
				if err := disk.Mount(ctx, att.Volumes[0], "owners,noatime", mount, false); err != nil {
					return err
				}
				return v.continueCloneWritesObserved(ctx, mount, filepath.Join(work, "writer"), "Fixture/followed", "Fixture/overwrite", func(_ string, original *nativeCloneState, _ error) error {
					if original != nil {
						copy := *original
						state = &copy
					}
					return nil
				})
			}()
			completed[mode]++
			if runErr != nil {
				counts[mode]++
			}
			probeJSON(t, root, filepath.Base(work)+".json", map[string]any{"mode": mode, "error": fmt.Sprint(runErr), "original": state, "syncCalls": volume.calls})
			if runErr != nil && !strings.Contains(runErr.Error(), "partial clone") {
				t.Fatal("different failure", runErr)
			}
			if runErr == nil {
				if err := os.Remove(raw); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	probeJSON(t, root, "synchronization-results.json", map[string]any{"producer": producer, "completed": completed, "failures": counts})
	t.Logf("original writer failures=%d, open-resource=%d, sync-resource=%d", counts["original"], counts["open-resource"], counts["sync-resource"])
	if counts["original"] == 0 {
		t.Fatal("inconclusive: original failure not reproduced")
	}
	if counts["sync-resource"] != 0 {
		t.Fatal("explicit resource sync did not resolve original failure")
	}
}

type forkSyncProbeVolume struct {
	fixture.HostVolume
	mode  string
	calls []string
}

func (v *forkSyncProbeVolume) Fullfsync(path string) error {
	if err := v.HostVolume.Fullfsync(path); err != nil {
		return err
	}
	if filepath.Base(path) != "first" && filepath.Base(path) != "partial" {
		return nil
	}
	resource := filepath.Join(path, "..namedfork", "rsrc")
	switch v.mode {
	case "original":
		return nil
	case "open-resource":
		v.calls = append(v.calls, "open-and-close:"+resource)
		f, err := os.Open(resource)
		if err != nil {
			return err
		}
		return f.Close()
	case "sync-resource":
		v.calls = append(v.calls, "F_FULLFSYNC:"+resource)
		return v.HostVolume.Fullfsync(resource)
	default:
		return fmt.Errorf("invalid mode")
	}
}

func schemaDigest(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum), nil
}
