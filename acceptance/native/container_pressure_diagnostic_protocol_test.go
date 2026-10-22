//go:build native && darwin

package native

// These file-only tests verify the frozen diagnostic protocol without invoking
// any native filesystem or disk operation on the developer host.
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func TestOriginalContainerPressurePreservesOperationOrder(t *testing.T) {
	for _, failPeer := range []bool{false, true} {
		t.Run(fmt.Sprint(failPeer), func(t *testing.T) {
			vol := &originalPressureRecorder{appendCounts: map[string]int{}}
			if failPeer {
				vol.peerError = errors.New("native peer allocation failure")
			}
			var recorded bytes.Buffer
			trace := &containerPressureTrace{encoder: json.NewEncoder(&recorded)}
			v := &originalContainerPressure{Verifier: &Verifier{Vol: containerPressureVolume{Volume: vol, trace: trace}}}
			att := &fixture.Attachment{}
			for _, name := range []string{"Reserved", "Limited", "Empty", "Fresh Empty"} {
				att.Volumes = append(att.Volumes, &fixture.AttachedVolume{Name: name, Mount: "/" + name})
			}
			out := schema.Output{Source: schema.CaseRef{Recipe: "container-volumes"}, Expect: schema.Expectation{Container: &schema.ContainerExpectation{EmptyVolumes: []string{"Fresh Empty"}}}}
			err := v.containerWrites(context.Background(), att, out)
			if err != vol.peerError {
				t.Fatalf("original native error changed: got %v, want %v", err, vol.peerError)
			}
			want := []string{
				"mkdir /Reserved/container-continuation", "mkdir /Limited/container-continuation", "mkdir /Empty/container-continuation", "mkdir /Fresh Empty/container-continuation",
				"write 0 /Limited/container-continuation/pressure", "append /Limited/container-continuation/pressure", "sync /Limited/container-continuation/pressure", "append /Limited/container-continuation/pressure", "truncate 0 /Limited/container-continuation/pressure", "unlink /Limited/container-continuation/pressure", "write 32768 /Limited/container-continuation/pressure", "sync /Limited/container-continuation/pressure", "unlink /Limited/container-continuation/pressure",
				"write 0 /Fresh Empty/container-continuation/pressure", "append /Fresh Empty/container-continuation/pressure", "sync /Fresh Empty/container-continuation/pressure", "append /Fresh Empty/container-continuation/pressure",
				"write 1048576 /Reserved/container-continuation/reservation-proof", "sync /Reserved/container-continuation/reservation-proof", "truncate 0 /Fresh Empty/container-continuation/pressure", "unlink /Fresh Empty/container-continuation/pressure", "unlink /Reserved/container-continuation/reservation-proof",
			}
			for _, name := range []string{"Reserved", "Limited", "Empty", "Fresh Empty"} {
				want = append(want, fmt.Sprintf("write %d /%s/container-continuation/peer", len(name)+1, name))
				if failPeer {
					break
				}
				want = append(want, "sync /"+name+"/container-continuation/peer")
			}
			if !reflect.DeepEqual(vol.calls, want) {
				t.Fatalf("original operations changed:\ngot %q\nwant %q", vol.calls, want)
			}
			if trace.err != nil {
				t.Fatal(trace.err)
			}
		})
	}
}

type originalPressureRecorder struct {
	fixture.Volume
	calls        []string
	appendCounts map[string]int
	peerError    error
}

func (v *originalPressureRecorder) Mkdir(p string, _ uint32) error {
	v.calls = append(v.calls, "mkdir "+p)
	return nil
}
func (v *originalPressureRecorder) WriteFile(p string, b []byte, exclusive bool) error {
	v.calls = append(v.calls, fmt.Sprintf("write %d %s", len(b), p))
	if !exclusive {
		return errors.New("original write must be exclusive")
	}
	if strings.HasSuffix(p, "/peer") {
		return v.peerError
	}
	for _, value := range b {
		if value != 0 {
			return errors.New("original pressure, reuse and reservation proof bytes must be zero")
		}
	}
	return nil
}
func (v *originalPressureRecorder) AppendFile(p string, b []byte) error {
	v.calls = append(v.calls, "append "+p)
	if len(b) != 512<<10 || !bytes.Equal(b, make([]byte, 512<<10)) {
		return errors.New("original append must contain 512KiB of zero bytes")
	}
	v.appendCounts[p]++
	if v.appendCounts[p] == 2 {
		if strings.Contains(p, "/Limited/") {
			return syscall.EDQUOT
		}
		return syscall.ENOSPC
	}
	return nil
}
func (v *originalPressureRecorder) Fullfsync(p string) error {
	v.calls = append(v.calls, "sync "+p)
	return nil
}
func (v *originalPressureRecorder) Truncate(p string, n int64) error {
	v.calls = append(v.calls, fmt.Sprintf("truncate %d %s", n, p))
	return nil
}
func (v *originalPressureRecorder) Remove(p string) error {
	v.calls = append(v.calls, "unlink "+p)
	return nil
}
