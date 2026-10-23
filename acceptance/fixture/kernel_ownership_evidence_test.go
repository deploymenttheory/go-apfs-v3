package fixture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const ownershipStreamLimit = 8 << 20
const ownershipCaptureLimit = 64 << 20

type ownershipStreamEvidence struct {
	File           string
	Bytes          int
	SHA256         string
	StoredBytes    int
	StoredSHA256   string
	RetentionError string `json:",omitempty"`
}

type ownershipCommandEvidence struct {
	Sequence int
	Phase    string
	Label    string
	Argv     []string
	Sudo     bool
	Status   int
	Error    string `json:",omitempty"`
	WallNS   int64
	Stdout   ownershipStreamEvidence
	Stderr   ownershipStreamEvidence
}

// This recorder does not interpret registry output or change a command result.
// Raw files preserve even empty, non-text and parser-rejected native output.
type ownershipEvidenceCommander struct {
	C       Commander
	Dir     string
	Phase   string
	Results []ownershipCommandEvidence
	Err     error
	stored  int
}

func (c *ownershipEvidenceCommander) Run(ctx context.Context, cmd Command) Result {
	result := c.C.Run(ctx, cmd)
	n := len(c.Results)
	row := ownershipCommandEvidence{Sequence: n, Phase: c.Phase, Label: cmd.Label, Argv: append([]string(nil), cmd.Argv...), Sudo: cmd.Sudo, Status: result.Status, WallNS: result.Duration.Nanoseconds()}
	if result.Err != nil {
		row.Error = result.Err.Error()
	}
	row.Stdout = c.retain(n, "stdout", result.Stdout)
	row.Stderr = c.retain(n, "stderr", result.Stderr)
	c.Results = append(c.Results, row)
	return result
}

func (c *ownershipEvidenceCommander) retain(sequence int, stream string, raw []byte) ownershipStreamEvidence {
	row := ownershipStreamEvidence{File: filepath.ToSlash(filepath.Join("command-results", fmt.Sprintf("%03d.%s", sequence, stream))), Bytes: len(raw), SHA256: fmt.Sprintf("%x", sha256.Sum256(raw))}
	keep := min(len(raw), ownershipStreamLimit, ownershipCaptureLimit-c.stored)
	if keep != len(raw) {
		limitErr := fmt.Errorf("native ownership command %d %s exceeded evidence bounds: %d of %d bytes retained", sequence, stream, keep, len(raw))
		row.RetentionError = limitErr.Error()
		c.Err = errors.Join(c.Err, limitErr)
	}
	data := raw[:keep]
	row.StoredBytes, row.StoredSHA256 = len(data), fmt.Sprintf("%x", sha256.Sum256(data))
	path := filepath.Join(c.Dir, filepath.FromSlash(row.File))
	err := os.MkdirAll(filepath.Dir(path), 0o700)
	if err == nil {
		err = os.WriteFile(path, data, 0o600)
	}
	if err != nil {
		row.StoredBytes, row.StoredSHA256 = 0, ""
		row.RetentionError += " retain original stream: " + err.Error()
		c.Err = errors.Join(c.Err, fmt.Errorf("retain native ownership command %d %s: %w", sequence, stream, err))
	} else {
		c.stored += keep
	}
	return row
}

// Collect all scopes even if a command fails or an earlier scope has no class.
// A collected inventory is evidence, never an ownership or absence verdict.
func collectOwnershipInventories(ctx context.Context, disk *HostDisk) error {
	var resultErr error
	for _, scope := range []struct {
		label string
		argv  []string
	}{
		{"collect-modern-image-ownership", imageRegistryArgs},
		{"collect-legacy-image-ownership", legacyRegistryArgs},
		{"collect-root-media", mediaRegistryArgs},
		// Apple's archive_search -t branch retains ancestors without assuming
		// a driver class. These bytes are diagnostic evidence only:
		// https://github.com/apple-oss-distributions/IOKitTools/blob/e6f4aac8b42e65f7e76009227de1d05057228488/ioreg.tproj/ioreg.c
		{"collect-bsd-ancestry", []string{"/usr/sbin/ioreg", "-a", "-l", "-p", "IOService", "-r", "-k", "BSD Name", "-t"}},
	} {
		cmd := Command{Label: scope.label, Argv: append([]string(nil), scope.argv...), Expected: "record"}
		resultErr = errors.Join(resultErr, disk.T.Record(cmd, disk.C.Run(ctx, cmd)))
	}
	return resultErr
}

type ownershipResultCommander struct {
	results []Result
	calls   int
}

func (c *ownershipResultCommander) Run(context.Context, Command) Result {
	result := c.results[c.calls]
	c.calls++
	return result
}

func TestNativeOwnershipEvidenceCollectsEveryScopeWithoutInterpretingResults(t *testing.T) {
	cause := errors.New("native registry launch failed")
	original := []Result{{}, {Status: -1, Stdout: []byte{0, 0xff, '\r', '\n'}, Stderr: []byte("original\r\n"), Err: cause}, {Status: 7, Stdout: []byte("not a plist")}, {Stdout: []byte("original ancestry")}}
	underlying := &ownershipResultCommander{results: original}
	recorder := &ownershipEvidenceCommander{C: underlying, Dir: t.TempDir(), Phase: "two-attached"}
	disk := &HostDisk{C: recorder, T: &Transcript{}}
	if err := collectOwnershipInventories(context.Background(), disk); !errors.Is(err, cause) {
		t.Fatalf("original launch failure was lost: %v", err)
	}
	if underlying.calls != 4 || len(recorder.Results) != 4 || len(disk.T.Commands) != 4 || recorder.Err != nil {
		t.Fatal("a miss or failure prevented complete original-data collection", recorder.Err)
	}
	for i, result := range original {
		row := recorder.Results[i]
		if row.Status != result.Status || row.Phase != "two-attached" {
			t.Fatal("native outcome or capture phase changed")
		}
		for stream, want := range map[ownershipStreamEvidence][]byte{row.Stdout: result.Stdout, row.Stderr: result.Stderr} {
			got, err := os.ReadFile(filepath.Join(recorder.Dir, filepath.FromSlash(stream.File)))
			if err != nil || !bytes.Equal(got, want) || stream.Bytes != len(want) || stream.StoredBytes != len(want) || stream.SHA256 != fmt.Sprintf("%x", sha256.Sum256(want)) || stream.StoredSHA256 != stream.SHA256 {
				t.Fatalf("original stream bytes or digest changed: %v", err)
			}
		}
	}
}

func TestNativeOwnershipEvidenceReturnsUnchangedResultsAndReportsRetentionFailures(t *testing.T) {
	cause := errors.New("original command error")
	original := Result{Status: 19, Stdout: make([]byte, ownershipStreamLimit+1), Stderr: []byte("original stderr"), Err: cause}
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	underlying := &ownershipResultCommander{results: []Result{original}}
	recorder := &ownershipEvidenceCommander{C: underlying, Dir: blocker}
	got := recorder.Run(context.Background(), Command{Label: "original"})
	if !reflect.DeepEqual(got, original) || recorder.Err == nil || len(recorder.Results) != 1 || recorder.Results[0].Stdout.StoredBytes != 0 || recorder.Results[0].Stdout.RetentionError == "" || recorder.Results[0].Stdout.Bytes != len(original.Stdout) {
		t.Fatal("retention failure changed or silently discarded the original result")
	}
}

func TestNativeOwnershipEvidenceBoundsRetainedBytesWithoutInventingFullRetention(t *testing.T) {
	original := Result{Stdout: []byte("original")}
	underlying := &ownershipResultCommander{results: []Result{original}}
	recorder := &ownershipEvidenceCommander{C: underlying, Dir: t.TempDir(), stored: ownershipCaptureLimit - 2}
	got := recorder.Run(context.Background(), Command{Label: "bounded"})
	row := recorder.Results[0].Stdout
	raw, err := os.ReadFile(filepath.Join(recorder.Dir, filepath.FromSlash(row.File)))
	if err != nil || !reflect.DeepEqual(got, original) || recorder.Err == nil || row.RetentionError == "" || row.Bytes != len(original.Stdout) || row.StoredBytes != 2 || !bytes.Equal(raw, original.Stdout[:2]) || row.SHA256 == row.StoredSHA256 {
		t.Fatal("bounded retention misreported original or retained bytes", err)
	}
}
