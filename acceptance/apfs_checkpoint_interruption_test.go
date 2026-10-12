package acceptance_test

import (
	"bytes"
	"compress/gzip"
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
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

type interruptedCheckpointWrite struct {
	Stage  string `json:"stage"`
	Offset int64  `json:"offset"`
	Bytes  int    `json:"bytes"`
}

type interruptedCheckpointFile struct {
	*block.Staging
	fail      string
	triggered bool
	trace     []interruptedCheckpointWrite
}

func (f *interruptedCheckpointFile) WriteAt(data []byte, offset int64) (int, error) {
	stage := "data"
	if offset == 0 {
		stage = "block-zero"
	} else if len(data) >= 36 && string(data[32:36]) == "NXSB" {
		stage = "superblock"
	} else if len(data) >= 32 {
		kind := binary.LittleEndian.Uint32(data[24:])
		switch {
		case kind == 0x4000000c:
			stage = "mapping"
		case kind&0xffff0000 == 0x80000000:
			stage = "ephemeral"
		case kind&0xffff == 2 || kind&0xffff == 3 || kind&0xffff == 7 || kind&0xffff == 11 || kind&0xffff == 13:
			stage = "metadata"
		}
	}
	f.trace = append(f.trace, interruptedCheckpointWrite{stage, offset, len(data)})
	if stage == f.fail && !f.triggered {
		f.triggered = true
		// Retain a real torn prefix in the backing file. This error is injected
		// outside Staging so its preserved bytes can be copied into an immutable
		// interruption fixture; production callers discard failed staging.
		n, err := f.Staging.WriteAt(data[:7], offset)
		if err != nil {
			return n, err
		}
		return n, io.ErrShortWrite
	}
	return f.Staging.WriteAt(data, offset)
}

type checkpointInterruptionCase struct {
	Stage               string                       `json:"stage"`
	Output              string                       `json:"output"`
	InputSHA256         string                       `json:"inputSHA256"`
	OutputSHA256        string                       `json:"outputSHA256"`
	SelectedTransaction uint64                       `json:"selectedTransaction"`
	Modified            bool                         `json:"modified"`
	PartialBytes        int                          `json:"partialBytes"`
	Trace               []interruptedCheckpointWrite `json:"trace"`
}

func checkpointPayload() []byte {
	return bytes.Repeat([]byte("Interrupted APFS transaction\n"), 512)[:8193]
}

// These are explicitly Go-produced interrupted commits, not Apple-produced
// references. The expected original state is Apple's complete observation;
// only a torn block-zero update follows a fully published new checkpoint.
// Native CI independently checks both outcomes and continued allocation.
func compareInterruptedGoCheckpoints(t *testing.T, dir string, major int, c checkpointRecoveryCase) {
	t.Helper()
	ctx := context.Background()
	sourcePath := openAPFSEditArchive(t, dir, c.Source)
	source, err := block.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	var nativeAddress uint64
	for _, candidate := range c.Checkpoint.Candidates {
		if candidate.XID == c.Native.SelectedXID {
			nativeAddress = candidate.Address
		}
	}
	nx := make([]byte, 4096)
	if err = block.ReadFull(source, nx, int64(nativeAddress)*4096); err != nil {
		t.Fatal(err)
	}
	next := binary.LittleEndian.Uint64(nx[96:])
	when := time.Unix(1749283750, 0)
	payload := checkpointPayload()
	payloadHash := sha256.Sum256(payload)
	root := os.Getenv("APFS_CHECKPOINT_RECOVERY_OUTPUT")
	if root == "" {
		root = t.TempDir()
	}
	root = filepath.Join(root, fmt.Sprintf("macos-%d", major))
	if err = os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	var results []checkpointInterruptionCase
	for _, stage := range []string{"data", "metadata", "ephemeral", "mapping", "superblock", "block-zero"} {
		t.Run(stage, func(t *testing.T) {
			staging, err := block.Stage(ctx, source, "")
			if err != nil {
				t.Fatal(err)
			}
			defer staging.Close()
			interrupted := &interruptedCheckpointFile{Staging: staging, fail: stage}
			_, err = apfs.Modify(ctx, interrupted, []filesystem.Change{{Path: "/Fixture/alias", Data: bytes.NewReader(payload)}}, when)
			if !errors.Is(err, io.ErrShortWrite) || !interrupted.triggered {
				t.Fatal("actual transaction stage not interrupted", stage, err)
			}
			input := filepath.Join(t.TempDir(), "interrupted.raw")
			file, err := os.Create(input)
			if err != nil {
				t.Fatal(err)
			}
			if n, err := io.Copy(file, io.NewSectionReader(staging, 0, staging.Size())); err != nil || n != staging.Size() {
				file.Close()
				t.Fatal("retain complete interrupted backing file", n, err)
			}
			if err = file.Close(); err != nil {
				t.Fatal(err)
			}
			before := fileDigest(t, input)
			output := filepath.Join(root, "fault-"+stage+".dmg")
			report, err := imageedit.RecoverCheckpoint(ctx, input, output, imageedit.CheckpointRecoveryOptions{Format: "UDZO"})
			if err != nil {
				t.Fatal("recovery of actual torn transaction", report, err)
			}
			modified := stage == "block-zero"
			transaction := c.Native.SelectedXID
			want := c.Native.Files
			want.Entries = append([]nativeFile(nil), want.Entries...)
			if modified {
				transaction = next
				for i := range want.Entries {
					entry := &want.Entries[i]
					if entry.Path == "Fixture/retained" || entry.Path == "Fixture/alias" {
						entry.Size, entry.SHA256 = uint64(len(payload)), hex.EncodeToString(payloadHash[:])
						entry.ModifyNS, entry.ChangeNS = when.UnixNano(), when.UnixNano()
					}
				}
			}
			if report.Transaction != transaction || (stage == "block-zero" && report.Checkpoint.BlockZeroValid) {
				t.Fatal("wrong commit boundary selected", report.Transaction, transaction)
			}
			container := openAPFSEditVolume(t, output)
			compareMetadataState(t, &container.Volumes[0], want, "apfs")
			if fileDigest(t, input) != before {
				t.Fatal("recovery changed immutable interrupted input")
			}
			// Preserve the real interrupted bytes alongside completed outputs.
			archive, err := os.Create(filepath.Join(root, "fault-"+stage+"-interrupted.raw.gz"))
			if err != nil {
				t.Fatal(err)
			}
			z := gzip.NewWriter(archive)
			if _, err = io.Copy(z, io.NewSectionReader(staging, 0, staging.Size())); err != nil {
				t.Fatal(err)
			}
			if err = errors.Join(z.Close(), archive.Close()); err != nil {
				t.Fatal(err)
			}
			results = append(results, checkpointInterruptionCase{Stage: stage, Output: filepath.Base(output),
				InputSHA256: fmt.Sprintf("%x", before), OutputSHA256: fmt.Sprintf("%x", fileDigest(t, output)),
				SelectedTransaction: transaction, Modified: modified, PartialBytes: 7, Trace: interrupted.trace})
		})
	}
	if len(results) != 6 {
		t.Fatal("incomplete transaction boundary outputs")
	}
	document := struct {
		Scenario      string                       `json:"scenario"`
		Producer      map[string]string            `json:"producer"`
		Schema        int                          `json:"schema"`
		Source        string                       `json:"source"`
		SourceSHA256  string                       `json:"sourceSHA256"`
		ModifySeconds int64                        `json:"modifySeconds"`
		PayloadSize   int                          `json:"payloadSize"`
		PayloadSHA256 string                       `json:"payloadSHA256"`
		Cases         []checkpointInterruptionCase `json:"cases"`
	}{"interrupted-Go-commits", map[string]string{"system": runtime.GOOS, "architecture": runtime.GOARCH, "revision": os.Getenv("GITHUB_SHA")},
		1, c.ID, c.Source.UncompressedSHA256, when.Unix(), len(payload), hex.EncodeToString(payloadHash[:]), results}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "faults.json"), append(encoded, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if checkpointDiskHash(t, source, 0) != c.Source.UncompressedSHA256 {
		t.Fatal("Go fault controls changed native evidence")
	}
}
