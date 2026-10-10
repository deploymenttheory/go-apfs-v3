package diskimage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash/crc32"
	"io"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

func repackInput(t *testing.T) ([]byte, []byte) {
	t.Helper()
	raw := make([]byte, 10<<20)
	copy(raw[32:], "NXSB") // Raw admission identifies the container, never rebuilds it.
	copy(raw[8<<20:], "recorded unallocated-sector bytes must survive")
	var encoded bytes.Buffer
	if err := Encode(context.Background(), &encoded, bytes.NewReader(raw), int64(len(raw)), "UDRO"); err != nil {
		t.Fatal(err)
	}
	return raw, encoded.Bytes()
}

func TestRepackPreservesAllSectorsAndIsDeterministic(t *testing.T) {
	raw, encoded := repackInput(t)
	for _, input := range [][]byte{raw, encoded} {
		for _, format := range []string{"UDRO", "UDZO"} {
			var out, repeat bytes.Buffer
			report, err := Repack(context.Background(), &out, bytes.NewReader(input), format)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(raw)
			if report.DiskSHA256 != hex.EncodeToString(digest[:]) || report.DiskBytes != int64(len(raw)) {
				t.Fatal(report)
			}
			u, err := openUDIF(bytes.NewReader(out.Bytes()), out.Bytes()[out.Len()-512:])
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(io.NewSectionReader(u, 0, u.Size()))
			if err != nil || !bytes.Equal(raw, got) {
				t.Fatal("disk sectors changed", err)
			}
			if _, err = Repack(context.Background(), &repeat, bytes.NewReader(input), format); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(out.Bytes(), repeat.Bytes()) {
				t.Fatal("nondeterministic output")
			}
		}
	}
}

func TestRepackRejectsCorruptionAndUnsupportedEnvelopeBeforeOutput(t *testing.T) {
	_, input := repackInput(t)
	footer := func(b []byte) []byte { return b[len(b)-512:] }
	metadata := func(b []byte, edit func([]byte) []byte) []byte {
		f := append([]byte(nil), footer(b)...)
		offset := int(binary.BigEndian.Uint64(f[216:]))
		xml := edit(b[offset : len(b)-512])
		binary.BigEndian.PutUint64(f[224:], uint64(len(xml)))
		result := append(append([]byte(nil), b[:offset]...), xml...)
		return append(result, f...)
	}
	table := func(b []byte, edit func([]byte)) []byte {
		return metadata(b, func(xml []byte) []byte {
			start := bytes.Index(xml, []byte("<data>")) + 6
			end := start + bytes.Index(xml[start:], []byte("</data>"))
			data, err := base64.StdEncoding.DecodeString(string(xml[start:end]))
			if err != nil {
				t.Fatal(err)
			}
			edit(data)
			replacement := []byte(base64.StdEncoding.EncodeToString(data))
			return bytes.Replace(xml, xml[start:end], replacement, 1)
		})
	}
	tests := []struct {
		name   string
		change func([]byte) []byte
		want   error
	}{
		{"stored data checksum", func(b []byte) []byte { b[99] ^= 1; return b }, filesystem.ErrCorrupt},
		{"block checksum", func(b []byte) []byte { return table(b, func(t []byte) { t[72] ^= 1 }) }, filesystem.ErrCorrupt},
		{"master checksum", func(b []byte) []byte { footer(b)[360] ^= 1; return b }, filesystem.ErrCorrupt},
		{"checksum algorithm", func(b []byte) []byte { footer(b)[83] = 99; return b }, filesystem.ErrUnsupported},
		{"signature", func(b []byte) []byte { footer(b)[303] = 1; return b }, filesystem.ErrUnsupported},
		{"chunk coverage gap", func(b []byte) []byte { return table(b, func(t []byte) { binary.BigEndian.PutUint64(t[220:], 8191) }) }, filesystem.ErrCorrupt},
		{"unknown resource", func(b []byte) []byte {
			return metadata(b, func(x []byte) []byte {
				return bytes.Replace(x, []byte("<key>blkx</key>"), []byte("<key>license</key><string>keep me</string><key>blkx</key>"), 1)
			})
		}, filesystem.ErrUnsupported},
		{"duplicate key", func(b []byte) []byte {
			return metadata(b, func(x []byte) []byte {
				return bytes.Replace(x, []byte("<key>Attributes</key>"), []byte("<key>Name</key><string>duplicate</string><key>Attributes</key>"), 1)
			})
		}, filesystem.ErrCorrupt},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := tt.change(append([]byte(nil), input...))
			var out bytes.Buffer
			_, err := Repack(context.Background(), &out, bytes.NewReader(b), "UDZO")
			if !errors.Is(err, tt.want) || out.Len() != 0 {
				t.Fatalf("got %v and %d output bytes; want %v", err, out.Len(), tt.want)
			}
		})
	}
}

func TestRepackCancellationAndOutputFailure(t *testing.T) {
	raw, input := repackInput(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	if _, err := Repack(ctx, &out, bytes.NewReader(input), "UDZO"); !errors.Is(err, context.Canceled) || out.Len() != 0 {
		t.Fatal(err)
	}
	failure := errors.New("destination failed")
	if _, err := Repack(context.Background(), errorWriter{failure}, bytes.NewReader(raw), "UDRO"); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if _, err := Repack(context.Background(), shortRepackWriter{}, bytes.NewReader(raw), "UDRO"); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
}

type errorWriter struct{ err error }

func (w errorWriter) Write([]byte) (int, error) { return 0, w.err }

type shortRepackWriter struct{}

func (shortRepackWriter) Write(p []byte) (int, error) { return len(p) / 2, nil }

// The existing GPT fixture isolates partition integrity. Add the backup copy so
// repacking can qualify both copies without relying on filesystem interpretation.
func TestRepackRawGPTBackupIntegrityAndSectorAdmission(t *testing.T) {
	raw := gptFixture(512)
	le := binary.LittleEndian
	copy(raw[10*512:], raw[2*512:2*512+256])
	backup := raw[11*512:]
	copy(backup, raw[512:1024])
	le.PutUint64(backup[24:], 11)
	le.PutUint64(backup[32:], 1)
	le.PutUint64(backup[72:], 10)
	clear(backup[16:20])
	le.PutUint32(backup[16:], crc32.ChecksumIEEE(backup[:92]))
	var out bytes.Buffer
	if _, err := Repack(context.Background(), &out, bytes.NewReader(raw), "UDRO"); err != nil {
		t.Fatal(err)
	}
	for _, at := range []int{10*512 + 16, 11*512 + 16} {
		b := append([]byte(nil), raw...)
		b[at] ^= 1
		out.Reset()
		if _, err := Repack(context.Background(), &out, bytes.NewReader(b), "UDRO"); !errors.Is(err, filesystem.ErrCorrupt) || out.Len() != 0 {
			t.Fatal("bad backup accepted", err)
		}
	}
	out.Reset()
	if _, err := Repack(context.Background(), &out, bytes.NewReader(gptFixture(4096)), "UDRO"); !errors.Is(err, filesystem.ErrUnsupported) || out.Len() != 0 {
		t.Fatal("unqualified logical sector size accepted", err)
	}
}

func FuzzRepackAdmission(f *testing.F) {
	raw := make([]byte, 8192)
	copy(raw[32:], "NXSB")
	var encoded bytes.Buffer
	if err := Encode(context.Background(), &encoded, bytes.NewReader(raw), int64(len(raw)), "UDZO"); err != nil {
		f.Fatal(err)
	}
	f.Add(encoded.Bytes())
	f.Add(raw)
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		image, err := New(bytes.NewReader(b))
		if err != nil {
			return
		}
		defer image.Close()
		// Limit output work independently of attacker-controlled sector counts.
		if image.Size() > 1<<20 {
			return
		}
		_, _ = Repack(context.Background(), io.Discard, bytes.NewReader(b), "UDRO")
	})
}
