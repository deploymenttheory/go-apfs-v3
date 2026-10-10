package diskimage

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

func encryptedBytes(t *testing.T, bits uint32, payload []byte) []byte {
	t.Helper()
	f, err := os.Create(filepath.Join(t.TempDir(), "encrypted.dmg"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	password := []byte("exact-password\n")
	n, err := Encrypt(context.Background(), f, EncryptionOptions{bits, password}, func(w io.Writer) error {
		// Deliberately split across cipher, sector and buffer boundaries.
		for len(payload) > 0 {
			amount := min(len(payload), 517)
			if _, err := w.Write(payload[:amount]); err != nil {
				return err
			}
			payload = payload[amount:]
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(password) != "exact-password\n" {
		t.Fatal("modified caller password")
	}
	position, err := f.Seek(0, io.SeekCurrent)
	if err != nil || position != n {
		t.Fatal("incorrect completed output position", position, n, err)
	}
	b, err := os.ReadFile(f.Name())
	if err != nil || int64(len(b)) != n {
		t.Fatal("incorrect output size", err)
	}
	return b
}

// The independent Apple gate qualifies the format. This isolates streaming,
// partial final blocks, fresh randomness and exact borrowed-password handling.
func TestEncryptStreamingAndFreshRandomness(t *testing.T) {
	payload := bytes.Repeat([]byte("nonuniform byte stream"), 6503)
	for _, bits := range []uint32{128, 256} {
		first := encryptedBytes(t, bits, payload)
		second := encryptedBytes(t, bits, payload)
		for _, span := range [][2]int{{36, 52}, {112, 132}, {148, 156}, {200, 248}, {122368, len(first)}} {
			if bytes.Equal(first[span[0]:span[1]], second[span[0]:span[1]]) {
				t.Fatal("reused identity, salt, IV, keys or ciphertext", bits, span)
			}
		}
		e, records, err := readEnvelope(bytes.NewReader(first))
		if err != nil {
			t.Fatal(err)
		}
		if err = e.unlock(context.Background(), []byte("exact-password\n"), records); err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(io.NewSectionReader(e, 0, e.Size()))
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatal("stream changed", err)
		}
		if err = e.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

type failingEncryptedOutput struct {
	*os.File
	failWrite, writes int
	patch             bool
	err               error
}

func (f *failingEncryptedOutput) Write(b []byte) (int, error) {
	f.writes++
	if f.writes == f.failWrite {
		if f.err == nil {
			return len(b) / 2, nil
		}
		return 0, f.err
	}
	return f.File.Write(b)
}
func (f *failingEncryptedOutput) Seek(offset int64, whence int) (int64, error) {
	if f.patch && offset == 56 && whence == io.SeekStart {
		return 0, f.err
	}
	return f.File.Seek(offset, whence)
}
func TestEncryptFailureDoesNotCompleteHeader(t *testing.T) {
	sentinel := errors.New("output unavailable")
	for _, tc := range []struct {
		name          string
		failWrite     int
		patch         bool
		failure, want error
	}{
		{"short header", 1, false, nil, io.ErrShortWrite},
		{"buffered payload failure", 2, false, sentinel, sentinel},
		{"final seek failure", 0, true, sentinel, sentinel},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := os.Create(filepath.Join(t.TempDir(), "out"))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			out := &failingEncryptedOutput{File: f, failWrite: tc.failWrite, patch: tc.patch, err: tc.failure}
			_, err = Encrypt(context.Background(), out, EncryptionOptions{128, []byte("password")}, func(w io.Writer) error { _, e := w.Write(make([]byte, 513)); return e })
			if !errors.Is(err, tc.want) {
				t.Fatal(err)
			}
			b, err := os.ReadFile(f.Name())
			if err != nil {
				t.Fatal(err)
			}
			if len(b) >= 64 && binary.BigEndian.Uint64(b[56:]) != 0 {
				t.Fatal("failed write marked complete")
			}
		})
	}
	// A callback error must propagate even if it wrote a valid-sized prefix.
	f, err := os.Create(filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	_, err = Encrypt(context.Background(), f, EncryptionOptions{256, []byte("password")}, func(w io.Writer) error { _, _ = w.Write(make([]byte, 512)); return sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(f.Name())
	if binary.BigEndian.Uint64(b[56:]) != 0 {
		t.Fatal("callback failure completed header")
	}
}

func TestEncryptRejectsInvalidOptionsAndExistingOutput(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	produce := func(io.Writer) error { t.Fatal("invalid request reached producer"); return nil }
	for _, o := range []EncryptionOptions{{128, nil}, {128, make([]byte, 4097)}, {128, []byte("a\x00b")}, {192, []byte("password")}} {
		if _, err = Encrypt(context.Background(), f, o, produce); err == nil {
			t.Fatal("invalid options accepted")
		}
	}
	o := EncryptionOptions{128, []byte("password")}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = Encrypt(ctx, f, o, produce); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err = f.WriteString("existing"); err != nil {
		t.Fatal(err)
	}
	for _, off := range []int64{0, 3} {
		if _, err = f.Seek(off, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		if _, err = Encrypt(context.Background(), f, o, produce); !errors.Is(err, fs.ErrInvalid) {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(f.Name())
	if string(b) != "existing" {
		t.Fatal("overwrote existing output")
	}
}

func TestEncryptedRepackRequiresPolicyAndRetainsAdmissionChecks(t *testing.T) {
	_, input := repackInput(t)
	// Encrypt a real UDIF, then exercise the public repacker with an unknown
	// outer resource, damaged ciphertext and a signature hidden inside encryption.
	encrypted := encryptedBytes(t, 128, input)
	for _, tc := range []struct {
		name   string
		data   []byte
		policy bool
		want   error
	}{
		{"missing explicit policy", encrypted, false, fs.ErrInvalid},
		{"truncated ciphertext", encrypted[:len(encrypted)-1], true, filesystem.ErrCorrupt},
		{"wrong password", encrypted, true, filesystem.ErrAuthentication},
	} {
		t.Run(tc.name, func(t *testing.T) {
			password := []byte("exact-password\n")
			if tc.name == "wrong password" {
				password = []byte("incorrect")
			}
			var out bytes.Buffer
			_, err := RepackWithOptions(context.Background(), &out, bytes.NewReader(tc.data), RepackOptions{SourcePassword: password, Decrypt: tc.policy})
			if !errors.Is(err, tc.want) || out.Len() != 0 {
				t.Fatal(err, out.Len())
			}
		})
	}
	for _, tc := range []struct {
		name   string
		mutate func([]byte)
		want   error
	}{
		{"unknown header bytes", func(b []byte) { b[800] = 1 }, filesystem.ErrUnsupported},
		{"payload checksum", func(b []byte) { b[122368+99] ^= 1 }, filesystem.ErrCorrupt},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := bytes.Clone(encrypted)
			tc.mutate(b)
			var out bytes.Buffer
			_, err := RepackWithOptions(context.Background(), &out, bytes.NewReader(b), RepackOptions{SourcePassword: []byte("exact-password\n"), Decrypt: true})
			if !errors.Is(err, tc.want) || out.Len() != 0 {
				t.Fatal(err, out.Len())
			}
		})
	}
	input[len(input)-512+303] = 1
	signed := encryptedBytes(t, 128, input)
	var out bytes.Buffer
	_, err := RepackWithOptions(context.Background(), &out, bytes.NewReader(signed), RepackOptions{SourcePassword: []byte("exact-password\n"), Decrypt: true})
	if !errors.Is(err, filesystem.ErrUnsupported) || out.Len() != 0 {
		t.Fatal("encrypted signed image accepted", err, out.Len())
	}
}
