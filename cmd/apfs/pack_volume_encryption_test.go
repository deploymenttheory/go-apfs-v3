package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/deploymenttheory/go-apfs-v3/pack"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestPackCreatesEncryptedAPFSWithIndependentEnvelopeCredential(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	source := filepath.Join(root, "input")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "file"), []byte("constructed encrypted payload"), 0644); err != nil {
		t.Fatal(err)
	}
	volume := filepath.Join(root, "volume-password")
	image := filepath.Join(root, "image-password")
	for name, data := range map[string]string{volume: "public-volume", image: "public-envelope"} {
		if err := os.WriteFile(name, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, envelope := range []bool{false, true} {
		path := filepath.Join(root, fmt.Sprintf("envelope-%t.dmg", envelope))
		args := []string{"pack", "--filesystem", "apfs", "--volume-password-file", volume, "--time", "2025-06-07T08:09:10Z"}
		if envelope {
			args = append(args, "--encryption", "AES-256", "--output-password-file", image)
		}
		args = append(args, source, path)
		var out, diag bytes.Buffer
		if err := run(ctx, args, nil, &out, &diag); err != nil {
			t.Fatal(err, diag.String())
		}
		cat := []string{"cat", "--password-file", volume}
		if envelope {
			cat = append(cat, "--image-password-file", image)
		}
		cat = append(cat, path, "/file")
		out.Reset()
		if err := run(ctx, cat, nil, &out, &diag); err != nil || out.String() != "constructed encrypted payload" {
			t.Fatal("readback", out.String(), err, diag.String())
		}
		cat = []string{"cat", "--password-file", image}
		if envelope {
			cat = append(cat, "--image-password-file", image)
		}
		cat = append(cat, path, "/file")
		out.Reset()
		if err := run(ctx, cat, nil, &out, &diag); err == nil || out.Len() != 0 {
			t.Fatal("exchanged volume credential succeeded", err)
		}
	}
}

func TestPackScopesIndependentVolumePasswordsAndRejectsSharedStdin(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	primary := filepath.Join(root, "primary")
	peer := filepath.Join(root, "peer")
	if err := os.WriteFile(primary, []byte("public-primary"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(peer, []byte("public-peer"), 0600); err != nil {
		t.Fatal(err)
	}
	var out, diag bytes.Buffer
	args := []string{"pack", "--json", "--volume", "Primary", "--directory", source, "--volume-password-file", primary, "--volume", "Plain", "--volume", "Peer", "--volume-password-file", peer, filepath.Join(root, "mixed.dmg")}
	if err := run(ctx, args, nil, &out, &diag); err != nil {
		t.Fatal(err, diag.String())
	}
	var report pack.ContainerReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.VolumeEncryption) != 2 || report.VolumeEncryption[0].Name != "Primary" || report.VolumeEncryption[1].Name != "Peer" || report.Encryption != nil {
		t.Fatal("volume and image encryption reports were conflated", report)
	}
	input := &packPasswordCounter{}
	if err := run(ctx, []string{"pack", "--volume", "First", "--volume-password-file", "-", "--volume", "Second", "--volume-password-file", "-", filepath.Join(root, "refused.dmg")}, input, &out, &diag); err == nil || input.reads != 0 {
		t.Fatal("ambiguous stdin credentials were consumed", err, input.reads)
	}
}

type packPasswordCounter struct{ reads int }

func (r *packPasswordCounter) Read([]byte) (int, error) { r.reads++; return 0, io.EOF }
