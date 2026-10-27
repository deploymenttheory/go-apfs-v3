package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

func TestVolumeConversionCommandsKeepEnvelopeAndVolumeCredentialsIndependent(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	directory := filepath.Join(root, "input")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "file"), []byte("preserved contents"), 0600); err != nil {
		t.Fatal(err)
	}
	imagePassword, volumePassword := "public-envelope-secret", "public-volume-secret-λ\n"
	outerPath, innerPath := filepath.Join(root, "image-password"), filepath.Join(root, "volume-password")
	for path, password := range map[string]string{outerPath: imagePassword, innerPath: volumePassword} {
		if err := os.WriteFile(path, []byte(password), 0600); err != nil {
			t.Fatal(err)
		}
	}
	invoke := func(input string, args ...string) string {
		t.Helper()
		var out, diagnostics bytes.Buffer
		if err := run(ctx, args, strings.NewReader(input), &out, &diagnostics); err != nil {
			t.Fatal(args, err, diagnostics.String())
		}
		for _, secret := range []string{imagePassword, volumePassword} {
			if strings.Contains(out.String()+diagnostics.String(), secret) {
				t.Fatal("credential leaked")
			}
		}
		return out.String()
	}
	source := filepath.Join(root, "source.dmg")
	invoke("", "pack", "--filesystem", "apfs", "--encryption", "AES-128", "--output-password-file", outerPath, directory, source)
	encrypted, plain := filepath.Join(root, "encrypted.dmg"), filepath.Join(root, "plain-volume.dmg")
	result := invoke(volumePassword, "encrypt", "--image", source, "--output", encrypted, "--image-password-file", outerPath, "--new-password-file", "-", "--json")
	var report imageedit.Report
	if err := json.Unmarshal([]byte(result), &report); err != nil || report.VolumeEncryption == nil || !report.VolumeEncryption.Completed || !report.VolumeEncryption.Encrypted {
		t.Fatal("missing completed encryption report", err, result)
	}
	invoke("", "decrypt", "--image", encrypted, "--output", plain, "--image-password-file", outerPath, "--password-file", innerPath)
	got := invoke("", "cat", "--image-password-file", outerPath, plain, "/file")
	if got != "preserved contents" {
		t.Fatal("conversion changed contents", got)
	}
	if err := run(ctx, []string{"encrypt", "--image", source, "--output", filepath.Join(root, "ambiguous.dmg"), "--image-password-file", "-", "--new-password-file", "-"}, strings.NewReader("unused"), io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "only one") {
		t.Fatal("two credentials consumed stdin", err)
	}
}
