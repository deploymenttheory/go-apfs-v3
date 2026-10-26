package main

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

func TestEncryptedImageCommandsPreserveRekeyAndRemoveEnvelope(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	directory := filepath.Join(root, "input")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	host := filepath.Join(directory, "file")
	if err := os.WriteFile(host, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	old, replacement := "old-edit-secret-λ-😀\n", "new-edit-secret\n"
	oldPath, newPath := filepath.Join(root, "old-password"), filepath.Join(root, "new-password")
	for path, password := range map[string]string{oldPath: old, newPath: replacement} {
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
		for _, secret := range []string{old, replacement} {
			if strings.Contains(out.String()+diagnostics.String(), strings.TrimSpace(secret)) {
				t.Fatal("credential leaked in output")
			}
		}
		return out.String()
	}
	source := filepath.Join(root, "source.dmg")
	invoke("", "pack", "--filesystem", "apfs", "--time", "2025-06-07T08:09:10Z", "--encryption", "AES-128", "--output-password-file", oldPath, directory, source)
	original, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(host, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	copyPath, rekeyPath, strongPath, plainPath := filepath.Join(root, "copy.dmg"), filepath.Join(root, "rekey.dmg"), filepath.Join(root, "strong.dmg"), filepath.Join(root, "plain.dmg")
	invoke(old, "cp", "--image", source, "--output", copyPath, "--image-password-file", "-", "--time", "2025-06-07T08:09:10Z", "--json", "--from-host", host, "/file")
	invoke("", "edit", "--image", copyPath, "--output", rekeyPath, "--image-password-file", oldPath, "--output-password-file", newPath, "--time", "2025-06-07T08:09:10Z", "--json", "--", "mkdir", "/created", "--next", "cp", "-p", "/file", "/created/copied", "--next", "chmod", "0751", "/created/copied")
	invoke(replacement, "chmod", "--image", rekeyPath, "--output", strongPath, "--image-password-file", "-", "--encryption", "AES-256", "--output-password-file", oldPath, "--time", "2025-06-07T08:09:10Z", "0700", "/created/copied")
	invoke(old, "touch", "--image", strongPath, "--output", plainPath, "--image-password-file", "-", "--encryption", "none", "--time", "2025-06-07T08:09:10Z", "/created/empty")
	for _, tc := range []struct {
		path, password string
		bits           uint32
	}{{copyPath, old, 128}, {rekeyPath, replacement, 128}, {strongPath, old, 256}, {plainPath, "", 0}} {
		var image *diskimage.Image
		if tc.bits == 0 {
			image, err = diskimage.Open(tc.path)
		} else {
			image, err = diskimage.OpenWithPassword(ctx, tc.path, []byte(tc.password))
		}
		if err != nil {
			t.Fatal(err)
		}
		if (image.Encryption == nil) != (tc.bits == 0) || image.Encryption != nil && image.Encryption.KeyBits != tc.bits {
			t.Fatal("wrong output policy", image.Encryption)
		}
		image.Close()
		args := []string{"cat"}
		if tc.bits != 0 {
			args = append(args, "--image-password-file", "-")
		}
		args = append(args, tc.path, "/file")
		if got := invoke(tc.password, args...); got != "replacement" {
			t.Fatal(got)
		}
	}
	if got := invoke("", "cat", plainPath, "/created/copied"); got != "replacement" {
		t.Fatal("ordered copy lost contents", got)
	}
	for _, tc := range []struct {
		flags []string
		input string
		want  error
	}{
		{nil, "", filesystem.ErrAuthentication},
		{[]string{"--image-password-file", "-"}, strings.TrimSpace(old), filesystem.ErrAuthentication},
		{[]string{"--password-file", oldPath}, "", filesystem.ErrAuthentication},
		{[]string{"--image-password-file", oldPath, "--password-file", newPath}, "", fs.ErrInvalid},
		{[]string{"--image-password-file", "-", "--output-password-file", "-"}, old, nil},
		{[]string{"--image-password-file", "-", "--password-file", "-"}, old, nil},
		{[]string{"--image-password-file", oldPath, "--encryption", "AES-256"}, "", nil},
		{[]string{"--image-password-file", oldPath, "--encryption", "none", "--output-password-file", newPath}, "", nil},
	} {
		destination := filepath.Join(t.TempDir(), "refused.dmg")
		args := append([]string{"chmod", "--image", source, "--output", destination}, tc.flags...)
		args = append(args, "0600", "/file")
		var out, diagnostics bytes.Buffer
		err := run(ctx, args, strings.NewReader(tc.input), &out, &diagnostics)
		if err == nil || tc.want != nil && !errors.Is(err, tc.want) {
			t.Fatal("wrong refusal", args, err)
		}
		if out.Len() != 0 || strings.Contains(err.Error()+diagnostics.String(), strings.TrimSpace(old)) {
			t.Fatal("failure leaked credential or output")
		}
		if _, err := os.Stat(destination); !errors.Is(err, fs.ErrNotExist) {
			t.Fatal("failure published output", err)
		}
	}
	after, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("commands changed source", err)
	}
	var out, diagnostics bytes.Buffer
	refused := filepath.Join(t.TempDir(), "misplaced.dmg")
	err = run(ctx, []string{"edit", "--image", source, "--output", refused, "--image-password-file", oldPath, "--", "mkdir", "--image-password-file", "-", "/dir"}, strings.NewReader(old), &out, &diagnostics)
	if err == nil || !strings.Contains(err.Error(), "belongs to the enclosing edit command") {
		t.Fatal("inner command accepted image credential flags", err)
	}
	if _, err := os.Stat(refused); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("misplaced credential command published output", err)
	}
}

func TestEditEncryptionFlagsStayAtImageBoundary(t *testing.T) {
	for _, args := range [][]string{
		{"mkdir", "--session", "unused", "--image-password-file", "-", "/dir"},
		{"mkdir", "--session", "unused", "--volume-password-file", "peer=-", "/dir"},
	} {
		var out, diagnostics bytes.Buffer
		if err := run(context.Background(), args, strings.NewReader("password"), &out, &diagnostics); err == nil {
			t.Fatal("misplaced image credential flag accepted")
		}
	}
}
