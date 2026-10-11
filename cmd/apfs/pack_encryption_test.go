package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise the user's whole password-change/decryption journey through the CLI.
// Exact newline-bearing password bytes must survive file and stdin transport.
func TestPackEncryptedImagePasswordJourney(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "input.dmg")
	directory := filepath.Join(root, "empty")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	var initialOut, initialDiag bytes.Buffer
	if err := run(context.Background(), []string{"pack", "--filesystem", "hfsplus", directory, source}, nil, &initialOut, &initialDiag); err != nil {
		t.Fatal(err)
	}
	oldPath, newPath := filepath.Join(root, "old-password"), filepath.Join(root, "new-password")
	for path, secret := range map[string]string{oldPath: "old-secret\n", newPath: "new-secret-λ-😀"} {
		if err := os.WriteFile(path, []byte(secret), 0600); err != nil {
			t.Fatal(err)
		}
	}
	first, changed, plain := filepath.Join(root, "first.dmg"), filepath.Join(root, "changed.dmg"), filepath.Join(root, "plain.dmg")
	commands := [][]string{
		{"pack", "--json", "--encryption", "AES-128", "--output-password-file", "-", source, first},
		{"pack", "--json", "--encryption", "AES-256", "--image-password-file", oldPath, "--output-password-file", newPath, first, changed},
		{"pack", "--json", "--encryption", "none", "--image-password-file", "-", changed, plain},
	}
	inputs := []string{"old-secret\n", "", "new-secret-λ-😀"}
	for i, args := range commands {
		var out, diag bytes.Buffer
		if err := run(context.Background(), args, strings.NewReader(inputs[i]), &out, &diag); err != nil {
			t.Fatal(i, err, diag.String())
		}
		for _, secret := range []string{"old-secret", "new-secret"} {
			if strings.Contains(out.String()+diag.String(), secret) {
				t.Fatal("password leaked in report")
			}
		}
		if !strings.Contains(out.String(), `"diskSHA256"`) {
			t.Fatal("missing preservation report")
		}
	}
	for _, tc := range []struct {
		image, password string
		ok              bool
	}{
		{first, oldPath, true}, {first, newPath, false}, {changed, newPath, true}, {changed, oldPath, false}, {plain, "", true},
	} {
		args := []string{"info"}
		if tc.password != "" {
			args = append(args, "--image-password-file", tc.password)
		}
		args = append(args, tc.image)
		var out, diag bytes.Buffer
		err := run(context.Background(), args, nil, &out, &diag)
		if (err == nil) != tc.ok {
			t.Fatal(tc.image, "unexpected password result", err)
		}
	}
	before, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	for _, flags := range [][]string{
		{}, {"--image-password-file", oldPath},
		{"--encryption", "AES-128"},
		{"--encryption", "none", "--output-password-file", newPath},
		{"--encryption", "AES-256", "--image-password-file", "-", "--output-password-file", "-"},
		{"--encryption", "AES-256", "--image-password-file", newPath, "--output-password-file", oldPath},
	} {
		destination := filepath.Join(root, "refused.dmg")
		args := append([]string{"pack"}, flags...)
		args = append(args, first, destination)
		var out, diag bytes.Buffer
		if err := run(context.Background(), args, strings.NewReader("password"), &out, &diag); err == nil {
			t.Fatal("accepted missing/invalid password policy", flags)
		}
		if _, err := os.Stat(destination); !os.IsNotExist(err) {
			t.Fatal("published refused output", err)
		}
	}
	after, err := os.ReadFile(first)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("source changed", err)
	}
}

func TestPackEncryptedDirectorySessionAndContainer(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	scratch := filepath.Join(root, "scratch")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "file"), []byte("contents"), 0600); err != nil {
		t.Fatal(err)
	}
	runCommand := func(args []string) string {
		t.Helper()
		var out, diag bytes.Buffer
		if err := run(context.Background(), args, strings.NewReader("password"), &out, &diag); err != nil {
			t.Fatal(args, err, diag.String())
		}
		return out.String()
	}
	runCommand([]string{"session", "create", "--scratch-dir", scratch, "--filesystem", "hfsplus", "build"})
	runCommand([]string{"cp", "--scratch-dir", scratch, "--session", "build", "--from-host", filepath.Join(source, "file"), "/file"})
	for i, args := range [][]string{
		{"pack", "--filesystem", "apfs", source},
		{"pack", "--scratch-dir", scratch, "--session", "build"},
		{"pack", "--volume", "Apps", "--directory", source, "--volume", "Empty"},
	} {
		image := filepath.Join(root, []string{"directory.dmg", "session.dmg", "container.dmg"}[i])
		args = append(args, "--encryption", "AES-256", "--output-password-file", "-", image)
		if out := runCommand(args); !strings.Contains(out, "Image encryption: AES-256") {
			t.Fatal(out)
		}
		if i < 2 {
			if got := runCommand([]string{"cat", "--image-password-file", "-", image, "/file"}); got != "contents" {
				t.Fatal(got)
			}
		}
	}
	var out, diag bytes.Buffer
	err := run(context.Background(), []string{"pack", "--filesystem", "apfs", "--image-password-file", "-", source, filepath.Join(root, "refused.dmg")}, nil, &out, &diag)
	if err == nil || !strings.Contains(err.Error(), "only to image repacking") {
		t.Fatal(err)
	}
}
