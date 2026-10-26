package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

func TestVolumePasswordCommandRequiresBothCredentialFiles(t *testing.T) {
	for _, credentials := range [][]string{nil, {"--password-file", "missing"}, {"--new-password-file", "missing"}} {
		args := append([]string{"passwd", "--image", "missing.dmg", "--output", filepath.Join(t.TempDir(), "new.dmg")}, credentials...)
		if err := run(context.Background(), args, strings.NewReader(""), io.Discard, io.Discard); !errors.Is(err, fs.ErrInvalid) {
			t.Fatal("missing password files reached image access", err)
		}
	}
}

func TestVolumeCredentialFilesCannotShareStdin(t *testing.T) {
	for _, args := range [][]string{
		{"--password-file", "-", "--new-password-file", "-"},
		{"--image-password-file", "-", "--volume-password-file", "uuid=-"},
		{"--volume-password-file", "a=-", "--volume-password-file", "b=-"},
	} {
		f := flag.NewFlagSet("credentials", flag.ContinueOnError)
		addEditEncryptionFlags(f)
		f.String("new-password-file", "", "")
		if err := f.Parse(args); err != nil {
			t.Fatal(err)
		}
		if _, err := editEncryptionOptions(f, strings.NewReader(""), imageedit.Options{}); err == nil || !strings.Contains(err.Error(), "only one") {
			t.Fatal("shared stdin accepted", err)
		}
	}
}

func TestAdditionalVolumeCredentialKeepsExactBytesAndClearsOwnedBuffer(t *testing.T) {
	password := []byte("public-peer-λ\n")
	path := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(path, password, 0600); err != nil {
		t.Fatal(err)
	}
	f := flag.NewFlagSet("credentials", flag.ContinueOnError)
	addEditEncryptionFlags(f)
	if err := f.Parse([]string{"--volume-password-file", "peer-uuid=" + path}); err != nil {
		t.Fatal(err)
	}
	o, err := editEncryptionOptions(f, strings.NewReader(""), imageedit.Options{})
	if err != nil || len(o.VolumeCredentials) != 1 || o.VolumeCredentials[0].VolumeUUID != "peer-uuid" || !bytes.Equal(o.VolumeCredentials[0].Password, password) {
		t.Fatal("credential bytes/selector changed", err)
	}
	clearEditPasswords(o)
	if !bytes.Equal(o.VolumeCredentials[0].Password, make([]byte, len(password))) {
		t.Fatal("owned peer credential was retained")
	}
	stored, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(stored, password) {
		t.Fatal("clearing the credential changed its input file", err)
	}
}
