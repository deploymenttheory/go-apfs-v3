package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestBuildExecutableIdentityUsesActualBytesAndLeavesItsSourceUnchanged(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "compiler")
	before := []byte("original compiler bytes")
	if err := os.WriteFile(filename, before, 0700); err != nil {
		t.Fatal(err)
	}
	first, err := executableIdentity(context.Background(), filename, "toolchain/compile")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(before)
	if first.SHA256 != hex.EncodeToString(sum[:]) || first.Bytes != int64(len(before)) {
		t.Fatal("actual compiler bytes were not fingerprinted", first)
	}
	data, err := os.ReadFile(filename)
	if err != nil || !reflect.DeepEqual(data, before) {
		t.Fatal("fingerprinting mutated its source", err)
	}
	if err = os.WriteFile(filename, []byte("changed compiler bytes!"), 0700); err != nil {
		t.Fatal(err)
	}
	changed, err := executableIdentity(context.Background(), filename, first.Path)
	if err != nil || changed.SHA256 == first.SHA256 {
		t.Fatal("a replaced compiler inherited its previous identity", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = executableIdentity(cancelled, filename, first.Path); !errors.Is(err, context.Canceled) {
		t.Fatal("interrupted fingerprint admitted", err)
	}
}

func TestBuildExecutableIdentityRefusesAbsentSpecialEmptyAndOversizedTools(t *testing.T) {
	root := t.TempDir()
	for _, kind := range []string{"absent", "directory", "empty", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			filename := filepath.Join(root, kind)
			if kind == "directory" {
				if err := os.Mkdir(filename, 0700); err != nil {
					t.Fatal(err)
				}
			} else if kind != "absent" {
				file, err := os.Create(filename)
				if err != nil {
					t.Fatal(err)
				}
				if kind == "oversized" {
					err = file.Truncate((512 << 20) + 1)
				}
				closeErr := file.Close()
				if err != nil || closeErr != nil {
					t.Fatal(err, closeErr)
				}
			}
			if _, err := executableIdentity(context.Background(), filename, "toolchain/compile"); err == nil {
				t.Fatal("invalid build tool admitted")
			}
		})
	}
}

func TestReplayBuildIdentityTracksActualToolsAndResolvedBuildFlags(t *testing.T) {
	t.Setenv("CGO_ENABLED", "0")
	t.Setenv("GOFLAGS", "")
	t.Setenv("GOWORK", "off")
	first, tools, err := replayBuildIdentity(context.Background(), "../..")
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) < 5 || !strings.Contains(first, "GOEXPERIMENT") || !strings.Contains(first, "GOARM64") {
		t.Fatal("actual build inputs missing", first, tools)
	}
	for _, tool := range tools {
		if tool.Bytes <= 0 || len(tool.SHA256) != 64 {
			t.Fatal("tool has no executable identity", tool)
		}
	}
	t.Setenv("GOFLAGS", "-tags=qualification_control")
	changed, sameTools, err := replayBuildIdentity(context.Background(), "../..")
	if err != nil || first == changed || !reflect.DeepEqual(tools, sameTools) {
		t.Fatal("build flags did not invalidate their fingerprint", err)
	}
	for _, override := range []string{"-overlay=/missing/control.json", "-modfile=/missing/go.mod", "-toolexec=/missing/compiler-wrapper"} {
		t.Setenv("GOFLAGS", override)
		if _, _, err = replayBuildIdentity(context.Background(), "../.."); err == nil {
			t.Fatal("unbound external build input admitted", override)
		}
	}
}
