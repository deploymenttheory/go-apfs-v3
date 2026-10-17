package main

import (
	"path/filepath"
	"testing"
)

func TestDecodedReplayCacheUsesOnlyHostedJobTemporaryStorage(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "false")
	t.Setenv("RUNNER_ENVIRONMENT", "github-hosted")
	t.Setenv("RUNNER_TEMP", "not-an-absolute-path")
	if directory, err := replayDecodedCacheDirectory(); err != nil || directory != "" {
		t.Fatal("ordinary local replay enabled persistent caching", directory, err)
	}
	t.Setenv("GITHUB_ACTIONS", "true")
	if _, err := replayDecodedCacheDirectory(); err == nil {
		t.Fatal("relative cache scratch accepted")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("RUNNER_TEMP", root)
	if directory, err := replayDecodedCacheDirectory(); err != nil || directory != filepath.Join(root, "apfs-decoded-inputs") {
		t.Fatal("hosted job lost its shared managed cache", directory, err)
	}
	t.Setenv("RUNNER_ENVIRONMENT", "self-hosted")
	if directory, err := replayDecodedCacheDirectory(); err != nil || directory != "" {
		t.Fatal("unowned host enabled persistent decoded caching", directory, err)
	}
}
