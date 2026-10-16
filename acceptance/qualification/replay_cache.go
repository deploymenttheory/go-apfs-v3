package main

import (
	"errors"
	"os"
	"path/filepath"
)

// Hosted replay invocations share only immutable decoded inputs. Runner-owned
// temporary storage bounds their lifetime to this job, without a remote cache.
func replayDecodedCacheDirectory() (string, error) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		return "", nil
	}
	root := os.Getenv("RUNNER_TEMP")
	if !filepath.IsAbs(root) {
		return "", errors.New("hosted decoded input cache requires absolute runner-owned scratch")
	}
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "apfs-decoded-inputs"), nil
}
