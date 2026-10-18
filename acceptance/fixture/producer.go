package fixture

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// toolsToIdentify are hashed into every observation so a verdict can be
// tied to the exact Apple binaries that produced it.
var toolsToIdentify = []string{
	"/usr/bin/hdiutil", "/usr/sbin/diskutil", "/sbin/newfs_hfs", "/sbin/newfs_apfs", "/sbin/fsck_hfs",
	"/System/Library/Filesystems/apfs.fs/Contents/Resources/fsck_apfs", "/usr/bin/ditto", "/bin/cp", "/bin/ln",
	"/usr/bin/codesign", "/usr/sbin/asr", "/usr/bin/xattr", "/usr/bin/chflags", "/usr/bin/compression_tool",
	"/System/Library/Filesystems/apfs.fs/Contents/Resources/apfs.util",
}

// IdentifyProducer records the macOS version, build, architecture, runner
// environment and tool digests. It refuses a host whose major version is
// not the expected one, so a mislabeled runner cannot produce a mislabeled
// bundle.
func IdentifyProducer(ctx context.Context, c Commander, expectedMajor int, captureToolDigest string) (schema.Producer, error) {
	version, err := swVers(ctx, c, "-productVersion")
	if err != nil {
		return schema.Producer{}, err
	}
	build, err := swVers(ctx, c, "-buildVersion")
	if err != nil {
		return schema.Producer{}, err
	}
	major, _ := strconv.Atoi(strings.SplitN(version, ".", 2)[0])
	if major != expectedMajor {
		return schema.Producer{}, fmt.Errorf("host is macOS %s, expected major %d", version, expectedMajor)
	}
	p := schema.Producer{Major: major, Version: version, Build: build, Architecture: runtime.GOARCH, Tools: map[string]string{}, CaptureTool: captureToolDigest}
	p.Runner = "local"
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		p.Runner = os.Getenv("RUNNER_ENVIRONMENT")
		p.Repository = os.Getenv("GITHUB_REPOSITORY")
		p.Commit = os.Getenv("GITHUB_SHA")
		if server, run := os.Getenv("GITHUB_SERVER_URL"), os.Getenv("GITHUB_RUN_ID"); server != "" && run != "" {
			p.RunURL = fmt.Sprintf("%s/%s/actions/runs/%s", server, p.Repository, run)
		}
	}
	for _, tool := range toolsToIdentify {
		sum, err := schema.FileDigest(tool)
		if err != nil {
			continue
		}
		p.Tools[tool] = sum
	}
	return p, nil
}

func swVers(ctx context.Context, c Commander, flag string) (string, error) {
	result := c.Run(ctx, Command{Argv: []string{"sw_vers", flag}, Expected: "0"})
	if result.Err != nil || result.Status != 0 {
		return "", fmt.Errorf("sw_vers %s failed", flag)
	}
	return strings.TrimSpace(string(result.Stdout)), nil
}

// RequireDisposableHost refuses to run native filesystem operations outside
// a GitHub-hosted runner unless the caller asserts it is inside another
// disposable VM. A development Mac once panicked under these tests.
func RequireDisposableHost() error {
	if os.Getenv("APFS_NATIVE_DISPOSABLE_VM") == "1" {
		return nil
	}
	if os.Getenv("GITHUB_ACTIONS") == "true" && os.Getenv("RUNNER_ENVIRONMENT") == "github-hosted" {
		return nil
	}
	return fmt.Errorf("native fixture capture runs only on a disposable VM: set APFS_NATIVE_DISPOSABLE_VM=1 inside one, or run on a GitHub-hosted macOS runner")
}
