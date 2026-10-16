package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/receipt"
)

// replayBuildIdentity records resolved code-generation switches and the actual
// compiler/linker bytes. A Go version label alone cannot distinguish changed
// GOEXPERIMENT, architecture levels, an external linker or a replaced tool.
func replayBuildIdentity(ctx context.Context, root string) (string, []receipt.File, error) {
	keys := []string{"GOOS", "GOARCH", "GOHOSTOS", "GOHOSTARCH", "GOAMD64", "GOARM", "GOARM64", "GO386", "GOMIPS", "GOMIPS64", "GOPPC64", "GORISCV64", "GOEXPERIMENT", "GOFIPS140", "CGO_ENABLED", "CC", "CXX", "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_FFLAGS", "CGO_LDFLAGS", "GOFLAGS", "GOTOOLCHAIN", "GOTOOLDIR", "GOROOT", "GOVERSION", "GOWORK", "GO_EXTLINK_ENABLED"}
	args := append([]string{"go", "env", "-json"}, keys...)
	text, err := commandText(ctx, root, args...)
	if err != nil {
		return "", nil, err
	}
	var build map[string]string
	if err = json.Unmarshal([]byte(text), &build); err != nil {
		return "", nil, err
	}
	for _, key := range keys {
		if _, exists := build[key]; !exists {
			return "", nil, fmt.Errorf("actual Go build setting is missing: %s", key)
		}
	}
	// These overrides can replace source/dependencies outside the reviewed tree.
	// They need an explicit dependency contract before qualification can use them.
	if build["GOWORK"] != "" && build["GOWORK"] != "off" || strings.Contains(build["GOFLAGS"], "-overlay") || strings.Contains(build["GOFLAGS"], "-modfile") || strings.Contains(build["GOFLAGS"], "-toolexec") {
		return "", nil, errors.New("external workspace, source overlays and tool wrappers require an explicit qualification identity contract")
	}
	if build["GOOS"] != runtime.GOOS || build["GOARCH"] != runtime.GOARCH || !filepath.IsAbs(build["GOROOT"]) || !filepath.IsAbs(build["GOTOOLDIR"]) {
		return "", nil, errors.New("replay requires its actual host toolchain and absolute tool locations")
	}
	build["GODEBUG"] = os.Getenv("GODEBUG")
	build["CGO_CFLAGS_ALLOW"], build["CGO_CFLAGS_DISALLOW"] = os.Getenv("CGO_CFLAGS_ALLOW"), os.Getenv("CGO_CFLAGS_DISALLOW")
	build["CGO_LDFLAGS_ALLOW"], build["CGO_LDFLAGS_DISALLOW"] = os.Getenv("CGO_LDFLAGS_ALLOW"), os.Getenv("CGO_LDFLAGS_DISALLOW")
	extension := ""
	if runtime.GOOS == "windows" {
		extension = ".exe"
	}
	locations := map[string]string{"toolchain/go": filepath.Join(build["GOROOT"], "bin", "go"+extension)}
	for _, name := range []string{"asm", "compile", "link"} {
		locations["toolchain/"+name] = filepath.Join(build["GOTOOLDIR"], name+extension)
	}
	if build["CGO_ENABLED"] == "1" {
		locations["toolchain/cgo"] = filepath.Join(build["GOTOOLDIR"], "cgo"+extension)
		compiler := build["CC"]
		if compiler == "" || strings.ContainsAny(compiler, "\r\n\t\"'") {
			return "", nil, errors.New("compiler wrappers for cgo require an explicit qualification identity contract")
		}
		// Absolute Windows compiler paths may contain spaces. A command with
		// extra arguments must not be mistaken for the compiler executable.
		if !filepath.IsAbs(compiler) && strings.Contains(compiler, " ") {
			return "", nil, errors.New("compiler wrappers for cgo require an explicit qualification identity contract")
		}
		locations["toolchain/c-compiler"], err = exec.LookPath(compiler)
		if err != nil {
			return "", nil, err
		}
		build["CC_VERSION"], err = commandText(ctx, root, compiler, "--version")
		if err != nil {
			return "", nil, err
		}
	}
	launcher, err := exec.LookPath("go")
	if err != nil {
		return "", nil, err
	}
	locations["toolchain/launcher"] = launcher
	tools := make([]receipt.File, 0, len(locations))
	for name, location := range locations {
		file, err := executableIdentity(ctx, location, name)
		if err != nil {
			return "", nil, fmt.Errorf("build tool %s: %w", name, err)
		}
		tools = append(tools, file)
	}
	slices.SortFunc(tools, func(a, b receipt.File) int { return strings.Compare(a.Path, b.Path) })
	data, err := json.Marshal(build)
	return string(data), tools, err
}

func executableIdentity(ctx context.Context, filename, name string) (receipt.File, error) {
	result := receipt.File{Path: name}
	filename, err := filepath.EvalSymlinks(filename)
	if err != nil {
		return result, err
	}
	input, err := os.Open(filename)
	if err != nil {
		return result, err
	}
	defer func() { _ = input.Close() }()
	info, err := input.Stat()
	if err != nil {
		return result, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 512<<20 {
		return result, errors.New("build tool must be a bounded ordinary executable")
	}
	digest := sha256.New()
	buffer := make([]byte, 64<<10)
	for {
		if err = ctx.Err(); err != nil {
			return result, err
		}
		n, readErr := input.Read(buffer)
		result.Bytes += int64(n)
		if result.Bytes > info.Size() {
			return result, errors.New("build tool changed during fingerprinting")
		}
		_, _ = digest.Write(buffer[:n])
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return result, readErr
		}
	}
	after, err := input.Stat()
	if err != nil {
		return result, err
	}
	if result.Bytes != info.Size() || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return result, errors.New("build tool changed during fingerprinting")
	}
	result.SHA256 = hex.EncodeToString(digest.Sum(nil))
	return result, nil
}
