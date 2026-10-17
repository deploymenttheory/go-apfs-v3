package main

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"slices"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/receipt"
)

// These programs inspect execution evidence or describe scheduling; they do
// not construct, restore or admit Apple input bytes. Unknown files remain in
// the conservative capture closure. Input resolvers, publication/transport
// code, native helpers and the qualification dispatcher remain bound.
var captureIndependentExecutionFiles = []string{
	"acceptance/qualification/ci_evidence.go",
	"acceptance/qualification/ci_reuse.py",
	"acceptance/qualification/compare_campaigns.py",
	"acceptance/qualification/execution_changes.go",
	"acceptance/qualification/execution_evidence.go",
	"acceptance/qualification/execution_index.go",
	"acceptance/qualification/execution_reuse.py",
	"acceptance/qualification/measure.py",
	"acceptance/qualification/native_evidence.go",
	"acceptance/qualification/native_reuse.py",
	"acceptance/qualification/workflow_evidence.go",
}

// All unlisted jobs remain bound, including capture jobs, reusable capture
// callers and new/unclassified jobs. Existing execution jobs may change their
// batching without invalidating independent Apple inputs. Current-Go HFS
// experiments are always fresh and are not an independent-input dependency.
var captureExecutionJobs = map[string][]string{
	".github/workflows/native.yml":         {"evidence", "references", "replay", "image_building_replay", "readback", "complete", "hfs_reference"},
	".github/workflows/apfs-edit.yml":      {"replay", "readback", "complete"},
	".github/workflows/hfs-edit.yml":       {"replay", "replay_copy", "readback", "complete"},
	".github/workflows/apfs-recovery.yml":  {"replay", "readback", "complete"},
	".github/workflows/hfs-recovery.yml":   {"replay", "readback", "complete"},
	".github/workflows/offline-family.yml": {"replay", "archive", "readback", "qualified"},
	".github/workflows/ci.yml":             {"evidence", "source_checks", "portable", "offline_retained", "portable_acceptance", "build", "race_library", "race_acceptance", "quality"},
}

var nativeProgramInvocation = regexp.MustCompile(`\bpython3?\s+(?:-u\s+)?["']?acceptance/native/([A-Za-z_][A-Za-z_0-9]*)\.py\b`)
var directNativeCaptureCommand = regexp.MustCompile(`\b(?:hdiutil|diskutil|newfs_apfs|newfs_hfs|clang|xcrun)\b`)
var captureJobHeader = regexp.MustCompile(`(?m)^  [^ \t\r\n#][^\r\n]*:`)
var captureYAMLAlias = regexp.MustCompile(`(?:^|[ \t])[&*][A-Za-z_]`)

func invokesNativeCapture(section string) bool {
	if directNativeCaptureCommand.MatchString(section) {
		return true
	}
	for _, match := range nativeProgramInvocation.FindAllStringSubmatch(section, -1) {
		name := match[1]
		if !strings.HasPrefix(name, "verify_") && !slices.Contains([]string{"qualification_complete", "readback_source"}, name) {
			return true
		}
	}
	return false
}

// This is a fingerprint projection, never a rewrite of original YAML or native
// evidence. The source audit still binds every complete workflow byte. Keep
// workflow-level inputs/env and every capture, caller or unknown job; omit only
// classified execution jobs that contain no native capture invocation.
func captureWorkflowProjection(name string, data []byte) (receipt.File, bool) {
	ignored, known := captureExecutionJobs[name]
	if !known {
		return receipt.File{}, false
	}
	body := string(data)
	_, jobs, found := strings.Cut(body, "\njobs:\n")
	if !found {
		return receipt.File{}, false // An unknown layout retains the whole file.
	}
	header := body[:len(body)-len(jobs)]
	matches := jobPattern.FindAllStringSubmatchIndex(jobs, -1)
	if len(matches) == 0 || len(matches) != len(captureJobHeader.FindAllStringIndex(jobs, -1)) || captureYAMLAlias.MatchString(body) {
		return receipt.File{}, false
	}
	for _, line := range strings.Split(jobs, "\n") {
		if strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "#") {
			return receipt.File{}, false // Global keys after jobs need a full-file binding.
		}
	}
	var projected strings.Builder
	projected.WriteString(header)
	for index, match := range matches {
		end := len(jobs)
		if index+1 < len(matches) {
			end = matches[index+1][0]
		}
		job, section := jobs[match[2]:match[3]], jobs[match[0]:end]
		currentGo := name == ".github/workflows/native.yml" && job == "hfs_reference"
		if slices.Contains(ignored, job) && (currentGo || !invokesNativeCapture(section)) {
			continue
		}
		projected.WriteString(section)
	}
	value := projected.String()
	sum := sha256.Sum256([]byte(value))
	return receipt.File{Path: "capture-workflow/" + name, Bytes: int64(len(value)), SHA256: hex.EncodeToString(sum[:])}, true
}
