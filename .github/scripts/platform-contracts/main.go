// Command platform-contracts validates retained test events before dependent
// acceptance work. It neither runs native tools nor imports a filesystem reader.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
)

const module = "github.com/deploymenttheory/go-apfs-v3/acceptance/"

// These are execution obligations, not a selection of tests to run. CI still
// runs every untagged helper test, including newly added packages and tests.
var helperContracts = map[string][]string{
	module + "fixture": {
		"TestCapturedEvidenceSurvivesGitCheckoutFiltersWithoutByteConversion",
		"TestNativePlatformOriginalsRetainCompleteIndependentScopesAndAdapterFailures",
		"TestNativePlatformReplayBindsOriginalPathsAliasesForeignImagesAndPostDetachFacts",
		"TestNativePlatformReplayProjectsOnlyAdditionalOwnerPathsActuallyCaptured",
		"TestOwnershipFixtureProjectsWindowsPathsBeforeFormingNativeFileURLs",
		"TestMacOSImageParsingIsIndependentOfHostPathSyntax",
		"TestImageIdentityResolvesCompleteNativeAndHostPathsThroughOneExplicitBoundary",
		"TestImageIdentityOrdinaryFileResolutionPreservesCanonicalPathsAndErrors",
		"TestImageIdentityResolutionFailureKeepsCancellationAndPreventsDetach",
		"TestForeignAttachmentCleanupDoesNotClaimRelease",
		"TestCapturedLiveImageWithAStaleDeviceCannotBeReportedReleased",
		"TestFrameworkImageAtAnotherDeviceCannotBeReportedReleased",
		"TestBusyDetachRetainsItsFailureWhenLaterOwnershipProofRefusesCleanup",
		"TestKernelOwnershipStatesReplayCompleteCapturedPlatformResults",
		"TestUnknownAttachmentRefusesCleanupAndPreservesProofFailure",
		"TestSuccessfulEmptyScopedQueriesRequireAnIndependentCompleteMediaProof",
		"TestDetachLeavesReassignedDeviceUntouchedOnFirstCall",
		"TestAttachFailureClosesOnlyItsOwnedImageAndRetainsTheFailure",
		"TestDetachStopsIfItsOwnerProbeIsCancelled",
		"TestCaptureFailureReceiptIncludesEarlyFormatAndDeferredCleanup",
		"TestCaptureFailureReceiptWriteErrorPreservesThePrimaryCause",
		"TestCaptureFailurePreservesDeferredCleanupCause",
		"TestVolumeObservationFailurePreservesUnmountCause",
		"TestJournalReplayFailurePreservesGuardedCleanupCause",
		"TestASRCleanupRefusalIsFatalWithoutForcedCommandsOrAnotherAttempt",
		"TestASRSourceAndTargetCleanupCausesAreRetainedWithoutAnotherAttempt",
		"TestNativeOwnershipEvidenceCollectsEveryScopeWithoutInterpretingResults",
		"TestNativeOwnershipEvidenceReturnsUnchangedResultsAndReportsRetentionFailures",
		"TestNativeOwnershipEvidenceBoundsRetainedBytesWithoutInventingFullRetention",
	},
	module + "native": {
		"TestNativeBlockReadPreservesGuardedCleanupOnSuccessAndFailure",
		"TestNativeReadAndCheckerFailuresPreserveCleanupCause",
		"TestFinalNativeWritePreservesWriteUnmountAndDetachCauses",
		"TestTrackedLimitJoinedWithCleanupFailureRetainsFailureEvidence",
		"TestTrackedLimitPolicyRejectsJoinedCleanupAndCancellation",
		"TestSectorPreservingVerificationFailureRetainsNativeOwnershipEvidence",
		"TestVerificationRetainsEarlyNativeFailureAndJoinsDiagnosticIOError",
		"TestObservationFailureWithoutObservationRetainsPhaseAndContinuationCommands",
	},
	module + "corpus": {},
	module + "schema": {},
}

var liveContracts = map[string][]string{
	module + "fixture": {"TestKernelOwnershipMatchesNativeImagePaths"},
}

func init() {
	// These captured platform cases are individually required, so deleting or
	// skipping a host case cannot be hidden by a successful parent test.
	for _, name := range []string{
		"TestNativePlatformOriginalsRetainCompleteIndependentScopesAndAdapterFailures",
		"TestNativePlatformReplayBindsOriginalPathsAliasesForeignImagesAndPostDetachFacts",
		"TestCapturedLiveImageWithAStaleDeviceCannotBeReportedReleased",
		"TestKernelOwnershipStatesReplayCompleteCapturedPlatformResults",
	} {
		for _, major := range []string{"15", "26", "27"} {
			helperContracts[module+"fixture"] = append(helperContracts[module+"fixture"], name+"/"+major)
		}
	}
}

type provenance struct {
	Commit, RunID, RunAttempt, GOOS, GOARCH, GoVersion string
}

type fileEvidence struct {
	File   string
	Bytes  int
	SHA256 string
}

type receipt struct {
	Schema int
	provenance
	TestExit  int
	Events    fileEvidence
	Contracts map[string][]string
	Native    *fileEvidence `json:",omitempty"`
	Error     string        `json:",omitempty"`
}

type options struct {
	events, output, native string
	testExit, major        int
}

func main() {
	var opts options
	flag.StringVar(&opts.events, "events", "", "original go test -json output")
	flag.StringVar(&opts.output, "receipt", "", "validation receipt to retain even on failure")
	flag.IntVar(&opts.testExit, "test-exit", -1, "actual test command exit status")
	flag.StringVar(&opts.native, "native-evidence", "", "existing live ownership evidence directory")
	flag.IntVar(&opts.major, "major", 0, "expected native macOS major")
	flag.Parse()
	if err := run(opts); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(opts options) error {
	p, pErr := currentProvenance()
	r := receipt{Schema: 1, provenance: p, TestExit: opts.testExit, Contracts: helperContracts}
	if opts.native != "" {
		r.Contracts = liveContracts
	}
	raw, original, readErr := readEvidence(opts.events, 32<<20)
	r.Events = original
	validationErr := errors.Join(pErr, readErr, validateEvents(raw, opts.testExit, r.Contracts))
	if opts.native != "" {
		packet, packetErr := validateNative(opts.native, opts.major, p)
		r.Native = &packet
		validationErr = errors.Join(validationErr, packetErr)
	} else if opts.major != 0 {
		validationErr = errors.Join(validationErr, errors.New("native major supplied without live evidence"))
	}
	if validationErr != nil {
		r.Error = validationErr.Error()
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err == nil {
		err = os.WriteFile(opts.output, append(data, '\n'), 0o600)
	}
	return errors.Join(validationErr, err)
}

func currentProvenance() (provenance, error) {
	p := provenance{Commit: os.Getenv("GITHUB_SHA"), RunID: os.Getenv("GITHUB_RUN_ID"), RunAttempt: os.Getenv("GITHUB_RUN_ATTEMPT"), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, GoVersion: runtime.Version()}
	head, err := exec.Command("git", "rev-parse", "HEAD").Output()
	// For a pull request GITHUB_SHA is the tested merge checkout, not the PR
	// branch head. Bind this invocation to that actual checkout in either case.
	if err != nil || strings.TrimSpace(string(head)) != p.Commit || !hexDigest(p.Commit, 20) {
		return p, errors.Join(errors.New("contract provenance does not match the actual checkout"), err)
	}
	for _, value := range []string{p.RunID, p.RunAttempt} {
		if n, err := strconv.ParseUint(value, 10, 64); err != nil || n == 0 {
			return p, errors.New("contract provenance requires the current run and attempt")
		}
	}
	return p, nil
}

func evidence(file string, raw []byte) fileEvidence {
	return fileEvidence{File: file, Bytes: len(raw), SHA256: fmt.Sprintf("%x", sha256.Sum256(raw))}
}

func readEvidence(file string, limit int64) ([]byte, fileEvidence, error) {
	raw, err := readBounded(file, limit)
	if err != nil {
		// The original remains on disk for upload. Never label a partial read's
		// size or digest as that of the complete retained file.
		return nil, fileEvidence{File: file}, err
	}
	return raw, evidence(file, raw), nil
}

func readBounded(file string, limit int64) ([]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(f, limit+1))
	if int64(len(raw)) > limit {
		readErr = errors.Join(readErr, fmt.Errorf("contract evidence exceeds %d bytes: %s", limit, file))
	}
	return raw, errors.Join(readErr, f.Close())
}

func hexDigest(value string, size int) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == size
}

func validateEvents(raw []byte, exit int, required map[string][]string) error {
	if exit != 0 {
		return fmt.Errorf("contract test command exited %d", exit)
	}
	type event struct{ Action, Package, Test string }
	type execution struct{ ran, passed, finished bool }
	tests := map[string]execution{}
	packages := map[string]bool{}
	observedPackages := map[string]bool{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	for {
		var item event
		if err := decoder.Decode(&item); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("decode complete contract events: %w", err)
		}
		if item.Package == "" || item.Action == "" {
			return errors.New("contract event lacks a package or action")
		}
		observedPackages[item.Package] = true
		if item.Action == "fail" || item.Action == "build-fail" {
			return fmt.Errorf("contract test failure: %s %s", item.Package, item.Test)
		}
		if item.Test == "" {
			if item.Action == "pass" {
				if packages[item.Package] {
					return fmt.Errorf("duplicate contract package result: %s", item.Package)
				}
				packages[item.Package] = true
			}
			continue
		}
		key := item.Package + "/" + item.Test
		state := tests[key]
		switch item.Action {
		case "run":
			if state.ran || state.passed {
				return fmt.Errorf("duplicate contract execution: %s", key)
			}
			state.ran = true
		case "pass":
			if !state.ran || state.finished {
				return fmt.Errorf("contract pass without one execution: %s", key)
			}
			state.passed = true
			state.finished = true
		case "skip":
			if slices.ContainsFunc(required[item.Package], func(name string) bool { return item.Test == name || strings.HasPrefix(item.Test, name+"/") }) {
				return fmt.Errorf("required contract was skipped: %s", key)
			}
			state.finished = true
		}
		tests[key] = state
	}
	for pkg := range observedPackages {
		if !packages[pkg] {
			return fmt.Errorf("observed contract package has no successful terminal result: %s", pkg)
		}
	}
	for name, state := range tests {
		if state.ran && !state.finished {
			return fmt.Errorf("contract execution has no terminal result: %s", name)
		}
	}
	for pkg, names := range required {
		if !packages[pkg] {
			return fmt.Errorf("contract package has no successful terminal result: %s", pkg)
		}
		for _, name := range names {
			if !tests[pkg+"/"+name].passed {
				return fmt.Errorf("required contract did not execute and pass: %s/%s", pkg, name)
			}
		}
	}
	return nil
}

type nativePacket struct {
	Schema                                 int
	Commit, RunID, RunAttempt              string
	KernelVersion, OSBuild, Architecture   string
	ContractError, RetentionError          string
	ToolsSHA256, RawSHA256, SymlinkAliases map[string]string
	RawBytes                               int64
	Claims                                 []nativeClaim
	CommandResults                         []nativeCommand
}

type nativeClaim struct {
	Kind, Image, Device, ExpectedState, State, Error string
	ExpectedOwned, Owned                             bool
}

type nativeCommand struct {
	Sequence int
	Argv     []string
	Status   int
	Error    string
	Stdout   nativeStream
	Stderr   nativeStream
}

type nativeStream struct {
	File, SHA256, StoredSHA256, RetentionError string
	Bytes, StoredBytes                         int
}

func validateNative(root string, major int, p provenance) (fileEvidence, error) {
	var files []string
	err := filepath.WalkDir(root, func(file string, entry os.DirEntry, err error) error {
		if err == nil && entry.Name() == "ownership-evidence.json" && entry.Type().IsRegular() {
			files = append(files, file)
		}
		return err
	})
	if err != nil || len(files) != 1 {
		return fileEvidence{}, errors.Join(fmt.Errorf("require exactly one original native contract packet, found %d", len(files)), err)
	}
	raw, proof, err := readEvidence(files[0], 64<<20)
	if err != nil {
		return proof, err
	}
	var packet nativePacket
	if err := json.Unmarshal(raw, &packet); err != nil {
		return proof, fmt.Errorf("decode original native contract packet: %w", err)
	}
	return proof, validateNativePacket(packet, filepath.Dir(files[0]), major, p)
}

func validateNativePacket(packet nativePacket, dir string, major int, p provenance) error {
	actual, err := strconv.Atoi(strings.SplitN(packet.KernelVersion, ".", 2)[0])
	if p.GOOS != "darwin" || major <= 0 || err != nil || actual != major || packet.OSBuild == "" || packet.Architecture != p.GOARCH || packet.Schema != 2 || packet.Commit != p.Commit || packet.RunID != p.RunID || packet.RunAttempt != p.RunAttempt {
		return errors.New("native contract platform/provenance differs from this checkout and invocation")
	}
	if packet.ContractError != "" || packet.RetentionError != "" {
		return fmt.Errorf("native contract or retention failed: %s %s", packet.ContractError, packet.RetentionError)
	}
	if len(packet.RawSHA256) != 2 || packet.RawBytes != 2<<20 || len(packet.SymlinkAliases) != 1 || len(packet.ToolsSHA256) != 2 {
		return errors.New("native contract lacks its complete image/alias/tool inventory")
	}
	for _, tool := range []string{"/usr/bin/hdiutil", "/usr/sbin/ioreg"} {
		if !hexDigest(packet.ToolsSHA256[tool], 32) {
			return fmt.Errorf("native tool digest missing: %s", tool)
		}
	}
	for _, digest := range packet.RawSHA256 {
		if !hexDigest(digest, 32) {
			return errors.New("native image digest malformed")
		}
	}
	expected := map[string]string{"positive-first": "owned", "positive-second": "owned", "positive-symlink-alias": "owned", "crossed-1": "foreign", "crossed-2": "foreign", "post-detach-first": "absent", "post-detach-second": "absent"}
	claims := map[string]nativeClaim{}
	if len(packet.Claims) != len(expected) {
		return errors.New("native contract claim inventory incomplete")
	}
	for _, claim := range packet.Claims {
		state, ok := expected[claim.Kind]
		if !ok || claim.State != state || claim.ExpectedState != state || claim.Error != "" || claim.Image == "" || claim.Device == "" || claim.Owned != (state == "owned") || claim.ExpectedOwned != claim.Owned {
			return fmt.Errorf("native contract claim is missing, duplicated or unqualified: %s", claim.Kind)
		}
		delete(expected, claim.Kind)
		claims[claim.Kind] = claim
	}
	first, second := claims["positive-first"], claims["positive-second"]
	if first.Image == second.Image || first.Device == second.Device || packet.RawSHA256[first.Image] == "" || packet.RawSHA256[second.Image] == "" {
		return errors.New("native contract does not distinguish the two original images and devices")
	}
	for kind, want := range map[string]nativeClaim{
		"crossed-1": {Image: first.Image, Device: second.Device}, "crossed-2": {Image: second.Image, Device: first.Device},
		"post-detach-first": first, "post-detach-second": second,
	} {
		if got := claims[kind]; got.Image != want.Image || got.Device != want.Device {
			return fmt.Errorf("native contract image/device relation changed: %s", kind)
		}
	}
	alias := claims["positive-symlink-alias"]
	if alias.Device != first.Device || alias.Image == first.Image || packet.SymlinkAliases[alias.Image] != first.Image {
		return errors.New("native contract alias does not bind the original first image")
	}
	if len(packet.CommandResults) == 0 {
		return errors.New("native contract has no original command streams")
	}
	seen := map[string]bool{}
	for i, command := range packet.CommandResults {
		if command.Sequence != i || len(command.Argv) == 0 || command.Status != 0 || command.Error != "" {
			return errors.New("native contract command inventory incomplete")
		}
		for _, stream := range []nativeStream{command.Stdout, command.Stderr} {
			if !filepath.IsLocal(stream.File) || seen[stream.File] || stream.RetentionError != "" || stream.Bytes < 0 || stream.Bytes != stream.StoredBytes || stream.SHA256 != stream.StoredSHA256 || !hexDigest(stream.SHA256, 32) {
				return errors.New("native command stream retention incomplete")
			}
			seen[stream.File] = true
			raw, err := readBounded(filepath.Join(dir, stream.File), 8<<20)
			if err != nil || len(raw) != stream.Bytes || evidence(stream.File, raw).SHA256 != stream.SHA256 {
				return errors.Join(fmt.Errorf("original native command stream changed: %s", stream.File), err)
			}
		}
	}
	return nil
}
