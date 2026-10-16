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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/corpus"
	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/receipt"
	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/replay"
)

type replayOptions struct {
	root, registry, catalog, bundles, directory string
	args                                        []string
}

type replayLog struct {
	mutex  sync.Mutex
	writer io.Writer
}

func (w *replayLog) Write(data []byte) (int, error) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	return w.writer.Write(data)
}

type testCommand struct {
	args      []string
	run, skip receipt.Selector
	race      bool
}

func parseTestCommand(args []string) (testCommand, error) {
	command := testCommand{args: []string{"test", "-json", "-count=1"}}
	run, skip := ".", ""
	packages := 0
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if !strings.HasPrefix(argument, "-") {
			if argument != "./acceptance" && argument != "./..." && argument != receipt.AcceptancePackage {
				return command, fmt.Errorf("unsupported replay package: %s", argument)
			}
			packages++
			command.args = append(command.args, argument)
			continue
		}
		flag, value, assigned := strings.Cut(argument, "=")
		if flag == "-v" || flag == "-race" {
			if assigned {
				return command, errors.New("boolean replay flags must be explicit switches")
			}
			command.race = command.race || flag == "-race"
			command.args = append(command.args, flag)
			continue
		}
		if !slices.Contains([]string{"-run", "-skip", "-count", "-timeout", "-parallel", "-p"}, flag) {
			return command, fmt.Errorf("unsupported replay flag: %s", flag)
		}
		if !assigned {
			index++
			if index >= len(args) {
				return command, errors.New("missing replay flag value")
			}
			value = args[index]
		}
		switch flag {
		case "-count":
			if value != "1" {
				return command, errors.New("qualification requires fresh assertions with -count=1")
			}
			continue
		case "-run":
			run = value
		case "-skip":
			skip = value
		case "-timeout":
			duration, err := time.ParseDuration(value)
			if err != nil || duration <= 0 || duration > 30*time.Minute {
				return command, errors.New("replay timeout must be bounded to thirty minutes")
			}
		case "-parallel", "-p":
			n, err := strconv.Atoi(value)
			if err != nil || n < 1 || n > 64 {
				return command, errors.New("invalid replay concurrency bound")
			}
		}
		command.args = append(command.args, flag, value)
	}
	if packages != 1 {
		return command, errors.New("replay requires exactly one acceptance-containing package selector")
	}
	var err error
	command.run, err = receipt.ParseSelector(run)
	if err != nil {
		return command, err
	}
	if skip != "" {
		command.skip, err = receipt.ParseSelector(skip)
	}
	return command, err
}

func commandText(ctx context.Context, root string, args ...string) (string, error) {
	command := exec.CommandContext(ctx, args[0], args[1:]...)
	command.Dir = root
	data, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("execution identity %s: %w", args[0], err)
	}
	if len(data) > 1<<20 {
		return "", errors.New("execution identity exceeds bound")
	}
	return strings.TrimSpace(string(data)), nil
}

func executionEnvironment(ctx context.Context, root string, command testCommand) (receipt.Environment, error) {
	environment := receipt.Environment{OS: runtime.GOOS, Architecture: runtime.GOARCH, Race: command.race, Flags: slices.Clone(command.args), Tools: []receipt.File{}}
	toolchain, err := commandText(ctx, root, "go", "version")
	if err != nil {
		return environment, err
	}
	environment.Toolchain = toolchain
	build, err := commandText(ctx, root, "go", "env", "GOOS", "GOARCH", "CGO_ENABLED", "GOFLAGS", "GOTOOLCHAIN")
	if err != nil {
		return environment, err
	}
	environment.Flags = append(environment.Flags, "go-environment="+build, "required-native-majors="+os.Getenv("APFS_REQUIRED_NATIVE_MAJORS"), "required-controls="+os.Getenv("APFS_REQUIRED_CONTROLS"))
	switch runtime.GOOS {
	case "darwin":
		environment.Version, err = commandText(ctx, root, "sw_vers", "-productVersion")
		if err == nil {
			environment.Build, err = commandText(ctx, root, "sw_vers", "-buildVersion")
		}
	case "linux":
		environment.Version, err = commandText(ctx, root, "uname", "-r")
		if err == nil {
			environment.Build, err = commandText(ctx, root, "uname", "-v")
		}
	case "windows":
		environment.Version, err = commandText(ctx, root, "cmd.exe", "/d", "/c", "ver")
		environment.Build = environment.Version
	default:
		err = errors.New("unsupported replay host")
	}
	return environment, err
}

func sourceIdentities(ctx context.Context, root string) (string, string, error) {
	// Tracked and untracked source inputs are both included. Assertions are
	// executed from the actual tree, never certified using a commit label alone.
	command := exec.CommandContext(ctx, "git", "ls-files", "--cached", "--others", "--exclude-standard", "-z")
	command.Dir = root
	data, err := command.Output()
	if err != nil {
		return "", "", err
	}
	paths := strings.Split(strings.TrimSuffix(string(data), "\x00"), "\x00")
	slices.Sort(paths)
	var production, contract []receipt.File
	for _, name := range paths {
		if strings.HasPrefix(name, ".github/") || strings.HasPrefix(name, "docs/") || strings.HasPrefix(name, "acceptance/testdata/") || strings.HasSuffix(name, ".md") || name == "AGENTS.md" {
			continue
		}
		harness := strings.HasPrefix(name, "acceptance/") || strings.HasPrefix(name, "internal/qualification/")
		if !harness && name != "go.mod" && name != "go.sum" && !slices.Contains([]string{".go", ".s", ".S", ".c", ".h", ".syso"}, filepath.Ext(name)) {
			continue
		}
		if strings.HasSuffix(name, "_test.go") && !harness {
			continue
		}
		if harness && (!strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, ".json") || name == "acceptance/qualification/corpus.json" || strings.HasPrefix(name, "acceptance/native/")) {
			continue
		}
		if strings.HasSuffix(name, ".go") {
			source, err := regularFile(root, name)
			if err != nil {
				return "", "", err
			}
			for line := range strings.SplitSeq(string(source), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "//go:embed ") || strings.HasPrefix(line, "#cgo ") {
					return "", "", errors.New("embedded or external build inputs require an explicit qualification identity contract")
				}
			}
		}
		file, err := digestFile(ctx, root, name)
		if err != nil {
			return "", "", err
		}
		if harness {
			contract = append(contract, file)
		} else {
			production = append(production, file)
		}
	}
	if len(production) == 0 || len(contract) == 0 {
		return "", "", errors.New("source identity inputs missing")
	}
	p, err := receipt.Digest(production)
	if err != nil {
		return "", "", err
	}
	c, err := receipt.Digest(contract)
	return p, c, err
}

func digestFile(ctx context.Context, root, name string) (receipt.File, error) {
	result := receipt.File{Path: filepath.ToSlash(name)}
	if !corpus.PortablePath(result.Path) {
		return result, fmt.Errorf("unsafe evidence file path: %s", name)
	}
	inputRoot, err := os.OpenRoot(root)
	if err != nil {
		return result, err
	}
	defer func() { _ = inputRoot.Close() }()
	info, err := inputRoot.Lstat(name)
	if err != nil {
		return result, err
	}
	if !info.Mode().IsRegular() {
		return result, fmt.Errorf("evidence file is not regular: %s", name)
	}
	input, err := inputRoot.Open(name)
	if err != nil {
		return result, err
	}
	defer func() { _ = input.Close() }()
	hash := sha256.New()
	buffer := make([]byte, 64<<10)
	for {
		if err = ctx.Err(); err != nil {
			return result, err
		}
		n, readErr := input.Read(buffer)
		if n > 0 {
			_, _ = hash.Write(buffer[:n])
			result.Bytes += int64(n)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return result, readErr
		}
	}
	if result.Bytes != info.Size() {
		return result, errors.New("evidence changed while hashing")
	}
	result.SHA256 = hex.EncodeToString(hash.Sum(nil))
	return result, nil
}

func newJSON(name string, value any) error {
	file, err := os.CreateTemp(filepath.Dir(name), ".qualification-")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer func() { _ = file.Close(); _ = os.Remove(temporary) }()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err = encoder.Encode(value); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return os.Link(temporary, name)
}

func runReplay(ctx context.Context, options replayOptions, output io.Writer) error {
	// os/exec copies stderr concurrently with streamed stdout events. Serialize
	// both even when the caller supplies a buffer rather than an os.File.
	output = &replayLog{writer: output}
	root, err := filepath.Abs(options.root)
	if err != nil {
		return err
	}
	data, err := regularFile(root, options.registry)
	if err != nil {
		return err
	}
	var r registry
	if err = corpus.StrictJSON(data, &r); err != nil {
		return err
	}
	contract, err := readReplayContract(root, r)
	if err != nil {
		return err
	}
	command, err := parseTestCommand(options.args)
	if err != nil {
		return err
	}
	families := map[string]string{}
	for _, family := range r.Families {
		for _, test := range family.Tests {
			families[test.Name] = family.ID
		}
	}
	var selected []replayTest
	optional := map[string]bool{}
	for _, test := range contract.Tests {
		if !command.run.Match(test.Test, true) || command.skip.Match(test.Test, false) {
			continue
		}
		if test.Layout == "continuation" && os.Getenv(test.Environment) == "" {
			optional[test.Test] = true
			continue
		}
		selected = append(selected, test)
	}
	admitted, err := admitReplayInputs(ctx, root, options.catalog, options.bundles, r, contract, selected)
	if err != nil {
		return err
	}
	defer func() { _ = admitted.close() }()
	controls, err := replay.RequiredControls(os.Getenv("APFS_REQUIRED_CONTROLS"))
	if err != nil {
		return err
	}
	for _, test := range selected {
		inputIndex := slices.IndexFunc(admitted.identities, func(input receipt.Input) bool { return input.ID == test.Input })
		if inputIndex >= 0 && admitted.identities[inputIndex].Use != "retained" {
			for _, control := range test.Controls {
				if !controls[control] {
					return fmt.Errorf("current capture replay requires explicit control: %s", control)
				}
			}
		}
	}
	continuations := map[string]continuationInput{}
	continuedCases := map[string][]receipt.Case{}
	for _, test := range selected {
		if test.Layout != "continuation" {
			continue
		}
		found, _, source, err := continuationCases(ctx, root, test, families[test.Test])
		if err != nil {
			return err
		}
		continuations[test.Test], continuedCases[test.Test] = source, found
		admitted.identities = append(admitted.identities, source.identity)
	}
	slices.SortFunc(admitted.identities, func(a, b receipt.Input) int { return strings.Compare(a.ID, b.ID) })
	directory := options.directory
	if !filepath.IsAbs(directory) {
		directory = filepath.Join(root, directory)
	}
	if err = os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	scratch, err := os.MkdirTemp(directory, "replay-")
	if err != nil {
		return err
	}
	bindingsFile := filepath.Join(scratch, "inputs.json")
	if err = newJSON(bindingsFile, admitted.bindings); err != nil {
		return err
	}
	environment := append([]string{}, os.Environ()...)
	environment = append(environment, "APFS_REPLAY_INPUTS="+bindingsFile)
	outputRoots := map[string]string{}
	for _, test := range selected {
		if test.Output == "" {
			continue
		}
		if _, exists := outputRoots[test.Output]; exists {
			continue
		}
		location := os.Getenv(test.Output)
		if location == "" && test.Layout == "statistics-transitions" {
			continue
		}
		if location == "" {
			location = filepath.Join(scratch, "outputs", test.Output)
		} else if !filepath.IsAbs(location) {
			location = filepath.Join(root, "acceptance", location)
		}
		location, err = filepath.Abs(location)
		if err != nil {
			return err
		}
		for _, input := range admitted.bindings.Bindings {
			if err := separatePaths(input.Path, location); err != nil {
				return err
			}
		}
		for _, input := range continuations {
			if err := separatePaths(input.path, location); err != nil {
				return err
			}
		}
		for _, other := range outputRoots {
			if err := separatePaths(other, location); err != nil {
				return err
			}
		}
		if err = os.MkdirAll(location, 0700); err != nil {
			return err
		}
		outputRoots[test.Output] = location
		environment = append(environment, test.Output+"="+location)
	}
	var cases []receipt.Case
	var declared []string
	for _, test := range selected {
		var found []receipt.Case
		var parents []string
		var caseErr error
		if test.Layout == "continuation" {
			found, parents = continuedCases[test.Test], []string{test.Test}
		} else {
			found, parents, caseErr = replayCases(test, families[test.Test], admitted)
		}
		if caseErr != nil {
			return caseErr
		}
		for _, c := range found {
			if !c.Continuation {
				c.Outputs = expectedCaseOutputs(test, c)
			}
			if command.run.Match(c.Test, false) && !command.skip.Match(c.Test, false) {
				cases = append(cases, c)
			}
		}
		declared = append(declared, parents...)
	}
	slices.SortFunc(cases, func(a, b receipt.Case) int { return strings.Compare(a.Test, b.Test) })
	actualEnvironment, err := executionEnvironment(ctx, root, command)
	if err != nil {
		return err
	}
	production, contractID, err := sourceIdentities(ctx, root)
	if err != nil {
		return err
	}
	plan := receipt.Plan{Schema: receipt.Schema, Stage: "replay", Contract: contractID, Production: production, Inputs: admitted.identities, Outputs: []receipt.File{}, Environment: actualEnvironment, Cases: cases, RequiredRuns: receipt.RequiredRuns(cases, declared)}
	fingerprint, err := plan.Fingerprint()
	if err != nil {
		return err
	}
	revision, err := commandText(ctx, root, "git", "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	origin := receipt.Origin{Revision: revision, Run: "local", Attempt: "1", Job: "local"}
	if run := os.Getenv("GITHUB_RUN_ID"); run != "" {
		origin.Run, origin.Attempt, origin.Job = run, os.Getenv("GITHUB_RUN_ATTEMPT"), os.Getenv("GITHUB_JOB")
		if revision != os.Getenv("GITHUB_SHA") {
			return errors.New("checked-out source differs from workflow revision")
		}
	}
	if err = newJSON(filepath.Join(scratch, "plan.json"), plan); err != nil {
		return err
	}
	eventName := filepath.Join(scratch, "events.jsonl")
	events, err := os.OpenFile(eventName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = events.Close() }()
	processContext, cancel := context.WithCancel(ctx)
	defer cancel()
	process := exec.CommandContext(processContext, "go", command.args...)
	process.Dir = root
	process.Env = environment
	process.Stderr = output
	stdout, err := process.StdoutPipe()
	if err != nil {
		return err
	}
	if err = process.Start(); err != nil {
		return err
	}
	bounded := &io.LimitedReader{R: stdout, N: (512 << 20) + 1}
	verdicts, eventErr := receipt.CheckEvents(io.TeeReader(bounded, events), plan, optional, output)
	if eventErr != nil {
		cancel()
		_ = stdout.Close()
	}
	processErr := process.Wait()
	if bounded.N == 0 {
		eventErr = errors.Join(eventErr, errors.New("test event stream exceeds bound"))
	}
	closeErr := events.Close()
	var sourceErr error
	for _, source := range admitted.resolved {
		sourceErr = errors.Join(sourceErr, source.Verify(ctx))
	}
	for _, source := range continuations {
		sourceErr = errors.Join(sourceErr, source.verify(ctx))
	}
	currentProduction, currentContract, identityErr := sourceIdentities(ctx, root)
	if identityErr != nil || currentProduction != production || currentContract != contractID {
		sourceErr = errors.Join(sourceErr, identityErr, errors.New("source or qualification contract changed during replay"))
	}
	if err = errors.Join(eventErr, processErr, closeErr, sourceErr); err != nil {
		return fmt.Errorf("replay failed; diagnostics retained in %s: %w", scratch, err)
	}
	eventFile, err := digestFile(ctx, scratch, "events.jsonl")
	if err != nil {
		return err
	}
	outputs := []receipt.File{}
	for variable, location := range outputRoots {
		files, err := snapshotFiles(ctx, location)
		if err != nil {
			return err
		}
		for _, file := range files {
			file.Path = variable + "/" + file.Path
			outputs = append(outputs, file)
		}
	}
	slices.SortFunc(outputs, func(a, b receipt.File) int { return strings.Compare(a.Path, b.Path) })
	result := receipt.Receipt{Schema: receipt.Schema, Plan: plan, Fingerprint: fingerprint, Origin: origin, Verdicts: verdicts, Outputs: outputs, Events: eventFile}
	if err = receipt.Complete([]receipt.Expected{{Plan: plan, Origin: origin}}, []receipt.Receipt{result}); err != nil {
		return err
	}
	if err = admitted.close(); err != nil {
		return err
	}
	if err = publishReplayEvidence(ctx, scratch, result, outputRoots, admitted, continuations); err != nil {
		return err
	}
	if err = newJSON(filepath.Join(scratch, "receipt.json"), result); err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "Qualified %d case obligations; execution evidence: %s\n", len(cases), scratch)
	return err
}
