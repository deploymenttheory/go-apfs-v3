package main

import (
	"context"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/corpus"
)

func workflowJobSection(t *testing.T, workflow, job string) string {
	t.Helper()
	start := strings.Index(workflow, "\n  "+job+":\n")
	if start < 0 {
		t.Fatal("required workflow job missing", job)
	}
	section := workflow[start+1:]
	matches := jobPattern.FindAllStringIndex(section, -1)
	if len(matches) > 1 {
		section = section[:matches[1][0]]
	}
	return section
}

func workflowReplayCommand(t *testing.T, section, marker string) testCommand {
	t.Helper()
	for _, line := range strings.Split(section, "\n") {
		_, args, found := strings.Cut(line, "run: go run ./acceptance/qualification -replay -- ")
		if !found || !strings.Contains(args, marker) {
			continue
		}
		fields := strings.Fields(args)
		for index := range fields {
			fields[index] = strings.Trim(fields[index], "'")
		}
		command, err := parseTestCommand(fields)
		if err != nil {
			t.Fatal(err)
		}
		return command
	}
	t.Fatal("required original replay command missing", marker)
	return testCommand{}
}

func TestMatchedHFSConstructionKeepsEveryHostAndSourceWithoutBlockingReaders(t *testing.T) {
	const root = "../.."
	data, err := regularFile(root, ".github/workflows/native.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(data)
	reader := workflowJobSection(t, workflow, "replay")
	construction := workflowJobSection(t, workflow, "image_building_replay")
	if strings.Contains(reader, "hfs_reference") || strings.Contains(reader, "hfs-header-growth-*") || strings.Contains(reader, "APFS_NATIVE_HFS_GROWTH:") {
		t.Fatal("general readers still wait for unrelated current-Go HFS construction")
	}
	if !strings.Contains(construction, "needs: [evidence, produce, hfs_reference]") || !strings.Contains(construction, "pattern: hfs-header-growth-*") || !strings.Contains(construction, "merge-multiple: true") {
		t.Fatal("matched HFS construction lost its current three-source inputs")
	}
	data, err = regularFile(root, "acceptance/qualification/registry.json")
	var registry registry
	if err != nil || corpus.StrictJSON(data, &registry) != nil {
		t.Fatal("coverage registry missing", err)
	}
	familyIndex := slices.IndexFunc(registry.Families, func(f family) bool { return f.ID == "matched-hfs-header-growth" })
	if familyIndex < 0 {
		t.Fatal("matched HFS obligations missing")
	}
	family := registry.Families[familyIndex]
	contract, err := readReplayContract(root, registry)
	if err != nil {
		t.Fatal(err)
	}
	specIndex := slices.IndexFunc(contract.Tests, func(s replayTest) bool { return s.Test == "TestNativeHFSCatalogGrowth" })
	if specIndex < 0 {
		t.Fatal("matched HFS case recipe missing")
	}
	spec := contract.Tests[specIndex]
	t.Setenv("APFS_NATIVE_HFS_GROWTH", "")
	inputs, err := admitReplayInputs(context.Background(), root, "acceptance/qualification/corpus.json", "", "", registry, contract, []replayTest{spec})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = inputs.close() }()
	cases, _, err := replayCases(spec, family.ID, inputs)
	if err != nil || len(cases) == 0 {
		t.Fatal("original HFS case inventory missing", err)
	}
	majorMatch := regexp.MustCompile(`(?m)^        major: \[([^\]]+)\]$`).FindStringSubmatch(construction)
	if len(majorMatch) != 2 {
		t.Fatal("explicit construction source matrix missing")
	}
	var majors []int
	for _, value := range strings.Split(majorMatch[1], ",") {
		major, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			t.Fatal(err)
		}
		majors = append(majors, major)
	}
	if !slices.Equal(majors, family.FreshSources) {
		t.Fatal("construction changed the original source versions", majors)
	}
	platforms := map[string]string{"Linux": "linux", "Windows": "windows", "macOS": "darwin"}
	if !strings.Contains(construction, "platform: [Linux, Windows, macOS]") || len(family.PortableHosts) != len(platforms) {
		t.Fatal("construction changed the original host matrix")
	}
	readerCommand := workflowReplayCommand(t, reader, "-skip")
	for _, platform := range []string{"Linux", "Windows", "macOS"} {
		host := platforms[platform]
		if !slices.Contains(family.PortableHosts, host) {
			t.Fatal("unplanned portable host", host)
		}
		seen := map[string]int{}
		for _, major := range majors {
			section := strings.ReplaceAll(construction, "${{ matrix.major }}", strconv.Itoa(major))
			command := workflowReplayCommand(t, section, "^TestNativeHFSCatalogGrowth$")
			if command.race || !strings.Contains(strings.Join(command.args, " "), "-timeout 6m") || !strings.Contains(strings.Join(command.args, " "), "-parallel 2") {
				t.Fatal("matched HFS instrumentation or bounds changed")
			}
			for _, c := range cases {
				if !readerCommand.skip.Match(c.Test, false) {
					t.Fatal("construction still repeats in the general reader job", c.Test)
				}
				if command.run.Match(c.Test, false) && !command.skip.Match(c.Test, false) {
					seen[c.Test]++
				}
			}
		}
		for _, c := range cases {
			if seen[c.Test] != 1 {
				t.Fatal("original HFS case lost or repeated", host, c.Test, seen[c.Test])
			}
		}
	}
}
