package acceptance_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/native"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
	"github.com/deploymenttheory/go-apfs-v3/inspect"
	"github.com/deploymenttheory/go-apfs-v3/pack"
	"github.com/deploymenttheory/go-apfs-v3/session"
	"github.com/deploymenttheory/go-apfs-v3/workspace"
)

// Every retained image is bound to the actual input seen on its producing
// host. The immutable Apple view still supplies the logical data and untouched
// peers. Host differences never waive same-input plaintext determinism.
func TestObservedHostArchivesSurviveSessionPackingAndImageImports(t *testing.T) {
	cases, _ := loadCorpus(t)
	recipes := recipesByName(t)
	binary := portableCommandBinary(t)
	seen := map[string]bool{}
	for _, k := range cases {
		if k.Recipe != "workspace-edits" || k.Stage != "before" {
			continue
		}
		key := fmt.Sprintf("macos-%d/%s", k.Producer, k.Profile)
		if seen[key] {
			t.Fatal("ambiguous observed host source", key)
		}
		seen[key] = true
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			img, source, closeSource := openSingleVolume(t, ctx, k, recipes[k.Recipe])
			defer closeSource()
			sourcePath := fixtureImage(t, k)
			sourceDigest := packingFileDigest(t, sourcePath)
			if got, bytes := hashReaderAt(img, img.Size()); got != k.Observation.Image.DiskSHA256 || bytes != k.Observation.Image.DiskBytes {
				t.Fatal("host staging source differs from its independent Apple disk observation")
			}
			partition := -1
			for _, p := range img.Partitions {
				if p.Type == diskimage.APFSType || p.Type == diskimage.HFSType {
					if partition != -1 {
						t.Fatal("host source has multiple filesystem partitions")
					}
					partition = p.Index
				}
			}
			if partition == -1 {
				t.Fatal("host source has no filesystem partition")
			}
			host := filepath.Join(t.TempDir(), "HostImport")
			paths := materializeObservedHostInput(t, ctx, host, source, nativeHostImportEntries(t, k.Observation.Views[0]), k.Observation.Views[0])
			input, err := observeHostInputTree(host, caseRef(k), paths)
			if err != nil {
				t.Fatal(err)
			}
			if err := native.ValidateHostInput(input, runtime.GOOS, caseRef(k)); err != nil {
				t.Fatal(err)
			}
			sidecar := writeHostInputSidecar(t, input)
			defer checkObservedHostInputUnchanged(t, host, input, paths)
			defer func() {
				if packingFileDigest(t, sourcePath) != sourceDigest {
					t.Error("host import changed the original native image")
				}
			}()

			policy := schema.HostImportExpectation{Route: "session-pack", Destination: "/HostImport", ClockNS: fixedClock.UnixNano(), UID: hostImportUID, GID: hostImportGID, PreserveLinks: true}
			want, err := native.HostImportView(input, policy, k.Observation.Views[0])
			if err != nil {
				t.Fatal(err)
			}
			scratch := t.TempDir()
			directory := filepath.Join(scratch, "typed")
			current, err := session.Create(ctx, directory, session.Options{Names: source.NameRules(), UID: hostImportUID, GID: hostImportGID, Time: &fixedClock})
			if err != nil {
				t.Fatal(err)
			}
			checkHostImportRefusals(t, ctx, current, host)
			if _, err := current.Copy(ctx, []string{host}, policy.Destination, session.CopyOptions{FromHost: true, Archive: true, PreserveLinks: true}); err != nil {
				closeFixture(t, current)
				t.Fatal(err)
			}
			checkObservedHostReader(t, ctx, current, input, policy, want, true)
			if err := current.Verify(ctx); err != nil {
				t.Fatal(err)
			}
			beforeReport := current.Report()
			if err := current.Close(); err != nil {
				t.Fatal(err)
			}
			current, err = session.Open(ctx, directory)
			if err != nil {
				t.Fatal(err)
			}
			checkObservedHostReader(t, ctx, current, input, policy, want, true)
			afterReport := current.Report()
			if !reflect.DeepEqual(beforeReport, afterReport) {
				t.Fatal("session reopen changed host provenance or logical inventory")
			}
			exported := filepath.Join(t.TempDir(), "workspace")
			if _, err := current.Export(ctx, exported); err != nil {
				t.Fatal(err)
			}
			if err := current.Close(); err != nil {
				t.Fatal(err)
			}
			w, err := workspace.Open(ctx, exported)
			if err != nil {
				t.Fatal(err)
			}
			defer closeFixture(t, w)
			checkObservedHostReader(t, ctx, w, input, policy, want, true)
			workspaceBefore := packingSourceInventory(t, exported)
			packOptions := pack.Options{Format: "UDZO", FileCompression: "preserve", Volume: pack.VolumeOptions{Name: "Host Imports", Capacity: 160 << 20, Time: fixedClock, CaseSensitive: source.NameRules().CaseSensitive}}
			buildName := hostInputOutputPrefix(caseRef(k)) + "build.host-import.UDZO.dmg"
			built := produceSameHostInputTwice(t, buildName, func(destination string) error {
				report, err := pack.Create(ctx, destination, w, packOptions)
				if err == nil {
					checkHostOmissionRecords(t, report.MetadataOmissions, beforeReport.MetadataOmissions, false)
				}
				return err
			})
			if !reflect.DeepEqual(packingSourceInventory(t, exported), workspaceBefore) {
				t.Fatal("packing changed the host preservation workspace")
			}
			checkObservedHostImage(t, ctx, built, input, policy, want)

			// A fresh public CLI session performs the same import, then exports
			// and packs after releasing its process lock. The original API
			// session remains unchanged throughout this independent route.
			cliScratch := t.TempDir()
			createHostImportCLISession(t, binary, cliScratch, k.Profile, host)
			checkHostImportCLIRefusals(t, binary, cliScratch, host)
			cliExport := filepath.Join(t.TempDir(), "cli-workspace")
			runHostImportCommand(t, binary, "session", "export", "--scratch-dir", cliScratch, "host", cliExport)
			cliWorkspace, err := workspace.Open(ctx, cliExport)
			if err != nil {
				t.Fatal(err)
			}
			checkObservedHostReader(t, ctx, cliWorkspace, input, policy, want, true)
			if err := cliWorkspace.Close(); err != nil {
				t.Fatal(err)
			}
			cliBefore := packingSourceInventory(t, filepath.Join(cliScratch, "host"))
			cliBuilt := filepath.Join(t.TempDir(), "cli-pack.dmg")
			var cliPack pack.Report
			if err := json.Unmarshal(runHostImportCommand(t, binary, "pack", "--scratch-dir", cliScratch, "--session", "host", "--volume-name", "Host Imports", "--capacity", "160MiB", "--format", "UDZO", "--time", fixedClock.Format(time.RFC3339), "--json", cliBuilt), &cliPack); err != nil {
				t.Fatal(err)
			}
			checkHostOmissionRecords(t, cliPack.MetadataOmissions, beforeReport.MetadataOmissions, false)
			if packingFileDigest(t, cliBuilt) != packingFileDigest(t, built) || !reflect.DeepEqual(cliBefore, packingSourceInventory(t, filepath.Join(cliScratch, "host"))) {
				t.Fatal("CLI session packing differs from the same independently observed API/workspace input")
			}
			recordOutput(t, schema.Output{Name: buildName, File: filepath.Base(built), Operation: "build", Format: "UDZO", Source: caseRef(k), HostInput: sidecar, Expect: schema.Expectation{HostImport: &policy, Continuation: true}})

			imagePolicy := policy
			imagePolicy.Route, imagePolicy.Destination = "image-copy", "/Fixture/HostImport"
			for _, entry := range k.Observation.Views[0].Entries {
				if entry.Path == "Fixture" {
					imagePolicy.UID, imagePolicy.GID = entry.UID, entry.GID
				}
			}
			imageWant, err := native.HostImportView(input, imagePolicy, k.Observation.Views[0])
			if err != nil {
				t.Fatal(err)
			}
			options := imageedit.Options{Partition: partition, Format: "UDZO", Time: fixedClock}
			checkHostImageRefusals(t, ctx, sourcePath, host, options)
			editName := hostInputOutputPrefix(caseRef(k)) + "edit.host-import.UDZO.dmg"
			edited := produceSameHostInputTwice(t, editName, func(destination string) error {
				report, err := imageedit.Copy(ctx, sourcePath, destination, options, []string{host}, imagePolicy.Destination, imageedit.CopyOptions{FromHost: true, Archive: true, PreserveLinks: true})
				if err == nil {
					checkHostOmissionRecords(t, report.MetadataOmissions, beforeReport.MetadataOmissions, true)
				}
				return err
			})
			cliEdited := filepath.Join(t.TempDir(), "cli-edit.dmg")
			var cliCopy imageedit.CopyReport
			if err := json.Unmarshal(runHostImportCommand(t, binary, "cp", "--image", sourcePath, "--partition", fmt.Sprint(partition), "--output", cliEdited, "--format", "UDZO", "--time", fixedClock.Format(time.RFC3339), "--from-host", "-a", "--preserve-links", "--json", host, imagePolicy.Destination), &cliCopy); err != nil {
				t.Fatal(err)
			}
			checkHostOmissionRecords(t, cliCopy.MetadataOmissions, beforeReport.MetadataOmissions, true)
			if packingFileDigest(t, edited) != packingFileDigest(t, cliEdited) {
				t.Fatal("typed and public CLI imports differ for the same original host input")
			}
			if data, err := exec.Command(binary, "cp", "--image", sourcePath, "--partition", fmt.Sprint(partition), "--output", cliEdited, "--format", "UDZO", "--time", fixedClock.Format(time.RFC3339), "--from-host", "-a", "--preserve-links", host, imagePolicy.Destination).CombinedOutput(); err == nil || packingFileDigest(t, edited) != packingFileDigest(t, cliEdited) {
				t.Fatal("public CLI import overwrote an occupied output", err, string(data))
			}
			checkObservedHostImage(t, ctx, edited, input, imagePolicy, imageWant)
			recordOutput(t, schema.Output{Name: editName, File: filepath.Base(edited), Operation: "edit", Format: "UDZO", Source: caseRef(k), HostInput: sidecar, Expect: schema.Expectation{HostImport: &imagePolicy, Continuation: true}})
		})
	}
	for _, producer := range schema.Producers {
		for _, profile := range []string{"apfs", "apfsx", "hfsplus", "hfsx"} {
			if !seen[fmt.Sprintf("macos-%d/%s", producer, profile)] {
				t.Fatalf("missing independently observed host archive source macOS %d/%s", producer, profile)
			}
		}
	}
}

func runHostImportCommand(t *testing.T, binary string, args ...string) []byte {
	t.Helper()
	data, err := exec.Command(binary, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("public host archive command %v: %v: %s", args, err, data)
	}
	return data
}

func createHostImportCLISession(t *testing.T, binary, scratch, profile, host string) {
	t.Helper()
	format := profile
	if profile == "apfsx" {
		format = "apfs"
	}
	create := []string{"session", "create", "--scratch-dir", scratch, "--filesystem", format, "--uid", fmt.Sprint(hostImportUID), "--gid", fmt.Sprint(hostImportGID), "--time", fixedClock.Format(time.RFC3339)}
	if profile == "apfsx" {
		create = append(create, "--case-sensitive")
	}
	runHostImportCommand(t, binary, append(create, "host")...)
	runHostImportCommand(t, binary, "cp", "--scratch-dir", scratch, "--session", "host", "--from-host", "-a", "--preserve-links", "--json", host, "/HostImport")
	runHostImportCommand(t, binary, "session", "verify", "--scratch-dir", scratch, "host")
}

func checkHostImportCLIRefusals(t *testing.T, binary, scratch, host string) {
	t.Helper()
	directory := filepath.Join(scratch, "host")
	before := packingSourceInventory(t, directory)
	for _, operands := range [][]string{
		{"--from-host", "-a", "--preserve-links", filepath.Join(host, "observed"), filepath.Join(host, "missing"), "/HostImport/metadata-dir"},
		{"--from-host", "-a", "-n", filepath.Join(host, "observed"), "/HostImport/observed"},
	} {
		args := append([]string{"cp", "--scratch-dir", scratch, "--session", "host", "--json"}, operands...)
		if data, err := exec.Command(binary, args...).CombinedOutput(); err == nil {
			t.Fatal("public CLI refused host import unexpectedly succeeded", args, string(data))
		}
		if !reflect.DeepEqual(before, packingSourceInventory(t, directory)) {
			t.Fatal("failed public CLI import changed persisted session bytes or revision")
		}
	}
	runHostImportCommand(t, binary, "session", "verify", "--scratch-dir", scratch, "host")
}

// Host-specific inputs remove the cross-host repeat substitution used by
// ordinary producers. These two same-input runs remain mandatory in CI.
func produceSameHostInputTwice(t *testing.T, name string, produce func(string) error) string {
	t.Helper()
	first := filepath.Join(outputDir(t), name)
	second := filepath.Join(t.TempDir(), name)
	if err := produce(first); err != nil {
		t.Fatal(err)
	}
	if err := produce(second); err != nil {
		t.Fatal(err)
	}
	if packingFileDigest(t, first) != packingFileDigest(t, second) {
		t.Fatal("same-host repeated import/pack changed plaintext bytes for an unchanged independently observed input")
	}
	return first
}

func checkHostImportRefusals(t *testing.T, ctx context.Context, current *session.Session, host string) {
	t.Helper()
	before := current.Report()
	for _, options := range []session.CopyOptions{{FromHost: true}, {FromHost: true, Archive: true, PreserveLinks: true}} {
		sources := []string{host}
		if options.Archive {
			sources = []string{filepath.Join(host, "observed"), filepath.Join(host, "missing")}
		}
		if _, err := current.Copy(ctx, sources, "/", options); err == nil {
			t.Fatal("refused/interrupted host copy succeeded")
		}
		if !reflect.DeepEqual(current.Report(), before) {
			t.Fatal("failed host import published a partial session revision or provenance")
		}
		if err := current.Verify(ctx); err != nil {
			t.Fatal(err)
		}
	}
}

func checkHostImageRefusals(t *testing.T, ctx context.Context, source, host string, options imageedit.Options) {
	t.Helper()
	missing := filepath.Join(t.TempDir(), "interrupted.dmg")
	report, err := imageedit.Copy(ctx, source, missing, options, []string{filepath.Join(host, "observed"), filepath.Join(host, "missing")}, "/Fixture", imageedit.CopyOptions{FromHost: true, Archive: true, PreserveLinks: true})
	if err == nil || len(report.MetadataOmissions) != 0 {
		t.Fatal("failed image import published successful host provenance", err, report.MetadataOmissions)
	}
	if _, err := os.Lstat(missing); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("failed image import left a published output", err)
	}
	occupied := filepath.Join(t.TempDir(), "occupied.dmg")
	if err := os.WriteFile(occupied, []byte("original occupied destination"), 0600); err != nil {
		t.Fatal(err)
	}
	want := packingFileDigest(t, occupied)
	if _, err := imageedit.Copy(ctx, source, occupied, options, []string{host}, "/Fixture/HostImport", imageedit.CopyOptions{FromHost: true, Archive: true, PreserveLinks: true}); err == nil || packingFileDigest(t, occupied) != want {
		t.Fatal("host import overwrote an occupied published output", err)
	}
}

func checkObservedHostReader(t *testing.T, ctx context.Context, reader filesystem.Reader, input schema.HostInputInventory, policy schema.HostImportExpectation, want schema.View, logical bool) {
	t.Helper()
	imported := strings.TrimPrefix(policy.Destination, "/")
	compareViewWith(t, ctx, "independently observed host archive", reader, want, compareOptions{ignoreIDFor: func(p string) bool {
		return policy.Route == "session-pack" || p == imported || strings.HasPrefix(p, imported+"/")
	}})
	forward, reverse := map[string]uint64{}, map[uint64]string{}
	for _, item := range input.Entries {
		p := path.Join(imported, item.Entry.Path)
		id, err := filesystem.LookupExact(ctx, reader, p)
		if err != nil {
			t.Fatal(err)
		}
		if other, ok := forward[item.Identity]; ok && other != id {
			t.Error("import split an independently observed host hard-link identity", p)
		}
		if other, ok := reverse[id]; ok && other != item.Identity {
			t.Error("import merged independently distinct host identities", p)
		}
		forward[item.Identity], reverse[id] = id, item.Identity
		if logical {
			node, err := reader.Stat(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			checkHostNodeProvenance(t, p, node, item, input.Host)
		}
	}
}

func checkHostNodeProvenance(t *testing.T, p string, node filesystem.Node, item schema.HostInputEntry, host string) {
	t.Helper()
	fields := map[string]schema.HostInputField{}
	for _, field := range item.Fields {
		fields[field.Field] = field
	}
	want := map[string]string{}
	switch host {
	case "linux":
		want["bsdFlags"] = "linux-inode-flags/unsupported"
	case "windows":
		want["bsdFlags"] = "windows-file-attributes/unsupported"
		want["mode"] = "windows-file-attributes/unsupported"
		want["uid"], want["gid"] = "windows-security-descriptor/unsupported", "windows-security-descriptor/unsupported"
	}
	if item.Security.State == "unavailable" {
		want["acl"] = item.Security.Format + "/unavailable"
	} else if host != "darwin" && item.Security.State != "absent" {
		want["acl"] = item.Security.Format + "/unsupported"
	}
	unavailable := fields["attributes"].State == "unavailable" || host == "windows" && len(item.NamedStreams) != 0
	if unavailable {
		status := "unavailable"
		if fields["attributes"].State != "unavailable" {
			status = "unsupported"
		}
		want["attributes"] = fields["attributes"].SourceFormat + "/" + status
	}
	got := map[string]string{}
	for _, omitted := range node.MetadataOmissions {
		if omitted.Reason == "" || got[omitted.Field] != "" {
			t.Error(p, "invalid/duplicate host metadata provenance", omitted)
		}
		got[omitted.Field] = omitted.SourceFormat + "/" + string(omitted.Status)
	}
	if !reflect.DeepEqual(want, got) || node.AttributesUnavailable != unavailable {
		t.Errorf("%s: observed host provenance got %v/unavailable=%t; want %v/%t", p, got, node.AttributesUnavailable, want, unavailable)
	}
	var defaults []string
	switch host {
	case "linux":
		defaults = []string{"bsdFlags"}
	case "windows":
		defaults = []string{"bsdFlags", "gid", "mode", "uid"}
	}
	if !slices.Equal(node.MetadataDefaulted, defaults) {
		t.Errorf("%s: missing durable host default policy: got %v, want %v", p, node.MetadataDefaulted, defaults)
	}
}

func checkHostOmissionRecords(t *testing.T, got, want []filesystem.MetadataOmissionRecord, image bool) {
	t.Helper()
	canonical := func(records []filesystem.MetadataOmissionRecord, image bool) []string {
		var result []string
		for _, record := range records {
			if record.Reason == "" || image && (record.Command != 1 || record.ClockNS != fixedClock.UnixNano()) || !image && (record.Command != 0 || record.ClockNS != 0) {
				t.Error("host omission report lost command/provenance binding", record)
			}
			p := record.Path
			if image {
				p = strings.TrimPrefix(p, "/Fixture")
			}
			result = append(result, p+":"+record.Field+":"+record.SourceFormat+":"+string(record.Status))
		}
		sort.Strings(result)
		return result
	}
	if !slices.Equal(canonical(got, image), canonical(want, false)) {
		t.Error("packing/import report differs from durable independently qualified host provenance", got, want)
	}
}

func checkObservedHostImage(t *testing.T, ctx context.Context, filename string, input schema.HostInputInventory, policy schema.HostImportExpectation, want schema.View) {
	t.Helper()
	image, err := diskimage.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFixture(t, image)
	report, err := inspect.Image(ctx, image)
	if err != nil {
		t.Fatal(err)
	}
	var reader filesystem.Reader
	for _, part := range report.Partitions {
		if part.APFS != nil && len(part.APFS.Volumes) == 1 {
			if reader != nil {
				t.Fatal("host image has ambiguous filesystems")
			}
			reader = &part.APFS.Volumes[0]
		} else if part.HFSPlus != nil {
			if reader != nil {
				t.Fatal("host image has ambiguous filesystems")
			}
			reader = part.HFSPlus
		}
	}
	if reader == nil {
		t.Fatal("host import output lacks its filesystem")
	}
	checkObservedHostReader(t, ctx, reader, input, policy, want, false)
}
