package acceptance_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/native"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/pack"
	"github.com/deploymenttheory/go-apfs-v3/session"
	"github.com/deploymenttheory/go-apfs-v3/workspace"
)

// This ordinary-file control exercises the reader/provenance boundaries without
// resolving or expanding a captured image. The corpus journey separately binds
// logical payloads and untouched peers to Apple observations.
func TestObservedHostMetadataSurvivesReopenedPreservationReaders(t *testing.T) {
	ctx := context.Background()
	binary := portableCommandBinary(t)
	host := filepath.Join(t.TempDir(), "HostImport")
	if err := os.Mkdir(host, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(host, "metadata-dir"), 0755); err != nil {
		t.Fatal(err)
	}
	data := []byte("bounded ordinary-file preservation control\x00\xff")
	for _, name := range []string{"observed", "metadata-dir/value"} {
		if err := os.WriteFile(filepath.Join(host, filepath.FromSlash(name)), data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(filepath.Join(host, "observed"), filepath.Join(host, "observed-alias")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("observed", filepath.Join(host, "link")); err != nil {
		t.Fatal(err)
	}
	if err := configureHostInputMetadata(host); err != nil {
		t.Fatal(err)
	}
	paths := map[string]string{".": "Fixture/tree", "observed": "Fixture/tree/data", "observed-alias": "Fixture/tree/data", "metadata-dir": "Fixture/tree", "metadata-dir/value": "Fixture/tree/data", "link": "Fixture/tree/link"}
	for name := range paths {
		if name != "link" {
			if err := os.Chtimes(filepath.Join(host, filepath.FromSlash(name)), time.Date(2035, 4, 5, 6, 7, 8, 0, time.UTC), fixedClock.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
		}
	}
	value := hostInputValue("", data)
	source := schema.View{Entries: []schema.Entry{{Path: "Fixture", Kind: "dir", Mode: 0755, UID: 501, GID: 20}, {Path: "Fixture/tree", Kind: "dir"}, {Path: "Fixture/tree/data", Kind: "file", Size: value.Bytes, SHA256: value.SHA256}, {Path: "Fixture/tree/link", Kind: "symlink", Target: "6f62736572766564"}}}
	for _, profile := range []string{"apfs", "apfsx", "hfsplus", "hfsx"} {
		t.Run(profile, func(t *testing.T) {
			ref := schema.CaseRef{Producer: 26, Recipe: "workspace-edits", Profile: profile, Stage: "before"}
			input, err := observeHostInputTree(host, ref, paths)
			if err != nil {
				t.Fatal(err)
			}
			if err := native.ValidateHostInput(input, runtime.GOOS, ref); err != nil {
				t.Fatal(err)
			}
			policy := schema.HostImportExpectation{Route: "session-pack", Destination: "/HostImport", ClockNS: fixedClock.UnixNano(), UID: hostImportUID, GID: hostImportGID, PreserveLinks: true}
			want, err := native.HostImportView(input, policy, source)
			if err != nil {
				t.Fatal(err)
			}
			rules := filesystem.NameRules{Format: "APFS", CaseSensitive: profile == "apfsx", NormalizationInsensitive: true}
			if profile == "hfsplus" || profile == "hfsx" {
				rules.Format = "HFS+"
				rules.CaseSensitive = profile == "hfsx"
			}
			directory := filepath.Join(t.TempDir(), "session")
			s, err := session.Create(ctx, directory, session.Options{Names: rules, UID: hostImportUID, GID: hostImportGID, Time: &fixedClock})
			if err != nil {
				t.Fatal(err)
			}
			checkHostImportRefusals(t, ctx, s, host)
			if _, err := s.Copy(ctx, []string{host}, "/HostImport", session.CopyOptions{FromHost: true, Archive: true, PreserveLinks: true}); err != nil {
				closeFixture(t, s)
				t.Fatal(err)
			}
			checkObservedHostReader(t, ctx, s, input, policy, want, true)
			report := s.Report()
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			s, err = session.Open(ctx, directory)
			if err != nil {
				t.Fatal(err)
			}
			defer closeFixture(t, s)
			checkObservedHostReader(t, ctx, s, input, policy, want, true)
			exported := filepath.Join(t.TempDir(), "workspace")
			if _, err := s.Export(ctx, exported); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			w, err := workspace.Open(ctx, exported)
			if err != nil {
				t.Fatal(err)
			}
			defer closeFixture(t, w)
			checkObservedHostReader(t, ctx, w, input, policy, want, true)
			image := filepath.Join(t.TempDir(), "host.dmg")
			if _, err := pack.Create(ctx, image, w, pack.Options{Format: "UDZO", Volume: pack.VolumeOptions{Name: "Host Imports", Time: fixedClock, Capacity: 16 << 20, CaseSensitive: rules.CaseSensitive}}); err != nil {
				t.Fatal(err)
			}
			checkObservedHostImage(t, ctx, image, input, policy, want)
			cliScratch := t.TempDir()
			createHostImportCLISession(t, binary, cliScratch, profile, host)
			checkHostImportCLIRefusals(t, binary, cliScratch, host)
			cliImage := filepath.Join(t.TempDir(), "cli.dmg")
			var cliReport pack.Report
			if err := json.Unmarshal(runHostImportCommand(t, binary, "pack", "--scratch-dir", cliScratch, "--session", "host", "--volume-name", "Host Imports", "--capacity", "16MiB", "--format", "UDZO", "--time", fixedClock.Format(time.RFC3339), "--json", cliImage), &cliReport); err != nil {
				t.Fatal(err)
			}
			checkHostOmissionRecords(t, cliReport.MetadataOmissions, report.MetadataOmissions, false)
			if packingFileDigest(t, image) != packingFileDigest(t, cliImage) {
				t.Fatal("public CLI and reopened API/workspace pack differ for identical observed host input")
			}
			checkObservedHostInputUnchanged(t, host, input, paths)
		})
	}
}
