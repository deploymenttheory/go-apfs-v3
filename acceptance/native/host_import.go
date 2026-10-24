package native

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// ACL errors cannot become an apparently absent ACL in this consumer.
type hostImportVolume struct {
	fixture.Volume
	aclError error
}

func (v *hostImportVolume) ACL(filename string) ([]byte, error) {
	value, err := v.Volume.ACL(filename)
	if err != nil {
		v.aclError = errors.Join(v.aclError, fmt.Errorf("read native host-import ACL %s: %w", filename, err))
	}
	return value, err
}

func (v *hostImportVolume) ObservationError() error { return v.aclError }

func (v *Verifier) hostImportVerifier(name, host string) (*Verifier, *hostImportVolume) {
	copy := v.ForSubtest()
	copy.Work = filepath.Join(v.Work, "host-import", sanitize(name), host)
	volume := &hostImportVolume{Volume: copy.Vol}
	copy.Vol = volume
	return copy, volume
}

func hostImportHosts(p Paired) ([]string, error) {
	hosts := make([]string, 0, len(p.ByHost))
	for host := range p.ByHost {
		hosts = append(hosts, host)
	}
	slices.Sort(hosts)
	if !slices.Equal(hosts, []string{"darwin", "linux", "windows"}) {
		return nil, fmt.Errorf("host import requires every portable host, got %v", hosts)
	}
	return hosts, nil
}

func (v *Verifier) verifyHostImport(ctx context.Context, p Paired) ([]Difference, error) {
	if err := validateHostImportOutput(p.Output); err != nil {
		return nil, err
	}
	hosts, err := hostImportHosts(p)
	if err != nil {
		return nil, err
	}
	k, source, err := v.expectedView(p.Output)
	if err != nil {
		return nil, err
	}
	var differences []Difference
	for _, host := range hosts {
		input, err := loadHostInput(p, host)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", host, err)
		}
		want, err := HostImportView(input, *p.ByHost[host].Expect.HostImport, source)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", host, err)
		}
		current, volume := v.hostImportVerifier(p.Name, host)
		output := p.ByHost[host]
		observed, err := current.observeImage(ctx, output.Name, filepath.Join(p.Dirs[host], output.File), output.Format, nil, schema.ObserveSpec{Checks: []string{"verify", "fsck"}}, v.Recipes[k.Recipe])
		if err := errors.Join(err, volume.aclError); err != nil {
			return nil, fmt.Errorf("%s: independently observe host import: %w", host, err)
		}
		view, err := onlyLiveView(observed)
		if err != nil {
			return nil, err
		}
		if output.Expect.HostImport.Route == "image-copy" {
			metadata, err := comparePreservedVolumeMetadata(observed, k.Observation)
			if err != nil {
				return nil, fmt.Errorf("%s: host import volume preservation: %w", host, err)
			}
			for _, difference := range metadata {
				difference.Path = host + ":" + difference.Path
				differences = append(differences, difference)
			}
		} else if err := hostImportConstructedProfile(observed.Volumes[0], output.Source.Profile); err != nil {
			return nil, fmt.Errorf("%s: %w", host, err)
		}
		opts := CompareOptions{IgnoreTimes: map[string]bool{}, IgnoreIdentity: output.Operation == "build"}
		if !opts.IgnoreIdentity {
			opts.Existing = map[string]bool{}
			for _, entry := range source.Entries {
				opts.Existing[entry.Path] = true
			}
		}
		for _, difference := range CompareViews(view, want, opts) {
			difference.Path = host + ":" + difference.Path
			differences = append(differences, difference)
		}
	}
	return differences, nil
}

func hostImportConstructedProfile(volume schema.Volume, profile string) error {
	switch profile {
	case "apfs", "apfsx":
		if volume.APFS == nil || volume.HFS != nil || volume.APFS.CaseSensitive != (profile == "apfsx") || volume.APFS.Encrypted || volume.APFS.Role != "" || volume.APFS.GroupUUID != "" || volume.APFS.ReserveBytes != 0 || volume.APFS.QuotaBytes != 0 || len(volume.APFS.Snapshots) != 0 {
			return fmt.Errorf("packed host import changed its qualified APFS profile")
		}
	case "hfsplus", "hfsx":
		if volume.HFS == nil || volume.APFS != nil || volume.HFS.CaseSensitive != (profile == "hfsx") || volume.HFS.Journaled {
			return fmt.Errorf("packed host import changed its qualified HFS profile")
		}
	default:
		return fmt.Errorf("unqualified host import filesystem profile")
	}
	return nil
}

// Every host has a different independently observed input. The complete normal
// native -> Go -> native continuation therefore runs on every host's output.
func (v *Verifier) hostImportContinuations(ctx context.Context, p Paired) error {
	hosts, err := hostImportHosts(p)
	if err != nil {
		return err
	}
	for _, host := range hosts {
		current, volume := v.hostImportVerifier(p.Name+".continued", host)
		selected := p
		selected.Output, selected.Primary = p.ByHost[host], host
		k := v.Cases[CaseKey(selected.Output.Source)]
		_, err := current.Continuation(ctx, selected, schemaCase{recipe: v.Recipes[k.Recipe]})
		if err := errors.Join(err, volume.aclError); err != nil {
			return fmt.Errorf("%s: full host-import continuation: %w", host, err)
		}
	}
	return nil
}

func hostImportOutputName(source schema.CaseRef, route string) string {
	operation := "build"
	if route == "image-copy" {
		operation = "edit"
	}
	return fmt.Sprintf("macos-%d.workspace-edits.%s.before.%s.host-import.UDZO.dmg", source.Producer, source.Profile, operation)
}

// A common omission must not erase an entire foreign-host archive consumer.
func requireHostImportOutputs(pairs []Paired, cases map[string]corpus.Case, major int) error {
	produced := map[string]bool{}
	for _, pair := range pairs {
		out := pair.Output
		if out.Expect.HostImport == nil && out.HostInput == nil {
			continue
		}
		if err := validateHostImportOutput(out); err != nil {
			return err
		}
		if _, err := hostImportHosts(pair); err != nil {
			return err
		}
		if out.Source.Producer != major || pair.Name != hostImportOutputName(out.Source, out.Expect.HostImport.Route) || produced[pair.Name] {
			return fmt.Errorf("duplicate or unqualified host-import output %s", pair.Name)
		}
		if _, ok := cases[CaseKey(out.Source)]; !ok {
			return fmt.Errorf("host import %s lacks its retained native source", pair.Name)
		}
		produced[pair.Name] = true
	}
	for _, profile := range []string{"apfs", "apfsx", "hfsplus", "hfsx"} {
		source := schema.CaseRef{Producer: major, Recipe: "workspace-edits", Profile: profile, Stage: "before"}
		if _, ok := cases[CaseKey(source)]; !ok {
			return fmt.Errorf("missing native host-import source %s", CaseKey(source))
		}
		for _, route := range []string{"session-pack", "image-copy"} {
			if !produced[hostImportOutputName(source, route)] {
				return fmt.Errorf("missing required host-import route %s", hostImportOutputName(source, route))
			}
		}
	}
	return nil
}
