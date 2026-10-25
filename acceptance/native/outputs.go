package native

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// HostOutputs is one host's outputs.json with its directory.
type HostOutputs struct {
	Dir      string
	Manifest schema.Outputs
}

// LoadOutputs reads every host's outputs.json. Every host must have
// produced the same set of output names: a host that silently produced
// less proves nothing. A non-zero producer keeps only the outputs derived
// from that macOS version's fixtures; the job verifying that producer
// downloads only those images.
func LoadOutputs(dirs map[string]string, producer int) (map[string]HostOutputs, error) {
	hosts := map[string]HostOutputs{}
	for host, dir := range dirs {
		data, err := os.ReadFile(filepath.Join(dir, "outputs.json"))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", host, err)
		}
		var m schema.Outputs
		if err := schema.DecodeStrict(data, &m); err != nil {
			return nil, fmt.Errorf("%s: outputs.json: %w", host, err)
		}
		if m.Schema != schema.OutputsSchema {
			return nil, fmt.Errorf("%s: outputs schema %d, want %d", host, m.Schema, schema.OutputsSchema)
		}
		if m.Host != host {
			return nil, fmt.Errorf("%s: outputs.json was produced on %s", host, m.Host)
		}
		if producer != 0 {
			var kept []schema.Output
			for _, o := range m.Outputs {
				if o.Source.Producer == producer {
					kept = append(kept, o)
				}
			}
			m.Outputs = kept
		}
		for _, o := range m.Outputs {
			info, err := os.Stat(filepath.Join(dir, o.File))
			if err != nil {
				return nil, fmt.Errorf("%s: output %s: %w", host, o.Name, err)
			}
			if info.Size() != o.Bytes {
				return nil, fmt.Errorf("%s: output %s is %d bytes, manifest says %d", host, o.Name, info.Size(), o.Bytes)
			}
		}
		hosts[host] = HostOutputs{Dir: dir, Manifest: m}
	}
	if len(hosts) == 0 {
		return nil, fmt.Errorf("no host outputs")
	}
	return hosts, nil
}

// Paired is one output name with every host's copy.
type Paired struct {
	Name    string
	Output  schema.Output // the first host's record; the expectation is identical on every host
	ByHost  map[string]schema.Output
	Dirs    map[string]string
	Locks   map[string]string
	Primary string // the host whose copy is attached when all copies are identical
	// Provenance binds independently observed host inputs to the producer
	// manifest which carried their image and sidecar.
	Provenance map[string]HostOutputProvenance
	// Passwords are the public output passwords from the primary host's
	// manifest.
	Passwords map[string]string
	// SkipChecksums skips hdiutil verify for a sector-preserving output
	// whose lineage already had its UDIF checksums verified in the same
	// format and encryption; its device digest is still checked.
	SkipChecksums bool
	// DecryptHosts, when set, limits which hosts' copies of an encrypted
	// sector-preserving output Apple decrypts; every host decrypts its own
	// copies in the portable tier.
	DecryptHosts []string
}

type HostOutputProvenance struct {
	Arch   string
	Go     string
	Commit string
}

// Pair groups outputs by name across hosts and requires every host to have
// produced every name against the same lock. Plaintext copies must be
// byte-identical; encrypted copies must all differ (fresh random material).
// Preservation archives retain host availability/provenance and are independently
// verified on every host's copy, rather than treating a matching digest as proof.
func Pair(hosts map[string]HostOutputs) ([]Paired, error) {
	var names []string
	byName := map[string]*Paired{}
	var locks []string
	for host, h := range hosts {
		locks = append(locks, h.Manifest.Lock)
		for _, o := range h.Manifest.Outputs {
			p := byName[o.Name]
			if p == nil {
				p = &Paired{Name: o.Name, Output: o, ByHost: map[string]schema.Output{}, Dirs: map[string]string{}, Locks: map[string]string{}, Provenance: map[string]HostOutputProvenance{}}
				byName[o.Name] = p
				names = append(names, o.Name)
			}
			p.ByHost[host] = o
			p.Dirs[host] = h.Dir
			p.Locks[host] = h.Manifest.Lock
			p.Provenance[host] = HostOutputProvenance{Arch: h.Manifest.Arch, Go: h.Manifest.Go, Commit: h.Manifest.Commit}
		}
	}
	for i := 1; i < len(locks); i++ {
		if locks[i] != locks[0] {
			return nil, fmt.Errorf("hosts tested against different locks: %s vs %s", locks[0], locks[i])
		}
	}
	sort.Strings(names)
	var out []Paired
	for _, name := range names {
		p := byName[name]
		if len(p.ByHost) != len(hosts) {
			var missing []string
			for host := range hosts {
				if _, ok := p.ByHost[host]; !ok {
					missing = append(missing, host)
				}
			}
			sort.Strings(missing)
			return nil, fmt.Errorf("output %s is missing from %v", name, missing)
		}
		digests := map[string][]string{}
		var hostNames []string
		for host, o := range p.ByHost {
			digests[o.SHA256] = append(digests[o.SHA256], host)
			hostNames = append(hostNames, host)
			if !expectationsEqual(o.Expect, p.Output.Expect) || o.Operation != p.Output.Operation || o.Encrypted != p.Output.Encrypted || o.Source != p.Output.Source || o.Format != p.Output.Format {
				return nil, fmt.Errorf("output %s: hosts disagree about its expectation", name)
			}
			if (o.HostInput == nil) != (o.Expect.HostImport == nil) {
				return nil, fmt.Errorf("output %s: unqualified host-input exception on %s", name, host)
			}
		}
		sort.Strings(hostNames)
		if p.Output.Expect.HostImport != nil {
			byInput := map[string]string{}
			for _, host := range hostNames {
				inventory, err := loadHostInput(*p, host)
				if err != nil {
					return nil, fmt.Errorf("output %s on %s: %w", name, host, err)
				}
				provenance := p.Provenance[host]
				if inventory.Arch != provenance.Arch || inventory.Go != provenance.Go || inventory.Commit != provenance.Commit {
					return nil, fmt.Errorf("output %s on %s: host inventory provenance differs from its manifest", name, host)
				}
				input, err := hostImportEffectiveDigest(inventory, *p.Output.Expect.HostImport)
				if err != nil {
					return nil, err
				}
				if previous, ok := byInput[input]; ok && previous != p.ByHost[host].SHA256 {
					return nil, fmt.Errorf("output %s: equal observed host inputs produced different plaintext bytes", name)
				}
				byInput[input] = p.ByHost[host].SHA256
			}
		}
		switch {
		case !p.Output.Encrypted && p.Output.Expect.Workspace == nil && p.Output.Expect.HostImport == nil && len(digests) != 1:
			return nil, fmt.Errorf("output %s: plaintext bytes differ across hosts: %v", name, digests)
		case p.Output.Encrypted && len(digests) != len(hosts):
			return nil, fmt.Errorf("output %s: encrypted copies are not all distinct: %v", name, digests)
		}
		p.Primary = hostNames[0]
		p.Passwords = hosts[p.Primary].Manifest.Passwords
		out = append(out, *p)
	}
	return out, nil
}

// A fixture or export omitted by every host must not disappear from the native
// verdict table. Require each stage of the capabilities this consumer qualifies.
func requireWorkspaceOutputs(pairs []Paired, cases map[string]corpus.Case, major int) error {
	produced := map[string]schema.Output{}
	for _, p := range pairs {
		o := p.Output
		if o.Expect.Workspace == nil {
			continue
		}
		if o.Operation == "workspace-snapshot" {
			continue // required independently for each captured snapshot below
		}
		if o.Format != "workspace" || o.Encrypted || o.Expect.Continuation {
			return fmt.Errorf("invalid workspace output %s", o.Name)
		}
		ref := o.Source
		if ref.Stage != "before" {
			return fmt.Errorf("workspace output %s lost its original source", o.Name)
		}
		if o.Expect.View != "" {
			ref.Stage = o.Expect.View
		}
		key := CaseKey(ref)
		if _, exists := produced[key]; exists {
			return fmt.Errorf("duplicate workspace state %s", key)
		}
		produced[key] = o
	}
	for _, k := range cases {
		if k.Producer != major {
			continue
		}
		var policy, operation string
		switch k.Recipe {
		case "workspace-edits":
			policy = "preserve"
			switch k.Stage {
			case "before":
				operation = "extract"
			case "replaced":
				operation = "replace"
			case "restructured", "metadata":
				operation = "edit"
			default:
				return fmt.Errorf("unqualified workspace stage %s", k.Stage)
			}
		case "file-command-journeys", "permission-inheritance":
			policy, operation = "commands", "session"
		default:
			continue
		}
		key := CaseKey(schema.CaseRef{Producer: k.Producer, Recipe: k.Recipe, Profile: k.Profile, Stage: k.Stage})
		o, exists := produced[key]
		if !exists {
			return fmt.Errorf("no independently verifiable workspace output for %s", key)
		}
		if o.Operation != "workspace-"+operation || o.Expect.Workspace.Policy != policy || o.Expect.Subtree != "Fixture" {
			return fmt.Errorf("wrong workspace consumer for %s", key)
		}
	}
	return nil
}

// Require every retained AppleDouble control, even if all hosts omit it.
func requireAppleDoubleOutputs(pairs []Paired, cases map[string]corpus.Case, major int) error {
	produced := map[string]bool{}
	for _, p := range pairs {
		o := p.Output
		if o.Expect.AppleDouble == nil {
			continue
		}
		if o.Operation != "appledouble" || o.Format != "appledouble" || o.Encrypted || !reflect.DeepEqual(o.Expect, schema.Expectation{AppleDouble: o.Expect.AppleDouble}) {
			return fmt.Errorf("invalid AppleDouble consumer %s", o.Name)
		}
		key := CaseKey(o.Source) + "\x00" + o.Expect.AppleDouble.Path
		if produced[key] {
			return fmt.Errorf("duplicate AppleDouble consumer %s", o.Name)
		}
		produced[key] = true
	}
	for _, k := range cases {
		if k.Producer != major || k.Recipe != "file-corpus" || k.Stage != "final" {
			continue
		}
		if k.Observation == nil || len(k.Observation.Views) != 1 || len(k.Observation.Views[0].AppleDouble) == 0 {
			return fmt.Errorf("missing native AppleDouble controls for %d/%s/%s", major, k.Recipe, k.Profile)
		}
		seen := map[string]bool{}
		for _, e := range k.Observation.Views[0].AppleDouble {
			key := CaseKey(schema.CaseRef{Producer: k.Producer, Recipe: k.Recipe, Profile: k.Profile, Stage: k.Stage}) + "\x00" + e.Path
			if seen[e.Path] || !produced[key] {
				return fmt.Errorf("no unique independently verifiable AppleDouble output for %s", key)
			}
			seen[e.Path] = true
		}
	}
	return nil
}

// expectationsEqual compares expectations field by field; the slices
// inside make == invalid.
func expectationsEqual(a, b schema.Expectation) bool {
	if !reflect.DeepEqual(a.DeletedSnapshots, b.DeletedSnapshots) {
		return false
	}
	if !reflect.DeepEqual(a.HostImport, b.HostImport) {
		return false
	}
	if !reflect.DeepEqual(a.Container, b.Container) {
		return false
	}
	if !reflect.DeepEqual(a.AppleDouble, b.AppleDouble) {
		return false
	}
	if !reflect.DeepEqual(a.Workspace, b.Workspace) {
		return false
	}
	if a.SelectedXID != b.SelectedXID || a.View != b.View || a.Snapshot != b.Snapshot || a.Volume != b.Volume || a.DiskSHA256 != b.DiskSHA256 || a.Subtree != b.Subtree || a.CommandClockNS != b.CommandClockNS || a.Continuation != b.Continuation || a.SystemMember != b.SystemMember || a.FileCompression != b.FileCompression || a.NewIdentities != b.NewIdentities || a.ContinuationRefusal != b.ContinuationRefusal {
		return false
	}
	if len(a.Codesign) != len(b.Codesign) || len(a.IgnoreTimes) != len(b.IgnoreTimes) {
		return false
	}
	for i := range a.Codesign {
		if a.Codesign[i] != b.Codesign[i] {
			return false
		}
	}
	for i := range a.IgnoreTimes {
		if a.IgnoreTimes[i] != b.IgnoreTimes[i] {
			return false
		}
	}
	return true
}

// planContainerChecks spreads the expensive container work of
// sector-preserving outputs across a lineage. hdiutil verify, which re-reads
// a whole image to check its UDIF checksums, runs on the first output of
// each format and encryption; every output still has its device digest
// checked. Apple decrypts one host's copy of each encrypted output, the
// host rotating through the lineage so every host's encryption is judged;
// each host decrypts all of its own copies in the portable tier.
func planContainerChecks(group []Paired) {
	verified := map[string]bool{}
	turn := 0
	for i := range group {
		p := &group[i]
		if p.Output.Expect.DiskSHA256 == "" || p.Output.Operation == "edit" || strings.HasPrefix(p.Output.Operation, "recover-") {
			continue
		}
		kind := fmt.Sprintf("%s/%v", p.Output.Format, p.Output.Encrypted)
		p.SkipChecksums = verified[kind]
		verified[kind] = true
		if p.Output.Encrypted {
			hosts := make([]string, 0, len(p.ByHost))
			for host := range p.ByHost {
				hosts = append(hosts, host)
			}
			sort.Strings(hosts)
			p.DecryptHosts = []string{hosts[turn%len(hosts)]}
			turn++
		}
	}
}
