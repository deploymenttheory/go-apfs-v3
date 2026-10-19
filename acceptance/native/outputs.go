package native

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// HostOutputs is one host's outputs.json with its directory.
type HostOutputs struct {
	Dir      string
	Manifest schema.Outputs
}

// LoadOutputs reads every host's outputs.json. Every host must have
// produced the same set of output names: a host that silently produced
// less proves nothing.
func LoadOutputs(dirs map[string]string) (map[string]HostOutputs, error) {
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
}

// Pair groups outputs by name across hosts and requires every host to have
// produced every name against the same lock. Plaintext copies must be
// byte-identical; encrypted copies must all differ (fresh random material)
// and are verified individually.
func Pair(hosts map[string]HostOutputs) ([]Paired, error) {
	var names []string
	byName := map[string]*Paired{}
	var locks []string
	for host, h := range hosts {
		locks = append(locks, h.Manifest.Lock)
		for _, o := range h.Manifest.Outputs {
			p := byName[o.Name]
			if p == nil {
				p = &Paired{Name: o.Name, Output: o, ByHost: map[string]schema.Output{}, Dirs: map[string]string{}, Locks: map[string]string{}}
				byName[o.Name] = p
				names = append(names, o.Name)
			}
			p.ByHost[host] = o
			p.Dirs[host] = h.Dir
			p.Locks[host] = h.Manifest.Lock
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
			if !expectationsEqual(o.Expect, p.Output.Expect) || o.Operation != p.Output.Operation || o.Encrypted != p.Output.Encrypted {
				return nil, fmt.Errorf("output %s: hosts disagree about its expectation", name)
			}
		}
		sort.Strings(hostNames)
		switch {
		case !p.Output.Encrypted && len(digests) != 1:
			return nil, fmt.Errorf("output %s: plaintext bytes differ across hosts: %v", name, digests)
		case p.Output.Encrypted && len(digests) != len(hosts):
			return nil, fmt.Errorf("output %s: encrypted copies are not all distinct: %v", name, digests)
		}
		p.Primary = hostNames[0]
		out = append(out, *p)
	}
	return out, nil
}

// expectationsEqual compares expectations field by field; the slices
// inside make == invalid.
func expectationsEqual(a, b schema.Expectation) bool {
	if a.View != b.View || a.Volume != b.Volume || a.DiskSHA256 != b.DiskSHA256 || a.Subtree != b.Subtree || a.Continuation != b.Continuation || a.SystemMember != b.SystemMember {
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
