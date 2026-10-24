package native

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func hostInputBasename(name string, producer int) bool {
	return name != "" && name != "." && name != ".." && filepath.Base(name) == name && !strings.ContainsAny(name, "/\\:\x00\r\n") && strings.HasPrefix(name, fmt.Sprintf("macos-%d.", producer))
}

// validateHostImportOutput admits only the two declared host-input journeys.
// It cannot turn an ordinary output into an exception to byte determinism.
func validateHostImportOutput(out schema.Output) error {
	policy := out.Expect.HostImport
	if policy == nil || out.HostInput == nil || out.Source.Recipe != "workspace-edits" || out.Source.Stage != "before" || !schema.IsSupportedProducer(out.Source.Producer) || !slices.Contains([]string{"apfs", "apfsx", "hfsplus", "hfsx"}, out.Source.Profile) || out.Format != "UDZO" || out.Encrypted || out.Password != "" || !reflect.DeepEqual(out.Expect, schema.Expectation{HostImport: policy, Continuation: true}) {
		return fmt.Errorf("host import lacks its closed source/output contract")
	}
	if policy.ClockNS != replayCommandClock || !policy.PreserveLinks {
		return fmt.Errorf("host import has an unqualified archive policy")
	}
	switch policy.Route {
	case "session-pack":
		if out.Operation != "build" || policy.Destination != "/HostImport" || policy.UID != 60001 || policy.GID != 60002 {
			return fmt.Errorf("host session packing has a conflicting operation or root")
		}
	case "image-copy":
		if out.Operation != "edit" || policy.Destination != "/Fixture/HostImport" {
			return fmt.Errorf("host image copying has a conflicting operation or root")
		}
	default:
		return fmt.Errorf("unqualified host import route %q", policy.Route)
	}
	if !hostInputBasename(out.Name, out.Source.Producer) || out.File != out.Name || !strings.HasSuffix(out.File, ".dmg") || out.Bytes <= 0 || out.Bytes > 256<<20 || !schema.ValidDigest(out.SHA256) || !hostInputBasename(out.HostInput.File, out.Source.Producer) || out.HostInput.File == out.File || !strings.HasSuffix(out.HostInput.File, ".json") || out.HostInput.Bytes <= 0 || out.HostInput.Bytes > schema.HostInputMaxBytes || !schema.ValidDigest(out.HostInput.SHA256) {
		return fmt.Errorf("host import has an unsafe or unbounded image/inventory binding")
	}
	return nil
}

// loadHostInput checks both actual artifact files before accepting an input
// inventory. Its contents remain observations of the host, not a native-image
// expectation; the caller must independently bind NativePath payloads to Apple.
func loadHostInput(p Paired, host string) (schema.HostInputInventory, error) {
	var inventory schema.HostInputInventory
	out, ok := p.ByHost[host]
	directory, hasDirectory := p.Dirs[host]
	if !ok || !hasDirectory || directory == "" || p.Name != out.Name || p.Output.Source != out.Source || !reflect.DeepEqual(p.Output.Expect, out.Expect) {
		return inventory, fmt.Errorf("host input lacks its paired source/host/policy binding")
	}
	if err := validateHostImportOutput(out); err != nil {
		return inventory, err
	}
	readArtifact := func(name string, size int64, digest string, retain bool) ([]byte, error) {
		filename := filepath.Join(directory, name)
		info, err := os.Lstat(filename)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Size() != size {
			return nil, fmt.Errorf("host artifact %s has an unexpected type or size", name)
		}
		file, err := os.Open(filename)
		if err != nil {
			return nil, err
		}
		defer func() { _ = file.Close() }()
		opened, err := file.Stat()
		if err != nil || !os.SameFile(info, opened) || opened.Size() != size {
			return nil, fmt.Errorf("host artifact %s changed during open: %v", name, err)
		}
		hash := sha256.New()
		var data []byte
		var count int64
		if retain {
			data, err = io.ReadAll(io.TeeReader(io.LimitReader(file, size+1), hash))
			count = int64(len(data))
		} else {
			count, err = io.Copy(hash, io.LimitReader(file, size+1))
		}
		if err != nil || count != size || hex.EncodeToString(hash.Sum(nil)) != digest {
			return nil, fmt.Errorf("host artifact %s failed its exact byte/digest binding: %v", name, err)
		}
		if err := file.Close(); err != nil {
			return nil, err
		}
		return data, nil
	}
	if _, err := readArtifact(out.File, out.Bytes, out.SHA256, false); err != nil {
		return inventory, err
	}
	data, err := readArtifact(out.HostInput.File, out.HostInput.Bytes, out.HostInput.SHA256, true)
	if err != nil {
		return inventory, err
	}
	if err := schema.DecodeStrict(data, &inventory); err != nil {
		return inventory, fmt.Errorf("host input inventory: %w", err)
	}
	if err := ValidateHostInput(inventory, host, out.Source); err != nil {
		return inventory, err
	}
	provenance, ok := p.Provenance[host]
	if !ok || inventory.Arch != provenance.Arch || inventory.Go != provenance.Go || inventory.Commit != provenance.Commit {
		return inventory, fmt.Errorf("host input provenance differs from its producer manifest")
	}
	return inventory, nil
}

// ValidateHostInput validates a bounded original-host observation. Conversion
// policy belongs to the separate native projection, never to these raw facts.
func ValidateHostInput(inventory schema.HostInputInventory, host string, source schema.CaseRef) error {
	if inventory.Schema != schema.HostInputSchema || inventory.Host != host || !slices.Contains([]string{"darwin", "linux", "windows"}, host) || inventory.Source != source || !slices.Contains([]string{"amd64", "arm64"}, inventory.Arch) || inventory.Go == "" || len(inventory.Go) > 128 || strings.ContainsAny(inventory.Go, "\x00\r\n") || len(inventory.Entries) == 0 || len(inventory.Entries) > schema.HostInputMaxEntries {
		return fmt.Errorf("host input has an invalid schema, provenance or entry bound")
	}
	if inventory.Commit != "" {
		commit, err := hex.DecodeString(inventory.Commit)
		if err != nil || len(commit) != 20 && len(commit) != 32 {
			return fmt.Errorf("host input has an invalid source commit")
		}
	}
	paths := map[string]schema.HostInputEntry{}
	identities := map[string]schema.HostInputEntry{}
	aliasCounts := map[string]uint64{}
	metadataBytes := int64(1024)
	mandatoryFields := []string{"accessTime", "acl", "attributes", "birthTime", "bsdFlags", "changeTime", "gid", "identity", "links", "mode", "modifyTime", "resourceFork", "sourceFlags", "uid"}
	formats := map[string][]string{
		"darwin":  {"darwin-stat", "darwin-xattrs", "darwin-filesec"},
		"linux":   {"linux-stat", "linux-statx", "linux-xattrs", "linux-posix-acl", "linux-inode-flags"},
		"windows": {"windows-file-attributes", "windows-file-basic-info", "windows-file-id", "windows-named-streams", "windows-security-descriptor"},
	}
	for index, item := range inventory.Entries {
		entry := item.Entry
		if entry.Path == "" || !utf8.ValidString(entry.Path) || len(entry.Path) > 4096 || strings.ContainsAny(entry.Path, "\\\x00") || path.Clean(entry.Path) != entry.Path || strings.HasPrefix(entry.Path, "/") || entry.Path == ".." || strings.HasPrefix(entry.Path, "../") || index > 0 && inventory.Entries[index-1].Entry.Path >= entry.Path || item.Identity == "" || len(item.Identity) > 256 || strings.ContainsAny(item.Identity, "\x00\r\n") || !slices.Contains([]string{"file", "dir", "symlink"}, entry.Kind) || entry.Size < 0 || entry.Mode&^uint32(07777) != 0 {
			return fmt.Errorf("host input has an invalid path, object or ordering at %q", entry.Path)
		}
		if item.SourceLinks == 0 || item.SourceLinks > 1<<32-1 || len(item.NameUTF16) > 4096 {
			return fmt.Errorf("host input %q lacks bounded original link/name evidence", entry.Path)
		}
		if host == "windows" {
			name, err := hex.DecodeString(entry.NameBytes)
			if err != nil || !hostInputUTF16Matches(item.NameUTF16, string(name)) {
				return fmt.Errorf("host input %q has conflicting original UTF-16/name bytes", entry.Path)
			}
		}
		if item.NativePath != "" && (!utf8.ValidString(item.NativePath) || len(item.NativePath) > 4096 || path.Clean(item.NativePath) != item.NativePath || item.NativePath == "." || item.NativePath == ".." || strings.HasPrefix(item.NativePath, "/") || strings.HasPrefix(item.NativePath, "../") || strings.ContainsAny(item.NativePath, "\\\x00")) {
			return fmt.Errorf("host input %q has an unsafe original native path", entry.Path)
		}
		if index == 0 {
			if entry.Path != "." || entry.Kind != "dir" {
				return fmt.Errorf("host input lacks its unique directory root")
			}
		} else {
			parent, exists := paths[path.Dir(entry.Path)]
			if !exists || parent.Entry.Kind != "dir" || entry.NameBytes != hex.EncodeToString([]byte(path.Base(entry.Path))) {
				return fmt.Errorf("host input path %q lacks a directory parent or exact name bytes", entry.Path)
			}
		}
		if entry.Kind == "file" && !schema.ValidDigest(entry.SHA256) || entry.Kind != "file" && entry.SHA256 != "" {
			return fmt.Errorf("host input %q has an invalid content digest", entry.Path)
		}
		if entry.Kind == "symlink" {
			target, err := hex.DecodeString(entry.Target)
			if err != nil || len(target) == 0 || len(target) > 4096 || strings.ContainsRune(string(target), 0) {
				return fmt.Errorf("host input %q has an invalid literal link", entry.Path)
			}
		} else if entry.Target != "" {
			return fmt.Errorf("host input %q has a link target on another kind", entry.Path)
		}
		if len(item.Fields) != len(mandatoryFields) {
			return fmt.Errorf("host input %q lacks bounded field availability", entry.Path)
		}
		fields := map[string]bool{}
		for fieldIndex, field := range item.Fields {
			if field.Field != mandatoryFields[fieldIndex] || fields[field.Field] || !slices.Contains([]string{"present", "absent", "unavailable"}, field.State) || !slices.Contains(formats[host], field.SourceFormat) || len(field.Reason) > 1024 || !utf8.ValidString(field.Reason) || strings.ContainsAny(field.Reason, "\x00\r\n") || field.State == "unavailable" && field.Reason == "" || field.State == "absent" && field.Field != "acl" && field.Field != "resourceFork" {
				return fmt.Errorf("host input %q has ambiguous field availability", entry.Path)
			}
			fields[field.Field] = true
			metadataBytes += int64(len(field.Field) + len(field.SourceFormat) + len(field.Reason) + 128)
		}
		for _, values := range [][]schema.HostInputValue{item.Attributes, item.NamedStreams, item.Security.Values} {
			if len(values) > schema.HostInputMaxAttributes {
				return fmt.Errorf("host input %q exceeds its attribute/security count bound", entry.Path)
			}
			for _, value := range values {
				metadataBytes += int64(len(value.Hex) + len(value.Name) + len(value.NameUTF16) + len(value.SHA256) + 256)
			}
			if metadataBytes > schema.HostInputMaxBytes {
				return fmt.Errorf("host input exceeds its aggregate metadata bound")
			}
			if err := validateHostInputValues(values); err != nil {
				return fmt.Errorf("host input %q: %w", entry.Path, err)
			}
		}
		format := map[string]string{"darwin": "darwin-filesec", "linux": "linux-posix-acl", "windows": "windows-security-descriptor"}[host]
		security := item.Security
		if security.Format != format || !slices.Contains([]string{"present", "empty", "null", "absent", "unavailable"}, security.State) || security.State == "null" && host != "windows" || len(security.Reason) > 1024 || strings.ContainsAny(security.Reason, "\x00\r\n") || security.State == "unavailable" && (security.Reason == "" || len(security.Values) != 0) || security.State == "absent" && host == "linux" && len(security.Values) != 0 || (security.State == "present" || security.State == "empty" || security.State == "null") && len(security.Values) == 0 || host != "windows" && (item.NameUTF16 != "" || len(item.NamedStreams) != 0) {
			return fmt.Errorf("host input %q has conflicting security or stream provenance", entry.Path)
		}
		for _, field := range item.Fields {
			if field.Field == "acl" {
				state := security.State
				if state == "empty" || state == "null" {
					state = "present"
				}
				if field.State != state || field.SourceFormat != security.Format {
					return fmt.Errorf("host input %q contradicts its ACL observation", entry.Path)
				}
			}
		}
		if prior, exists := identities[item.Identity]; exists {
			if entry.Kind != "file" || prior.Entry.Kind != "file" || entry.SHA256 != prior.Entry.SHA256 || entry.Size != prior.Entry.Size || item.SourceLinks != prior.SourceLinks || item.SourceMode != prior.SourceMode || item.SourceFlags != prior.SourceFlags || entry.Mode != prior.Entry.Mode || entry.UID != prior.Entry.UID || entry.GID != prior.Entry.GID || entry.Flags != prior.Entry.Flags || !reflect.DeepEqual(entry.Times, prior.Entry.Times) || !reflect.DeepEqual(item.Fields, prior.Fields) || !reflect.DeepEqual(item.Attributes, prior.Attributes) || !reflect.DeepEqual(item.NamedStreams, prior.NamedStreams) || !reflect.DeepEqual(item.Security, prior.Security) {
				return fmt.Errorf("host input %q contradicts its alias identity", entry.Path)
			}
		} else {
			identities[item.Identity] = item
		}
		aliasCounts[item.Identity]++
		if entry.Kind == "file" && aliasCounts[item.Identity] > item.SourceLinks {
			return fmt.Errorf("host input %q has more aliases than its original link count", entry.Path)
		}
		paths[entry.Path] = item
		metadataBytes += int64(len(entry.Path) + len(entry.NameBytes) + len(entry.Target) + len(item.Identity) + len(item.NameUTF16) + len(item.NativePath) + 1024)
		if metadataBytes > schema.HostInputMaxBytes {
			return fmt.Errorf("host input exceeds its aggregate metadata bound")
		}
	}
	return nil
}

func validateHostInputValues(values []schema.HostInputValue) error {
	if len(values) > schema.HostInputMaxAttributes {
		return fmt.Errorf("host attribute/security inventory exceeds its entry bound")
	}
	seen := map[string]bool{}
	for _, value := range values {
		if value.Name == "" || len(value.Name) > 1024 || !utf8.ValidString(value.Name) || strings.ContainsRune(value.Name, 0) || seen[value.Name] || value.Bytes < 0 || value.Bytes > schema.HostInputMaxValueBytes || len(value.Hex) != int(value.Bytes)*2 || !schema.ValidDigest(value.SHA256) || len(value.NameUTF16) > 4096 {
			return fmt.Errorf("host attribute/security value is duplicated or unbounded")
		}
		data, err := hex.DecodeString(value.Hex)
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(data)) != value.SHA256 {
			return fmt.Errorf("host attribute/security value failed its original byte digest")
		}
		if value.NameUTF16 != "" {
			if !hostInputUTF16Matches(value.NameUTF16, value.Name) {
				return fmt.Errorf("host stream name has invalid original UTF-16 bytes")
			}
		}
		seen[value.Name] = true
	}
	return nil
}

func hostInputUTF16Matches(encoded, bridge string) bool {
	raw, err := hex.DecodeString(encoded)
	if err != nil || len(raw) == 0 || len(raw)%2 != 0 || len(raw) > 2048 {
		return false
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	for i := 0; i < len(units); i++ {
		if utf16.IsSurrogate(rune(units[i])) {
			if i+1 >= len(units) || utf16.DecodeRune(rune(units[i]), rune(units[i+1])) == utf8.RuneError {
				return false
			}
			i++
		}
	}
	return string(utf16.Decode(units)) == bridge
}
