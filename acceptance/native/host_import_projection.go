package native

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func hostInputState(item schema.HostInputEntry, field string) string {
	for _, value := range item.Fields {
		if value.Field == field {
			return value.State
		}
	}
	return ""
}

// hostCopiedACL is an independent COPYFILE_ACL projection. Only direct source
// ACEs are copied; inherited source ACEs belong to the original host parent.
// Destination inheritance is deliberately absent in the two bounded consumers
// (their qualified parent has no ACL), rather than being silently discarded.
func hostCopiedACL(security schema.HostInputSecurity) (string, error) {
	if security.Format != "darwin-filesec" || security.State == "unavailable" {
		return "", nil
	}
	if len(security.Values) == 0 {
		if security.State != "absent" {
			return "", fmt.Errorf("captured Darwin ACL has no original bytes")
		}
		return "", nil
	}
	if len(security.Values) != 1 {
		return "", fmt.Errorf("captured Darwin ACL has multiple representations")
	}
	raw, err := hex.DecodeString(security.Values[0].Hex)
	if err != nil || len(raw) < 44 || len(raw) > 44+128*24 || binary.LittleEndian.Uint32(raw) != 0x012cc16d {
		return "", fmt.Errorf("captured Darwin ACL has invalid bounded host layout")
	}
	count := binary.LittleEndian.Uint32(raw[36:])
	if count != math.MaxUint32 && (count > 128 || len(raw) != 44+int(count)*24) || count == math.MaxUint32 && len(raw) != 44 {
		return "", fmt.Errorf("captured Darwin ACL count contradicts its original bytes")
	}
	state := "present"
	switch count {
	case math.MaxUint32:
		state = "absent"
	case 0:
		state = "empty"
	}
	if security.State != state {
		return "", fmt.Errorf("captured Darwin ACL state contradicts its original count")
	}
	result := make([]byte, 44)
	copy(result[:36], raw[:36])
	if count == math.MaxUint32 {
		if slices.Equal(result[4:36], make([]byte, 32)) {
			return "", nil
		}
		binary.LittleEndian.PutUint32(result[36:], math.MaxUint32)
		return hex.EncodeToString(result), nil
	}
	for offset := 44; offset < len(raw); offset += 24 {
		if binary.LittleEndian.Uint32(raw[offset+16:])&0x10 == 0 {
			result = append(result, raw[offset:offset+24]...)
		}
	}
	binary.LittleEndian.PutUint32(result[36:], uint32((len(result)-44)/24))
	return hex.EncodeToString(result), nil
}

// HostImportDiskACL exposes the reference host-to-network representation for
// portable reader checks without importing the product's filesec codec.
func HostImportDiskACL(security schema.HostInputSecurity) ([]byte, error) {
	value, err := hostCopiedACL(security)
	if err != nil || value == "" {
		return nil, err
	}
	raw, _ := hex.DecodeString(value)
	for _, offset := range []int{0, 36, 40} {
		binary.BigEndian.PutUint32(raw[offset:], binary.LittleEndian.Uint32(raw[offset:]))
	}
	for offset := 44; offset < len(raw); offset += 24 {
		for _, word := range []int{16, 20} {
			binary.BigEndian.PutUint32(raw[offset+word:], binary.LittleEndian.Uint32(raw[offset+word:]))
		}
	}
	return raw, nil
}

func projectedHostTree(inventory schema.HostInputInventory, policy schema.HostImportExpectation) (schema.View, error) {
	if err := ValidateHostInput(inventory, inventory.Host, inventory.Source); err != nil {
		return schema.View{}, err
	}
	clock := policy.ClockNS
	if clock != replayCommandClock || !policy.PreserveLinks || policy.Route == "session-pack" && (policy.UID != 60001 || policy.GID != 60002) {
		return schema.View{}, fmt.Errorf("unqualified host input preservation policy")
	}
	profile := inventory.Source.Profile
	stamp := func(value int64) int64 {
		if profile == "hfsplus" || profile == "hfsx" {
			return time.Unix(0, value).Truncate(time.Second).UnixNano()
		}
		return value
	}
	identities := map[string]uint64{}
	links := map[string]uint32{}
	for _, item := range inventory.Entries {
		if item.Entry.Kind != "dir" {
			links[item.Identity]++
		}
	}
	var view schema.View
	for _, item := range inventory.Entries {
		entry := item.Entry
		if identities[item.Identity] == 0 {
			identities[item.Identity] = uint64(1)<<62 | uint64(len(identities)+1)
		}
		entry.ID = identities[item.Identity]
		entry.Links = links[item.Identity]
		if entry.Path == "." {
			entry.Path = strings.TrimPrefix(policy.Destination, "/")
		} else {
			entry.Path = path.Join(strings.TrimPrefix(policy.Destination, "/"), entry.Path)
		}
		entry.NameBytes = hex.EncodeToString([]byte(path.Base(entry.Path)))
		if hostInputState(item, "mode") != "present" {
			switch entry.Kind {
			case "dir":
				entry.Mode = 0o755
			case "file":
				entry.Mode = 0o644
			case "symlink":
				entry.Mode = 0o777
			}
		}
		if hostInputState(item, "uid") != "present" {
			entry.UID = policy.UID
		}
		if hostInputState(item, "gid") != "present" {
			entry.GID = policy.GID
		}
		if hostInputState(item, "bsdFlags") != "present" {
			entry.Flags = 0
		}
		entry.Flags &^= 0x20 // UF_COMPRESSED describes host storage, not copied logical data.
		entry.Allocated, entry.RawSHA256, entry.Compression, entry.Sparse, entry.Extents, entry.Samples = 0, "", nil, nil, nil, nil
		entry.Times = schema.Times{Birth: min(clock, item.Entry.Times.Modify), Modify: stamp(item.Entry.Times.Modify), Access: stamp(item.Entry.Times.Access), Change: clock}
		entry.Times.Birth, entry.Times.Change = stamp(entry.Times.Birth), stamp(entry.Times.Change)
		switch entry.Kind {
		case "dir":
			entry.Size, entry.Links = 0, 0
		case "symlink":
			target, _ := hex.DecodeString(entry.Target)
			entry.Size = int64(len(target))
		}
		entry.Xattrs = nil
		for _, value := range item.Attributes {
			// These are native security/filesystem representations, not
			// ordinary copied Darwin attributes. ACL policy is separate.
			if value.Name == "system.posix_acl_access" || value.Name == "system.posix_acl_default" || value.Name == "com.apple.system.Security" || strings.HasPrefix(value.Name, "com.apple.fs.") {
				continue
			}
			entry.Xattrs = append(entry.Xattrs, schema.Xattr{Name: value.Name, Bytes: value.Bytes, SHA256: value.SHA256})
		}
		var err error
		entry.ACL, err = hostCopiedACL(item.Security)
		if err != nil {
			return schema.View{}, fmt.Errorf("host input %s: %w", item.Entry.Path, err)
		}
		view.Entries = append(view.Entries, entry)
	}
	return view, nil
}

// HostImportView keeps immutable Apple observations as the reference for every
// untouched peer. Only the declared imported subtree comes from actual-host
// observations. Every staged logical payload is bound to its Apple Entry hash.
func HostImportView(inventory schema.HostInputInventory, policy schema.HostImportExpectation, source schema.View) (schema.View, error) {
	byPath := map[string]schema.Entry{}
	for _, entry := range source.Entries {
		byPath[entry.Path] = entry
	}
	for _, item := range inventory.Entries {
		native, ok := byPath[item.NativePath]
		if !ok || native.Kind != item.Entry.Kind || item.Entry.Kind == "file" && (native.SHA256 != item.Entry.SHA256 || native.Size != item.Entry.Size) || item.Entry.Kind == "symlink" && native.Target != item.Entry.Target {
			return schema.View{}, fmt.Errorf("host input %q is not bound to its original Apple logical entry %q", item.Entry.Path, item.NativePath)
		}
	}
	view, err := projectedHostTree(inventory, policy)
	if err != nil {
		return schema.View{}, err
	}
	switch policy.Route {
	case "session-pack":
		if policy.Destination != "/HostImport" {
			return schema.View{}, fmt.Errorf("host session destination differs")
		}
	case "image-copy":
		if policy.Destination != "/Fixture/HostImport" {
			return schema.View{}, fmt.Errorf("host image destination differs")
		}
		parent, ok := byPath["Fixture"]
		if !ok || parent.Kind != "dir" || parent.ACL != "" {
			return schema.View{}, fmt.Errorf("host image source lacks its qualified ACL-free parent")
		}
		if policy.UID != parent.UID || policy.GID != parent.GID {
			return schema.View{}, fmt.Errorf("host image fallback owners differ from its independently captured parent")
		}
		var peers []schema.Entry
		for _, entry := range source.Entries {
			if entry.Path == "Fixture/HostImport" || strings.HasPrefix(entry.Path, "Fixture/HostImport/") {
				return schema.View{}, fmt.Errorf("host import destination already exists in the native source")
			}
			if entry.Path == "Fixture" {
				entry.Times.Modify, entry.Times.Change = policy.ClockNS, policy.ClockNS
			}
			peers = append(peers, entry)
		}
		view.Entries = append(peers, view.Entries...)
	default:
		return schema.View{}, fmt.Errorf("unqualified host import route")
	}
	slices.SortFunc(view.Entries, func(a, b schema.Entry) int { return strings.Compare(a.Path, b.Path) })
	return view, nil
}

// Effective input equality excludes raw host IDs, provenance and metadata which
// the explicit archive conversion policy cannot preserve. Equal projected
// inputs still require identical plaintext bytes across hosts.
func hostImportEffectiveDigest(inventory schema.HostInputInventory, policy schema.HostImportExpectation) (string, error) {
	view, err := projectedHostTree(inventory, policy)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(struct {
		Source schema.CaseRef               `json:"source"`
		Policy schema.HostImportExpectation `json:"policy"`
		View   schema.View                  `json:"view"`
	}{inventory.Source, policy, view})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
