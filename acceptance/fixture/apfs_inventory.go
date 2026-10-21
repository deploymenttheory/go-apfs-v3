package fixture

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// APFSInventory returns copied volume records enriched with the container UUID
// and roles from the last retained diskutil apfs list transcript containing the
// observed volumes. Older captures omitted those fields from APFSVolume even
// though the original Apple output retained them. The observation stays intact.
func APFSInventory(obs *schema.Observation) ([]schema.Volume, error) {
	if obs == nil || len(obs.Volumes) == 0 {
		return nil, fmt.Errorf("missing observed APFS inventory")
	}
	wanted := make(map[string]schema.Volume, len(obs.Volumes))
	references, containers := map[string]bool{}, map[string]bool{}
	for _, v := range obs.Volumes {
		if v.APFS == nil || !inventoryUUID(v.APFS.VolumeUUID) {
			return nil, fmt.Errorf("volume %d has no valid native APFS identity", v.Index)
		}
		id := strings.ToUpper(v.APFS.VolumeUUID)
		if _, duplicate := wanted[id]; duplicate {
			return nil, fmt.Errorf("duplicate observed APFS UUID %s", id)
		}
		wanted[id] = v
		if ref, _ := v.Diskutil["APFSContainerReference"].(string); ref != "" {
			if !inventoryReference(ref) {
				return nil, fmt.Errorf("volume %d has an invalid native APFS container reference", v.Index)
			}
			references[strings.TrimPrefix(ref, "/dev/")] = true
		}
		if v.APFS.ContainerUUID != "" {
			if !inventoryUUID(v.APFS.ContainerUUID) {
				return nil, fmt.Errorf("volume %d has an invalid native APFS container identity", v.Index)
			}
			containers[strings.ToUpper(v.APFS.ContainerUUID)] = true
		}
	}
	for i := len(obs.Commands) - 1; i >= 0; i-- {
		cmd := obs.Commands[i]
		if cmd.Status != "0" || !isAPFSListPlist(cmd.Argv) {
			continue
		}
		if cmd.StdoutText == "" {
			return nil, fmt.Errorf("retained APFS listing text unavailable")
		}
		if cmd.StdoutSHA256 != "" {
			sum := sha256.Sum256([]byte(cmd.StdoutText))
			if fmt.Sprintf("%x", sum) != cmd.StdoutSHA256 {
				return nil, fmt.Errorf("retained APFS listing digest changed")
			}
		}
		listing, err := readInventoryPlist(cmd.StdoutText)
		if err != nil {
			return nil, fmt.Errorf("retained APFS listing: %w", err)
		}
		listedContainers, ok := listing["Containers"].([]any)
		if !ok {
			return nil, fmt.Errorf("retained APFS listing has no Containers array")
		}
		var selected map[string]any
		for _, item := range listedContainers {
			container, ok := item.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("malformed retained APFS container")
			}
			ref, _ := container["ContainerReference"].(string)
			ref = strings.TrimPrefix(ref, "/dev/")
			containerID, _ := container["APFSContainerUUID"].(string)
			matches := references[ref] || containers[strings.ToUpper(containerID)]
			volumes, hasVolumes := container["Volumes"].([]any)
			completeVolumeIDs := hasVolumes && len(volumes) != 0
			for _, item := range volumes {
				v, ok := item.(map[string]any)
				if !ok {
					completeVolumeIDs = false
					continue // Strict validation follows only after target selection.
				}
				id, _ := v["APFSVolumeUUID"].(string)
				if !inventoryUUID(id) {
					completeVolumeIDs = false
				}
				if _, ok := wanted[strings.ToUpper(id)]; ok {
					matches = true
				}
			}
			distinctReference := len(references) != 0 && inventoryReference(ref) && !references[ref]
			distinctContainer := len(containers) != 0 && inventoryUUID(containerID) && !containers[strings.ToUpper(containerID)]
			provedUnrelated := completeVolumeIDs || distinctReference || distinctContainer
			if matches {
				if selected != nil {
					return nil, fmt.Errorf("observed volumes occur in several retained APFS containers")
				}
				selected = container
			} else if !provedUnrelated {
				return nil, fmt.Errorf("unidentifiable retained APFS container has incomplete volume identities")
			}
		}
		if selected == nil {
			if len(cmd.Argv) == 5 && (references[strings.TrimPrefix(cmd.Argv[4], "/dev/")] || containers[strings.ToUpper(cmd.Argv[4])]) {
				return nil, fmt.Errorf("retained target APFS listing omits the observed container")
			}
			continue
		}
		return enrichInventory(obs.Volumes, selected)
	}
	return nil, fmt.Errorf("no retained native APFS listing contains the observed volumes")
}

func enrichInventory(observed []schema.Volume, container map[string]any) ([]schema.Volume, error) {
	id, _ := container["APFSContainerUUID"].(string)
	if !inventoryUUID(id) {
		return nil, fmt.Errorf("invalid retained APFS container UUID")
	}
	volumes, ok := container["Volumes"].([]any)
	if !ok {
		return nil, fmt.Errorf("retained target APFS container has no Volumes array")
	}
	if len(volumes) != len(observed) {
		return nil, fmt.Errorf("retained APFS volume count %d, observed %d", len(volumes), len(observed))
	}
	byID := map[string]map[string]any{}
	for _, item := range volumes {
		v, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("malformed retained target APFS volume")
		}
		uuid, _ := v["APFSVolumeUUID"].(string)
		if !inventoryUUID(uuid) || byID[strings.ToUpper(uuid)] != nil {
			return nil, fmt.Errorf("invalid or duplicate retained APFS volume UUID")
		}
		byID[strings.ToUpper(uuid)] = v
	}
	out := make([]schema.Volume, len(observed))
	names := map[string]bool{}
	for i, original := range observed {
		if expected, _ := original.Diskutil["APFSContainerReference"].(string); expected != "" {
			got, _ := container["ContainerReference"].(string)
			if strings.TrimPrefix(expected, "/dev/") != strings.TrimPrefix(got, "/dev/") {
				return nil, fmt.Errorf("recorded APFS container reference differs from retained target listing")
			}
		}
		listed := byID[strings.ToUpper(original.APFS.VolumeUUID)]
		if listed == nil {
			return nil, fmt.Errorf("observed volume %s absent from retained APFS inventory", original.APFS.VolumeUUID)
		}
		name, ok := listed["Name"].(string)
		if !ok || name == "" || names[name] || original.Diskutil["VolumeName"] != name {
			return nil, fmt.Errorf("inconsistent retained APFS volume name %q", name)
		}
		names[name] = true
		for field, want := range map[string]int64{"CapacityReserve": original.APFS.ReserveBytes, "CapacityQuota": original.APFS.QuotaBytes} {
			got, ok := listed[field].(int64)
			if !ok || got != want || got < 0 {
				return nil, fmt.Errorf("volume %s: retained %s %v, observed %d", name, field, listed[field], want)
			}
		}
		roles, ok := listed["Roles"].([]any)
		if !ok {
			return nil, fmt.Errorf("volume %s has no retained native Roles array", name)
		}
		roleNames := make([]string, len(roles))
		seen := map[string]bool{}
		for j, role := range roles {
			s, ok := role.(string)
			if !ok || s == "" || seen[s] {
				return nil, fmt.Errorf("volume %s has malformed native roles", name)
			}
			roleNames[j], seen[s] = s, true
		}
		role := strings.Join(roleNames, ",")
		if original.APFS.Role != "" && original.APFS.Role != role || original.APFS.ContainerUUID != "" && !strings.EqualFold(original.APFS.ContainerUUID, id) {
			return nil, fmt.Errorf("volume %s: recorded APFS identity differs from retained listing", name)
		}
		out[i] = original
		apfs := *original.APFS
		apfs.Role, apfs.ContainerUUID = role, strings.ToUpper(id)
		out[i].APFS = &apfs
		out[i].Diskutil = make(map[string]any, len(original.Diskutil))
		for k, v := range original.Diskutil {
			out[i].Diskutil[k] = v
		}
	}
	return out, nil
}

func inventoryUUID(s string) bool {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil {
		return false
	}
	for _, v := range b {
		if v != 0 {
			return true
		}
	}
	return false
}

func inventoryReference(s string) bool {
	s = strings.TrimPrefix(s, "/dev/")
	if !strings.HasPrefix(s, "disk") || len(s) == len("disk") {
		return false
	}
	for _, c := range s[len("disk"):] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// The retained diskutil list format uses only dictionaries, arrays, strings,
// integers and booleans. Parse it directly, with bounded text, depth and tokens,
// so reconstructing historical evidence never invokes a native command.
func readInventoryPlist(text string) (map[string]any, error) {
	if len(text) == 0 || len(text) > retainedAPFSListingTextLimit {
		return nil, fmt.Errorf("APFS listing size outside bounds")
	}
	p := inventoryPlist{decoder: xml.NewDecoder(strings.NewReader(text))}
	start, err := p.next()
	if err != nil || start.Kind != "plist" || start.End {
		return nil, fmt.Errorf("missing plist root: %v", err)
	}
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	end, err := p.next()
	if err != nil || end.Kind != "plist" || !end.End {
		return nil, fmt.Errorf("missing plist end: %v", err)
	}
	if _, err := p.next(); err != io.EOF {
		return nil, fmt.Errorf("trailing plist content")
	}
	dict, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("plist root is not a dictionary")
	}
	return dict, nil
}

type inventoryToken struct {
	Kind string
	End  bool
}

type inventoryPlist struct {
	decoder *xml.Decoder
	tokens  int
}

func (p *inventoryPlist) next() (inventoryToken, error) {
	for {
		p.tokens++
		if p.tokens > 100000 {
			return inventoryToken{}, fmt.Errorf("APFS listing token limit")
		}
		t, err := p.decoder.Token()
		if err != nil {
			return inventoryToken{}, err
		}
		switch t := t.(type) {
		case xml.StartElement:
			return inventoryToken{Kind: t.Name.Local}, nil
		case xml.EndElement:
			return inventoryToken{Kind: t.Name.Local, End: true}, nil
		case xml.CharData:
			if strings.TrimSpace(string(t)) != "" {
				return inventoryToken{}, fmt.Errorf("unexpected plist text")
			}
		}
	}
}

func (p *inventoryPlist) value(depth int) (any, error) {
	t, err := p.next()
	if err != nil {
		return nil, err
	}
	return p.from(t, depth)
}

func (p *inventoryPlist) from(t inventoryToken, depth int) (any, error) {
	if depth > 64 || t.End {
		return nil, fmt.Errorf("invalid plist value or nesting limit")
	}
	switch t.Kind {
	case "dict":
		m := map[string]any{}
		for {
			key, err := p.next()
			if err != nil {
				return nil, err
			}
			if key.Kind == "dict" && key.End {
				return m, nil
			}
			if key.Kind != "key" || key.End {
				return nil, fmt.Errorf("plist dictionary expected key")
			}
			name, err := p.scalar("key")
			if err != nil {
				return nil, err
			}
			if _, duplicate := m[name]; duplicate || name == "" {
				return nil, fmt.Errorf("empty or duplicate plist key")
			}
			m[name], err = p.value(depth + 1)
			if err != nil {
				return nil, err
			}
		}
	case "array":
		var a []any
		for {
			next, err := p.next()
			if err != nil {
				return nil, err
			}
			if next.Kind == "array" && next.End {
				return a, nil
			}
			v, err := p.from(next, depth+1)
			if err != nil {
				return nil, err
			}
			a = append(a, v)
		}
	case "string":
		return p.scalar("string")
	case "integer":
		s, err := p.scalar("integer")
		if err != nil {
			return nil, err
		}
		return strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	case "true", "false":
		s, err := p.scalar(t.Kind)
		if err != nil || s != "" {
			return nil, fmt.Errorf("malformed plist boolean: %v", err)
		}
		return t.Kind == "true", nil
	default:
		return nil, fmt.Errorf("unsupported plist element %q", t.Kind)
	}
}

func (p *inventoryPlist) scalar(kind string) (string, error) {
	var text strings.Builder
	for {
		p.tokens++
		if p.tokens > 100000 {
			return "", fmt.Errorf("APFS listing token limit")
		}
		t, err := p.decoder.Token()
		if err != nil {
			return "", err
		}
		switch t := t.(type) {
		case xml.CharData:
			text.Write(t)
		case xml.EndElement:
			if t.Name.Local == kind {
				return text.String(), nil
			}
			return "", fmt.Errorf("mismatched plist scalar end")
		default:
			return "", fmt.Errorf("nested or malformed plist scalar")
		}
	}
}
