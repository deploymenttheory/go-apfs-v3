package edit

import (
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"slices"
	"strings"
)

func ValidNode(n filesystem.Node) bool {
	m := n.Metadata
	if len(n.MetadataDefaulted) > len(MetadataFields) {
		return false
	}
	for i, name := range n.MetadataDefaulted {
		if !slices.Contains(MetadataFields, name) || (i > 0 && n.MetadataDefaulted[i-1] >= name) {
			return false
		}
	}

	if len(n.MetadataModified) > len(MetadataFields) || len(n.AttributesModified) > maxAttributes {
		return false
	}
	for i, name := range n.MetadataModified {
		if !slices.Contains(MetadataFields, name) || (i > 0 && n.MetadataModified[i-1] >= name) {
			return false
		}
		states := map[string]filesystem.State{"mode": m.Mode.State, "uid": m.UID.State, "gid": m.GID.State, "bsdFlags": m.BSDFlags.State, "birthTime": m.BirthTime.State, "modifyTime": m.ModifyTime.State, "accessTime": m.AccessTime.State, "changeTime": m.ChangeTime.State}
		if states[name] != filesystem.Present {
			return false
		}
	}
	for i, name := range n.AttributesModified {
		if !validAttributeName(name) || (i > 0 && n.AttributesModified[i-1] >= name) {
			return false
		}
	}
	for _, state := range []filesystem.State{m.Mode.State, m.UID.State, m.GID.State,
		m.BSDFlags.State, m.BirthTime.State, m.ModifyTime.State, m.ChangeTime.State,
		m.AccessTime.State, n.Links.State, n.Compression.State} {
		if state > filesystem.Present {
			return false
		}
	}
	mode := m.Mode.Value & 0170000
	if n.LinksModified && (mode == 0040000 || n.Links.State != filesystem.Present || n.Links.Value == 0) {
		return false
	}
	if n.Created {
		for _, state := range []filesystem.State{m.Mode.State, m.UID.State, m.GID.State, m.BSDFlags.State, m.BirthTime.State, m.ModifyTime.State, m.ChangeTime.State, m.AccessTime.State} {
			if state != filesystem.Present {
				return false
			}
		}
		if n.Identity.View != 0 || n.Compression.State != filesystem.Absent || m.BSDFlags.Value&32 != 0 {
			return false
		}
		if mode == 0100000 && !n.DataModified {
			return false
		}
		if mode != 0040000 && (n.Links.State != filesystem.Present || n.Links.Value == 0) {
			return false
		}
	} else if strings.HasPrefix(n.Identity.Volume, "workspace:") {
		return false
	}
	return n.Identity.Object != 0 && m.Mode.State == filesystem.Present && (!n.DataModified || m.Mode.Value&0170000 == 0100000)
}
