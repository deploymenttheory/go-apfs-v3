package session

import (
	"fmt"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// Session blobs can coincide for independent files. Clone groups are separate,
// explicit lineage, and must refer to the same complete stream when repeated.
// Checking stored references here needs no payload reads during metadata edits.
func validateCloneGroups(d revision) error {
	type stream struct {
		name        string
		raw, data   blob
		compression filesystem.Observation[filesystem.Compression]
	}
	groups := map[string]stream{}
	claim := func(token string, value stream) error {
		if previous, exists := groups[token]; exists && previous != value {
			return fmt.Errorf("conflicting session clone stream: %w", filesystem.ErrCorrupt)
		}
		groups[token] = value
		return nil
	}
	for _, o := range d.Objects {
		clones := o.Node.CloneStreams
		if clones == nil {
			continue
		}
		if err := filesystem.ValidateCloneStreams(clones); err != nil {
			return err
		}
		if d.Schema < 2 || o.Node.Metadata.Mode.Value&0170000 != 0100000 {
			return fmt.Errorf("invalid session clone metadata: %w", filesystem.ErrCorrupt)
		}
		if clones.Data != "" {
			if o.Raw == nil || o.Data == nil {
				return fmt.Errorf("session clone has no data stream: %w", filesystem.ErrCorrupt)
			}
			if err := claim(clones.Data, stream{raw: *o.Raw, data: *o.Data, compression: o.Node.Compression}); err != nil {
				return err
			}
		}
		for name, token := range clones.Attributes {
			found := false
			for _, attribute := range o.Attributes {
				if attribute.Name == name {
					found = true
					if err := claim(token, stream{name: name, raw: attribute.Value}); err != nil {
						return err
					}
					break
				}
			}
			if !found {
				return fmt.Errorf("session clone attribute is absent: %w", filesystem.ErrCorrupt)
			}
		}
		for _, name := range clones.Partial {
			if name == "" {
				if o.Raw == nil {
					return filesystem.ErrCorrupt
				}
				continue
			}
			found := false
			for _, attribute := range o.Attributes {
				found = found || attribute.Name == name
			}
			if !found {
				return fmt.Errorf("partially shared session stream is absent: %w", filesystem.ErrCorrupt)
			}
		}
	}
	return nil
}
