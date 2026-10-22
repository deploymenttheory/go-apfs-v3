package apfs

import (
	"bytes"
	"fmt"
	"math"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

func validateBuildCloneGroups(objects []*buildObject) error {
	type value struct {
		name        string
		size        int64
		logical     uint64
		compression filesystem.Observation[filesystem.Compression]
		inline      []byte
	}
	groups := map[string]value{}
	claim := func(token string, got value) error {
		if token == "" {
			return nil
		}
		if want, exists := groups[token]; exists && (want.name != got.name || want.size != got.size || want.logical != got.logical || want.compression != got.compression || !bytes.Equal(want.inline, got.inline)) {
			return fmt.Errorf("incompatible declared APFS clone stream: %w", filesystem.ErrCorrupt)
		}
		groups[token] = got
		return nil
	}
	for _, object := range objects {
		clones := object.node.CloneStreams
		if clones == nil {
			continue
		}
		if object.data == nil {
			return filesystem.ErrCorrupt
		}
		if err := claim(clones.Data, value{size: object.data.size, logical: object.node.Size, compression: object.node.Compression}); err != nil {
			return err
		}
		attributes := map[string]buildAttribute{}
		for _, attribute := range object.attrs {
			attributes[attribute.name] = attribute
		}
		for name, token := range clones.Attributes {
			attribute, exists := attributes[name]
			if !exists {
				return fmt.Errorf("declared APFS clone attribute is absent: %w", filesystem.ErrCorrupt)
			}
			got := value{name: name, inline: attribute.inline, size: int64(len(attribute.inline))}
			if attribute.stream != nil {
				got.size = attribute.stream.size
			}
			if err := claim(token, got); err != nil {
				return err
			}
		}
	}
	return nil
}

// The builder translates declared whole-stream lineage to the two APFS
// reference domains. Several data descriptors share one stream ID; independent
// attribute stream IDs may share one physical allocation. Hard-link names do
// not add references in either domain (Apple APFS Reference, streams/extents).
func (p *volumeLayout) shareStream(groups map[string]*buildStream, token string, stream *buildStream, attribute bool) error {
	stream.physicalRefs = 1
	if token == "" {
		return nil
	}
	previous := groups[token]
	if previous == nil {
		groups[token] = stream
		return nil
	}
	if previous.attribute != stream.attribute || previous.size != stream.size || previous.blocks != stream.blocks || (previous.attribute != "") != attribute {
		return fmt.Errorf("incompatible declared APFS clone stream: %w", filesystem.ErrCorrupt)
	}
	stream.backing = previous
	previous.members = append(previous.members, stream)
	if attribute {
		if previous.physicalRefs == math.MaxInt32 {
			return filesystem.ErrLimit
		}
		previous.physicalRefs++
	} else {
		if previous.references == math.MaxUint32 {
			return filesystem.ErrLimit
		}
		previous.references++
	}
	return nil
}
