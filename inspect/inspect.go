// Package inspect composes image and filesystem readers for structural reports.
// The CLI and acceptance harness use this same public entry point.
package inspect

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/hfsplus"
)

type Report struct {
	Schema       int         `json:"schema"`
	Format       string      `json:"format"`
	Size         int64       `json:"size"`
	PartitionMap string      `json:"partitionMap"`
	Partitions   []Partition `json:"partitions"`
}

type Partition struct {
	diskimage.Partition
	Filesystem string          `json:"filesystem"`
	APFS       *apfs.Container `json:"apfs,omitempty"`
	HFSPlus    *hfsplus.Volume `json:"hfsPlus,omitempty"`
}

// Image inspects every recognized partition without selecting one by preference.
// An unrecognized partition is reported; a corrupt recognized filesystem fails.
func Image(ctx context.Context, img *diskimage.Image) (*Report, error) {
	r := &Report{Schema: 1, Format: img.Format, Size: img.Size(), PartitionMap: img.PartitionMap, Partitions: make([]Partition, 0, len(img.Partitions))}
	for _, p := range img.Partitions {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		view, err := img.Partition(p.Index)
		if err != nil {
			return nil, err
		}
		entry := Partition{Partition: p, Filesystem: "unknown"}
		header := make([]byte, 1536)
		known := p.Type == diskimage.APFSType || p.Type == diskimage.HFSType || p.Type == "Apple_APFS" || p.Type == "Apple_HFS" || p.Type == "Apple_HFSX"
		if known && view.Size() < int64(len(header)) {
			return nil, fmt.Errorf("partition %d is too short for its filesystem: %w", p.Index, filesystem.ErrCorrupt)
		}
		if view.Size() >= int64(len(header)) {
			if err := block.ReadFull(view, header, 0); err != nil {
				return nil, err
			}
			switch {
			case string(header[32:36]) == "NXSB" || p.Type == diskimage.APFSType || p.Type == "Apple_APFS":
				entry.Filesystem = "APFS"
				entry.APFS, err = apfs.Open(view)
			case string(header[1024:1026]) == "H+" || string(header[1024:1026]) == "HX" || p.Type == diskimage.HFSType || p.Type == "Apple_HFS" || p.Type == "Apple_HFSX":
				entry.HFSPlus, err = hfsplus.Open(view)
				if entry.HFSPlus != nil {
					entry.Filesystem = entry.HFSPlus.Format
				}
			}
		}
		if err != nil {
			return nil, fmt.Errorf("partition %d: %w", p.Index, err)
		}
		r.Partitions = append(r.Partitions, entry)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return r, nil
}

// Marshal emits stable, versioned JSON without progress or host diagnostics.
func (r *Report) Marshal() ([]byte, error) { return json.MarshalIndent(r, "", "  ") }

// RequireFilesystem rejects a report containing only unrecognized partitions.
func (r *Report) RequireFilesystem() error {
	for _, p := range r.Partitions {
		if p.APFS != nil || p.HFSPlus != nil {
			return nil
		}
	}
	return fmt.Errorf("no recognized filesystem: %w", filesystem.ErrUnsupported)
}
