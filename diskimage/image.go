// Package diskimage separates image decoding and partition enumeration from
// filesystem interpretation. No partition is implicitly preferred.
package diskimage

import (
	"errors"
	"fmt"
	"io"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

type Partition struct {
	Index  int    `json:"index"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Offset int64  `json:"offset"`
	Size   int64  `json:"size"`
}

type Image struct {
	Format       string      `json:"format"`
	PartitionMap string      `json:"partitionMap"`
	Partitions   []Partition `json:"partitions"`
	source       block.Source
	closer       io.Closer
}

// Open owns the input file. The caller must close the returned image after all
// its partition views and filesystem readers have finished using it.
func Open(path string) (*Image, error) {
	f, err := block.Open(path)
	if err != nil {
		return nil, err
	}
	img, err := New(f)
	if err != nil {
		return nil, errors.Join(err, f.Close())
	}
	img.closer = f
	return img, nil
}

// New borrows source, never closes it, and never requests writable access.
func New(source block.Source) (*Image, error) {
	if source == nil || source.Size() < 512 {
		return nil, fmt.Errorf("short image: %w", filesystem.ErrCorrupt)
	}
	i := &Image{Format: "raw", source: source}
	footer := make([]byte, 512)
	if err := block.ReadFull(source, footer, source.Size()-512); err != nil {
		return nil, err
	}
	if string(footer[:4]) == "koly" {
		decoded, err := openUDIF(source, footer)
		if err != nil {
			return nil, err
		}
		i.Format = "udif"
		i.source = decoded
	}
	var err error
	i.PartitionMap, i.Partitions, err = partitions(i.source)
	if err != nil {
		return nil, err
	}
	return i, nil
}

func (i *Image) Size() int64 { return i.source.Size() }
func (i *Image) Close() error {
	if i.closer == nil {
		return nil
	}
	return i.closer.Close()
}

// Partition returns a borrowed view selected by its on-disk index.
func (i *Image) Partition(index int) (*block.Section, error) {
	for _, p := range i.Partitions {
		if p.Index == index {
			return block.NewSection(i.source, p.Offset, p.Size)
		}
	}
	return nil, fmt.Errorf("partition %d does not exist", index)
}
