package apfs

import (
	"context"
	"fmt"
	"math"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

type storageStream struct {
	size, allocated, sparse uint64
	owners                  uint32
	attribute               bool
}

type streamInventory struct {
	streams    map[uint64]*storageStream
	references map[uint64]uint32
	inodes     map[uint64]buildRecord
	extents    []storageExtent
}

func (s *streamInventory) add(id uint64, data []byte, attribute bool, sparse uint64) error {
	if id == 0 || id > objectMask || len(data) != 40 {
		return corrupt("storage stream descriptor", 0)
	}
	if le.Uint64(data[8:])%4096 != 0 || sparse%4096 != 0 || sparse > le.Uint64(data[8:]) {
		return corrupt("stream allocation/sparse-byte count", 0)
	}
	if le.Uint64(data[16:]) != 0 {
		return fmt.Errorf("stream allocation or crypto profile: %w", filesystem.ErrUnsupported)
	}
	// Native sparse inodes include hole bytes in alloced_size. Their separate
	// INO_EXT_TYPE_SPARSE_BYTES field removes those bytes from physical usage.
	stream := storageStream{size: le.Uint64(data), allocated: (le.Uint64(data[8:]) - sparse) / 4096, sparse: sparse, owners: 1, attribute: attribute}
	if previous, exists := s.streams[id]; exists {
		if previous.size != stream.size || previous.allocated != stream.allocated || previous.sparse != sparse || previous.attribute != attribute || previous.owners == math.MaxUint32 {
			return corrupt("conflicting shared stream descriptors", 0)
		}
		previous.owners++
	} else {
		s.streams[id] = &stream
	}
	return nil
}

func scanStorageStreams(ctx context.Context, records []buildRecord, blocks uint64, super []byte) (*streamInventory, error) {
	if len(records) > maxStorageRecords {
		return nil, filesystem.ErrLimit
	}
	s := &streamInventory{streams: map[uint64]*storageStream{}, references: map[uint64]uint32{}, inodes: map[uint64]buildRecord{}}
	links := map[uint64]uint32{}
	var files, dirs, symlinks, others uint64
	for _, r := range records {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(r.key) < 8 {
			return nil, corrupt("storage record key", 0)
		}
		p := prefix(r.key)
		switch p.kind {
		case 3:
			if len(r.key) != 8 || len(r.value) < 92 {
				return nil, corrupt("storage inode record", 0)
			}
			if _, exists := s.inodes[p.id]; exists {
				return nil, corrupt("duplicate storage inode", 0)
			}
			s.inodes[p.id] = r
			flags := le.Uint64(r.value[48:])
			if flags&^uint64(0x7fffff) != 0 || flags&(0x80|0x800|0x400000) != 0 {
				return nil, fmt.Errorf("unfinished/exempt inode storage flags %#x: %w", flags, filesystem.ErrUnsupported)
			}
			switch le.Uint16(r.value[80:]) & 0170000 {
			case 0100000:
				files++
			case 0040000:
				if p.id != 2 && p.id != 3 {
					dirs++
				}
			case 0120000:
				symlinks++
			default:
				others++
			}
			var descriptor []byte
			var sparse uint64
			sparseFound := false
			if err := extendedFields(r.value[92:], func(kind byte, data []byte) error {
				switch kind {
				case 8:
					if descriptor != nil || len(data) != 40 {
						return corrupt("inode stream descriptor", 0)
					}
					descriptor = data
				case 13:
					if sparseFound || len(data) != 8 {
						return corrupt("inode sparse-byte field", 0)
					}
					sparseFound, sparse = true, le.Uint64(data)
				}
				return nil
			}); err != nil {
				return nil, err
			}
			if sparseFound != (le.Uint64(r.value[48:])&0x200 != 0) || sparseFound && descriptor == nil {
				return nil, corrupt("inode sparse flag/descriptor", 0)
			}
			if descriptor != nil {
				id := le.Uint64(r.value[8:])
				if err := s.add(id, descriptor, false, sparse); err != nil {
					return nil, err
				}
			}
		case 4:
			if len(r.key) < 11 || len(r.value) < 4 || int(le.Uint16(r.value[2:])) != len(r.value)-4 || int(le.Uint16(r.key[8:])) != len(r.key)-10 || r.key[len(r.key)-1] != 0 {
				return nil, corrupt("storage attribute record", 0)
			}
			flags := le.Uint16(r.value)
			if flags&^uint16(0x1f) != 0 || flags&3 != 1 && flags&3 != 2 || flags&0x10 != 0 && flags&3 != 1 {
				return nil, fmt.Errorf("storage attribute flags %#x: %w", flags, filesystem.ErrUnsupported)
			}
			if string(r.key[10:len(r.key)-1]) == filesystem.ResourceFork && flags&3 != 1 {
				return nil, corrupt("resource fork is not stream based", 0)
			}
			if flags&1 != 0 {
				if len(r.value) != 52 {
					return nil, corrupt("attribute stream descriptor", 0)
				}
				id := le.Uint64(r.value[4:])
				if err := s.add(id, r.value[12:], true, 0); err != nil {
					return nil, err
				}
			}
		case 6:
			if len(r.key) != 8 || len(r.value) != 4 || le.Uint32(r.value) == 0 {
				return nil, corrupt("data-stream reference record", 0)
			}
			if _, exists := s.references[p.id]; exists {
				return nil, corrupt("duplicate data-stream reference", 0)
			}
			s.references[p.id] = le.Uint32(r.value)
		case 9:
			if len(r.value) < 18 || links[le.Uint64(r.value)] == math.MaxUint32 {
				return nil, corrupt("storage directory reference", 0)
			}
			links[le.Uint64(r.value)]++
		case 10:
			if len(r.key) != 8 || len(r.value) != 32 {
				return nil, corrupt("storage directory statistics", 0)
			}
		case 5, 8, 11, 12:
			// These records do not add a stream owner. File extents are
			// validated after the complete descriptor inventory below.
		default:
			return nil, fmt.Errorf("storage filesystem record %d: %w", p.kind, filesystem.ErrUnsupported)
		}
	}
	allocated, logicalEnd := map[uint64]uint64{}, map[uint64]uint64{}
	for _, r := range records {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p := prefix(r.key)
		if p.kind == 4 {
			if _, exists := s.inodes[p.id]; !exists {
				return nil, corrupt("attribute without inode owner", 0)
			}
		}
		if p.kind != 8 {
			continue
		}
		if len(r.key) != 16 || len(r.value) != 24 {
			return nil, corrupt("storage file extent record", 0)
		}
		_, exists := s.streams[p.id]
		if !exists {
			return nil, corrupt("file extent without stream owner", 0)
		}
		length, logical := le.Uint64(r.value)&((1<<56)-1), le.Uint64(r.key[8:])
		address := le.Uint64(r.value[8:])
		if length == 0 || length%4096 != 0 || logical%4096 != 0 || logical < logicalEnd[p.id] || length > math.MaxUint64-logical {
			return nil, corrupt("file extent logical range", 0)
		}
		if le.Uint64(r.value)>>56 != 0 || le.Uint64(r.value[16:]) != 0 {
			return nil, fmt.Errorf("file extent storage flags/crypto: %w", filesystem.ErrUnsupported)
		}
		logicalEnd[p.id] = logical + length
		if address == 0 {
			continue // Sparse logical coverage does not own physical blocks.
		}
		count := length / 4096
		if address >= blocks || count > blocks-address || allocated[p.id] > math.MaxUint64-count {
			return nil, corrupt("file extent physical range", 0)
		}
		allocated[p.id] += count
		s.extents = append(s.extents, storageExtent{address, address + count, 1})
	}
	for id, stream := range s.streams {
		if allocated[id] != stream.allocated {
			return nil, fmt.Errorf("stream %d allocation: descriptor=%d extents=%d: %w", id, stream.allocated, allocated[id], filesystem.ErrCorrupt)
		}
		if stream.size > math.MaxUint64-4095 {
			return nil, corrupt("stream logical size overflow", 0)
		}
		coverage := max(logicalEnd[id], (stream.size+4095)&^uint64(4095))
		if stream.allocated > coverage/4096 || coverage-stream.allocated*4096 != stream.sparse {
			return nil, corrupt("stream sparse logical coverage", 0)
		}
		refs, present := s.references[id]
		// Native single-owner attribute streams can omit DSTREAM_ID. The
		// implicit count is one; shared streams require an explicit record.
		if present && refs != stream.owners || !present && stream.owners != 1 {
			return nil, fmt.Errorf("stream %d references: recorded=%d present=%t owners=%d allocated=%d: %w", id, refs, present, stream.owners, stream.allocated, filesystem.ErrCorrupt)
		}
	}
	for id := range s.references {
		if _, exists := s.streams[id]; !exists {
			return nil, corrupt("unowned data-stream reference", 0)
		}
	}
	for id, r := range s.inodes {
		if le.Uint16(r.value[80:])&0170000 != 0040000 && links[id] != le.Uint32(r.value[56:]) {
			return nil, corrupt("inode directory-reference count", 0)
		}
	}
	if len(super) < 216 || files != le.Uint64(super[184:]) || dirs != le.Uint64(super[192:]) || symlinks != le.Uint64(super[200:]) || others != le.Uint64(super[208:]) {
		return nil, corrupt("filesystem inode counters", 0)
	}
	return s, nil
}
