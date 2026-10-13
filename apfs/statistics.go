package apfs

import (
	"context"
	"io/fs"
	"math"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// DirectoryStatistics reports the current native directory-stat profile. Origin
// directories own a stored record. Inherited directories share their origin's
// key and report computed subtree totals, with GenCount zero, as apfs.util -S
// does. TotalSize counts allocated data-fork bytes; aliases contribute once
// through their primary inode. Resource forks and attributes are excluded.
type DirectoryStatistics struct {
	Key, NumChildren, TotalSize, ChainedKey, GenCount uint64
	Origin                                            bool
}

func (v *Volume) statisticsInode(ctx context.Context, id uint64) (value []byte, err error) {
	err = v.records(ctx, id, 3, func(r record) error {
		if value != nil || len(r.key) != 8 || len(r.value) < 92 {
			return corrupt("statistics inode", 0)
		}
		value = r.value
		return nil
	})
	if err == nil && value == nil {
		err = fs.ErrNotExist
	}
	return value, err
}

func (v *Volume) statisticsRecord(ctx context.Context, key uint64) (result DirectoryStatistics, err error) {
	var found bool
	err = v.records(ctx, key, 10, func(r record) error {
		if found || len(r.key) != 8 || len(r.value) != 32 {
			return corrupt("directory statistics record", 0)
		}
		found = true
		result = DirectoryStatistics{Key: key, NumChildren: le.Uint64(r.value),
			TotalSize: le.Uint64(r.value[8:]), ChainedKey: le.Uint64(r.value[16:]),
			GenCount: le.Uint64(r.value[24:]), Origin: true}
		return nil
	})
	if err == nil && !found {
		err = corrupt("missing directory statistics record", 0)
	}
	return result, err
}

func (v *Volume) DirectoryStatistics(ctx context.Context, id uint64) (result DirectoryStatistics, err error) {
	value, err := v.statisticsInode(ctx, id)
	if err != nil {
		return result, err
	}
	if le.Uint16(value[80:])&0170000 != 0040000 {
		return result, fs.ErrInvalid
	}
	info, err := statisticsForInode(value)
	if err != nil {
		return result, err
	}
	if info.key == 0 {
		return result, fs.ErrNotExist
	}
	if info.origin {
		return v.statisticsRecord(ctx, info.key)
	}
	result.Key = info.key
	seen := map[uint64]bool{id: true}
	var walk func(uint64, int) error
	walk = func(parent uint64, depth int) error {
		if depth >= 256 {
			return filesystem.ErrLimit
		}
		return v.ReadDir(ctx, parent, func(entry filesystem.DirEntry) error {
			value, err := v.statisticsInode(ctx, entry.Object)
			if err != nil {
				return err
			}
			// A secondary alias contributes to its primary directory's group.
			if le.Uint64(value) != parent || seen[entry.Object] {
				return nil
			}
			if len(seen) >= 1<<20 {
				return filesystem.ErrLimit
			}
			seen[entry.Object] = true
			info, err := statisticsForInode(value)
			if err != nil {
				return err
			}
			count, allocated := uint64(1), info.allocated
			if info.origin {
				child, err := v.statisticsRecord(ctx, info.key)
				if err != nil {
					return err
				}
				if child.NumChildren == math.MaxUint64 {
					return corrupt("directory statistics child overflow", 0)
				}
				count, allocated = child.NumChildren+1, child.TotalSize
			}
			if count > math.MaxUint64-result.NumChildren || allocated > math.MaxUint64-result.TotalSize {
				return corrupt("directory statistics subtree overflow", 0)
			}
			result.NumChildren += count
			result.TotalSize += allocated
			if le.Uint16(value[80:])&0170000 == 0040000 && !info.origin {
				return walk(entry.Object, depth+1)
			}
			return nil
		})
	}
	err = walk(id, 0)
	return result, err
}
