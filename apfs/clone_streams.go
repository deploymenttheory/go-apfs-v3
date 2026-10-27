package apfs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

type capturedCloneStream struct {
	object uint64
	name   string
	token  string
}

type cloneExtentEvent struct {
	at    uint64
	token string
	start bool
}

// CloneStreams inventories one captured subtree, independently of file bytes.
// Exact complete physical maps establish a whole-stream group. Any overlap
// between different maps is recorded as partial, never advertised as preserved
// whole-stream sharing. Descriptor-less private_id hints establish no ownership.
// This explicit capture operation leaves ordinary Stat/read admission unchanged.
func (v *Volume) CloneStreams(ctx context.Context, root uint64) (map[uint64]filesystem.CloneStreams, error) {
	var streams []capturedCloneStream
	var events []cloneExtentEvent
	maps := map[string]bool{}
	seen := map[uint64]bool{}
	entries, metadataBytes := 0, 0
	collect := func(object, id, size uint64, name string) error {
		metadataBytes += 512 + len(name)
		if metadataBytes > 64<<20 {
			return filesystem.ErrLimit
		}
		if id == 0 || id > objectMask || size > 1<<40 {
			return corrupt("captured clone stream descriptor", 0)
		}
		if size == 0 {
			// An actual empty descriptor can still have several stream owners.
			// Unlike an empty extent map or a private-ID hint, its shared stream
			// ID establishes explicit lineage without implying physical storage.
			digest := sha256.Sum256([]byte(fmt.Sprintf("APFS empty stream identity:%s:%d:%d:%d:%s", v.UUID, v.xid, id, len(name), name)))
			streams = append(streams, capturedCloneStream{object, name, hex.EncodeToString(digest[:])})
			return nil
		}
		hash := sha256.New()
		_, _ = fmt.Fprintf(hash, "APFS stream identity:%s:%d:%d:%s:%d:", v.UUID, v.xid, len(name), name, size)
		var ranges [][2]uint64
		var end uint64
		var previous []byte
		flush := func() {
			if previous != nil {
				_, _ = hash.Write(previous)
			}
		}
		err := v.records(ctx, id, 8, func(record record) error {
			metadataBytes += 192
			if metadataBytes > 64<<20 {
				return filesystem.ErrLimit
			}
			if len(record.key) != 16 || len(record.value) != 24 {
				return corrupt("captured clone extent record", 0)
			}
			logical, flags, physical := le.Uint64(record.key[8:]), le.Uint64(record.value), le.Uint64(record.value[8:])
			length, blockSize := flags&0x00ffffffffffffff, uint64(v.container.BlockSize)
			if logical != end || length == 0 || length%blockSize != 0 || logical%blockSize != 0 || length > (1<<40)-logical || physical >= v.container.BlockCount || physical != 0 && length/blockSize > v.container.BlockCount-physical {
				return corrupt("captured clone extent geometry", 0)
			}
			if flags>>56 != 0 && (flags>>56 != 1 || !v.Encrypted && !v.decryptedSnapshot || v.Flags&8 == 0) {
				return filesystem.ErrUnsupported
			}
			end += length
			if physical != 0 {
				ranges = append(ranges, [2]uint64{physical, physical + length/blockSize})
			}
			// Normalize adjacent extents, so a harmless record boundary does not
			// turn one complete native map into a partial-sharing observation.
			crypto := le.Uint64(record.value[16:])
			if previous != nil && le.Uint64(previous[24:]) == flags>>56 && le.Uint64(previous[32:]) == crypto && ((physical == 0 && le.Uint64(previous[16:]) == 0) || physical != 0 && le.Uint64(previous[16:]) != 0 && le.Uint64(previous[16:])+le.Uint64(previous[8:])/blockSize == physical) {
				le.PutUint64(previous[8:], le.Uint64(previous[8:])+length)
			} else {
				flush()
				previous = make([]byte, 40)
				for i, value := range []uint64{logical, length, physical, flags >> 56, crypto} {
					le.PutUint64(previous[i*8:], value)
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		if end < size {
			return corrupt("captured clone extent coverage", 0)
		}
		if len(ranges) == 0 {
			return nil // Holes alone have no shared physical ownership.
		}
		flush()
		token := hex.EncodeToString(hash.Sum(nil))
		streams = append(streams, capturedCloneStream{object, name, token})
		if !maps[token] {
			maps[token] = true
			for _, extent := range ranges {
				events = append(events, cloneExtentEvent{extent[0], token, true}, cloneExtentEvent{extent[1], token, false})
			}
		}
		return nil
	}
	var visit func(uint64, int) error
	visit = func(id uint64, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries++
		if entries > 100000 || depth > 256 {
			return filesystem.ErrLimit
		}
		if seen[id] {
			return nil // Hard-link names do not add another stream owner.
		}
		seen[id] = true
		inode, err := v.inode(ctx, id)
		if err != nil {
			return err
		}
		switch inode.node.Metadata.Mode.Value & 0170000 {
		case 0040000:
			return v.ReadDir(ctx, id, func(entry filesystem.DirEntry) error { return visit(entry.Object, depth+1) })
		case 0100000:
		default:
			return nil
		}
		var dataID uint64
		err = v.records(ctx, id, 3, func(record record) error {
			var err error
			dataID, err = inodeDataStreamID(record.value)
			return err
		})
		if err != nil {
			return err
		}
		if dataID != 0 {
			if err := collect(id, dataID, inode.streamSize, ""); err != nil {
				return err
			}
		}
		return v.attributes(ctx, id, func(name string, record record) error {
			if len(record.value) < 4 {
				return corrupt("captured clone attribute", 0)
			}
			flags := le.Uint16(record.value)
			if flags&^uint16(0x1f) != 0 || flags&3 != 1 && flags&3 != 2 {
				return filesystem.ErrUnsupported
			}
			if flags&3 == 2 {
				return nil
			}
			if len(record.value) != 52 {
				return corrupt("captured clone attribute stream", 0)
			}
			return collect(id, le.Uint64(record.value[4:]), le.Uint64(record.value[12:]), name)
		})
	}
	if err := visit(root, 0); err != nil {
		return nil, err
	}
	partial := partialCloneMaps(events)
	groups := map[string]int{}
	for _, stream := range streams {
		groups[stream.token]++
	}
	result := map[uint64]filesystem.CloneStreams{}
	for _, stream := range streams {
		if !partial[stream.token] && groups[stream.token] < 2 {
			continue
		}
		clones := result[stream.object]
		if partial[stream.token] {
			clones.Partial = append(clones.Partial, stream.name)
		} else if stream.name == "" {
			clones.Data = stream.token
		} else {
			if clones.Attributes == nil {
				clones.Attributes = map[string]string{}
			}
			clones.Attributes[stream.name] = stream.token
		}
		result[stream.object] = clones
	}
	for id, clones := range result {
		sort.Strings(clones.Partial)
		result[id] = clones
	}
	return result, nil
}

// Sweep metadata ranges without a per-block ownership map or pairwise stream
// comparison. Each map becomes partial at most once, even for many overlaps.
func partialCloneMaps(events []cloneExtentEvent) map[string]bool {
	sort.Slice(events, func(i, j int) bool {
		if events[i].at != events[j].at {
			return events[i].at < events[j].at
		}
		return !events[i].start && events[j].start
	})
	partial, active, unmarked := map[string]bool{}, map[string]int{}, map[string]bool{}
	for _, event := range events {
		if !event.start {
			active[event.token]--
			if active[event.token] == 0 {
				delete(active, event.token)
				delete(unmarked, event.token)
			}
			continue
		}
		if len(active) > 1 || len(active) == 1 && active[event.token] == 0 {
			partial[event.token] = true
			for token := range unmarked {
				partial[token] = true
				delete(unmarked, token)
			}
		}
		active[event.token]++
		if !partial[event.token] {
			unmarked[event.token] = true
		}
	}
	return partial
}
