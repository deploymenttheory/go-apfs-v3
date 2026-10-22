package main

// Read-only proof tool for a stored UDIF member in a complete ZIP archive.
// It reports hashes and structural metadata, never decoded firmware bytes.

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
)

func main() {
	if len(os.Args) != 3 {
		panic("usage: probe IPSW STORED_OS_MEMBER")
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		panic(err)
	}
	archiveHash := sha256.New()
	if _, err := io.Copy(archiveHash, f); err != nil {
		panic(err)
	}
	z, err := zip.NewReader(f, stat.Size())
	if err != nil {
		panic(err)
	}
	for _, member := range z.File {
		if member.Name != os.Args[2] {
			continue
		}
		if member.Method != zip.Store {
			panic("OS member is not stored")
		}
		offset, err := member.DataOffset()
		if err != nil {
			panic(err)
		}
		source := io.NewSectionReader(f, offset, int64(member.UncompressedSize64))
		image, err := diskimage.New(source)
		if err != nil {
			panic(fmt.Errorf("diskimage.New: %w", err))
		}
		defer image.Close()
		prefix := make([]byte, 4096)
		if _, err := io.ReadFull(io.NewSectionReader(image, 0, image.Size()), prefix); err != nil {
			panic(err)
		}
		partitions := make([]map[string]any, 0, len(image.Partitions))
		for _, p := range image.Partitions {
			partitions = append(partitions, map[string]any{"index": p.Index, "type": p.Type, "offset": p.Offset, "size": p.Size})
		}
		prefixDigest := sha256.Sum256(prefix)
		result := map[string]any{
			"archive_size":      stat.Size(),
			"archive_sha256":    hex.EncodeToString(archiveHash.Sum(nil)),
			"member":            member.Name,
			"member_offset":     offset,
			"member_size":       member.UncompressedSize64,
			"member_zip_method": member.Method,
			"member_zip_crc32":  fmt.Sprintf("%08x", member.CRC32),
			"format":            image.Format,
			"partition_map":     image.PartitionMap,
			"logical_size":      image.Size(),
			"partitions":        partitions,
			"prefix_bytes":      len(prefix),
			"prefix_sha256":     hex.EncodeToString(prefixDigest[:]),
		}
		if len(image.Partitions) == 1 {
			partition, err := image.Partition(image.Partitions[0].Index)
			if err != nil {
				result["apfs_error"] = err.Error()
			} else if container, err := apfs.Open(partition); err != nil {
				result["apfs_error"] = err.Error()
			} else {
				result["apfs_block_size"] = container.BlockSize
				result["apfs_volumes"] = len(container.Volumes)
			}
		}
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			panic(err)
		}
		return
	}
	panic("OS member not found")
}
