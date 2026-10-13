package filesec

import (
	"context"
	"errors"
	"io/fs"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// Read retains the exact filesec bytes from a logical filesystem. Native xattr
// enumeration can hide this value, so ACL policy requests it explicitly.
func Read(ctx context.Context, reader filesystem.Reader, id uint64) (data []byte, err error) {
	value, err := reader.OpenAttribute(ctx, id, Attribute)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, value.Close()) }()
	if value.Size() < 44 || value.Size() > MaxSize {
		return nil, filesystem.ErrCorrupt
	}
	data = make([]byte, value.Size())
	if err = block.ReadFull(value, data, 0); err != nil {
		return nil, err
	}
	return data, Validate(data)
}
