package apfs

import (
	"errors"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/internal/filesec"
)

func (m *mutation) security(id uint64) (value []byte, err error) {
	r, ok := m.fs.get(buildXattr(id, filesec.Attribute, nil, 2).key)
	if !ok {
		return nil, corrupt("missing flagged security attribute", 0)
	}
	v, err := m.attributeValue(r)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, v.Close()) }()
	if v.Size() < 44 || v.Size() > filesec.MaxSize {
		return nil, corrupt("security attribute size", 0)
	}
	value = make([]byte, v.Size())
	if err = block.ReadFull(v, value, 0); err != nil {
		return nil, err
	}
	return value, filesec.Validate(value)
}

func (m *mutation) inheritSecurity(parent uint64, directory bool) ([]byte, error) {
	r, err := m.inodeRecord(parent)
	if err != nil {
		return nil, err
	}
	if le.Uint64(r.value[48:])&0x40 == 0 {
		return nil, nil
	}
	value, err := m.security(parent)
	if err != nil {
		return nil, err
	}
	return filesec.Inherit(value, directory)
}
