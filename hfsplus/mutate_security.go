package hfsplus

import (
	"bytes"

	"github.com/deploymenttheory/go-apfs-v3/internal/filesec"
)

func (m *mutation) security(id uint32) ([]byte, error) {
	records, err := m.attributeRecords(id)
	if err != nil {
		return nil, err
	}
	key := attributeKey(id, filesec.Attribute)
	var descriptor []byte
	continuations := map[uint32][]byte{}
	for _, r := range records {
		if !bytes.Equal(r.key[12:], key[12:]) {
			continue
		}
		switch be.Uint32(r.value) {
		case 0x10:
			size := be.Uint32(r.value[12:])
			if size > filesec.MaxSize || uint64(size)+16 > uint64(len(r.value)) {
				return nil, bad("inline security size")
			}
			value := bytes.Clone(r.value[16 : 16+size])
			return value, filesec.Validate(value)
		case 0x20:
			descriptor = r.value[8:]
		case 0x30:
			continuations[be.Uint32(r.key[8:])] = r.value[8:]
		}
	}
	if descriptor == nil || be.Uint64(descriptor) < 44 || be.Uint64(descriptor) > filesec.MaxSize {
		return nil, bad("missing or oversized flagged security attribute")
	}
	f, err := resolveFork(m.ctx, m.disk, m.v.BlockSize, m.v.BlockCount, descriptor,
		func() (map[uint32][]byte, error) { return continuations, nil })
	if err != nil {
		return nil, err
	}
	value := make([]byte, be.Uint64(descriptor))
	if err = f.read(value, 0); err != nil {
		return nil, err
	}
	return value, filesec.Validate(value)
}

func (m *mutation) inheritSecurity(parent *catalogItem, directory bool) ([]byte, error) {
	if be.Uint16(parent.value[2:])&8 == 0 {
		return nil, nil
	}
	value, err := m.security(parent.id())
	if err != nil {
		return nil, err
	}
	return filesec.Inherit(value, directory)
}
