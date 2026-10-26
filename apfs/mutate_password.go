package apfs

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	storagecrypto "github.com/deploymenttheory/go-apfs-v3/internal/crypto"
)

// PasswordChange selects one crypto user. Empty CryptoUser selects the single
// admitted native Disk user; otherwise the exact UUID is required. Both password
// buffers are borrowed for the operation only. Non-nil empty passwords are valid.
type PasswordChange struct {
	CryptoUser  string
	OldPassword []byte `json:"-"`
	NewPassword []byte `json:"-"`
}

type PasswordChangeReport struct {
	ChangeReport
	CryptoUser string `json:"cryptoUser"`
}

// ChangeVolumePassword updates the selected user's wrapped key in an unpublished
// authenticated MutationSource. New salts use secure randomness; the data key,
// volume/user identities, filesystem and all peers retain their existing state.
func ChangeVolumePassword(ctx context.Context, disk MutableSource, volumeUUID string, change PasswordChange, when time.Time) (PasswordChangeReport, error) {
	var report PasswordChangeReport
	if disk == nil || change.OldPassword == nil || change.NewPassword == nil || when.IsZero() || when.Nanosecond() != 0 {
		return report, fs.ErrInvalid
	}
	stamp, err := buildTime(when)
	if err != nil {
		return report, err
	}
	m, err := openMutationVolume(ctx, disk, volumeUUID)
	if err != nil {
		return report, err
	}
	if !m.v.Encrypted || volumeUUID == "" && len(m.c.Volumes) > 1 {
		return report, fs.ErrInvalid
	}
	if change.CryptoUser != "" && change.CryptoUser != m.v.UUID {
		return report, fs.ErrNotExist
	}
	if err := m.changePassword(change); err != nil {
		return report, err
	}
	if err := m.commit(stamp); err != nil {
		return report, err
	}
	// Validate the new credential through a fresh keybag/root open, not merely
	// the key schedule retained by the mutation source.
	changed, err := Open(disk)
	if err != nil {
		return report, err
	}
	for i := range changed.Volumes {
		if changed.Volumes[i].UUID == m.v.UUID {
			view, err := changed.Volumes[i].Unlock(ctx, change.NewPassword)
			if err != nil {
				return report, err
			}
			if err := view.Close(); err != nil {
				return report, err
			}
			return PasswordChangeReport{ChangeReport: ChangeReport{VolumeID: m.v.UUID, FreeBlocks: m.space.free, Transaction: m.xid}, CryptoUser: m.v.UUID}, nil
		}
	}
	return report, corrupt("password change lost selected volume", 0)
}

func (m *mutation) changePassword(change PasswordChange) error {
	c := m.c
	outer, err := c.keybagObject(m.ctx, c.keylockerStart, c.keylockerCount, c.id, 0x6b657973)
	if err != nil {
		return err
	}
	entries, err := decodeKeybagEntries(outer, int64(c.keylockerStart)*4096)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.id != m.v.id || entry.tag != 3 {
			continue
		}
		start, count := le.Uint64(entry.data), le.Uint64(entry.data[8:])
		bag, err := c.keybagObject(m.ctx, start, count, m.v.id, 0x72656373)
		if err != nil {
			return err
		}
		records, err := decodeKeybagEntries(bag, int64(start)*4096)
		if err != nil {
			return err
		}
		found := false
		for _, record := range records {
			if record.tag != 3 || record.id != m.v.id {
				continue
			}
			wrapped, err := rewrapPasswordRecord(m.ctx, record.data, change.OldPassword, change.NewPassword)
			if err != nil {
				return err
			}
			if len(wrapped) != len(record.data) {
				return fmt.Errorf("password key record growth: %w", filesystem.ErrUnsupported)
			}
			copy(record.data, wrapped) // Other entries and all reserved bytes stay intact.
			found = true
		}
		if !found {
			return fs.ErrNotExist
		}
		address, err := m.writeKeybag(bag, m.v.id, start, count)
		if err != nil {
			return err
		}
		le.PutUint64(entry.data, address)
		address, err = m.writeKeybag(outer, c.id, c.keylockerStart, c.keylockerCount)
		if err != nil {
			return err
		}
		le.PutUint64(m.nx[1296:], address)
		return nil
	}
	return corrupt("selected volume keybag is missing", 0)
}

func (m *mutation) writeKeybag(data []byte, id [16]byte, previous, count uint64) (uint64, error) {
	address, allocated, err := m.space.allocate(count)
	if err != nil {
		return 0, err
	}
	if allocated != count {
		return 0, filesystem.ErrLimit
	}
	// Native keybag objects have OID zero, distinct from their physical address.
	sealMutationObject(data, le.Uint64(data[8:]), m.xid, le.Uint32(data[24:]), le.Uint32(data[28:]))
	key := append(append([]byte(nil), id[:]...), id[:]...)
	defer clear(key)
	x, err := storagecrypto.NewXTS(key)
	if err != nil {
		return 0, err
	}
	if err := x.Encrypt(data, data, address*8); err != nil {
		return 0, err
	}
	if err := m.write(data, address*4096); err != nil {
		return 0, err
	}
	if err := m.space.retire(false, previous, count); err != nil {
		return 0, err
	}
	return address, nil
}

func rewrapPasswordRecord(ctx context.Context, data, oldPassword, newPassword []byte) ([]byte, error) {
	record, err := parseKeyRecord(data, true)
	if err != nil {
		return nil, err
	}
	old, err := storagecrypto.PBKDF2(ctx, sha256.New, oldPassword, record.salt, record.iterations, 32)
	defer clear(old)
	if err != nil {
		return nil, err
	}
	kek, err := storagecrypto.Unwrap(old, record.wrapped)
	defer clear(kek)
	if errors.Is(err, storagecrypto.ErrIntegrity) {
		return nil, filesystem.ErrAuthentication
	}
	if err != nil {
		return nil, err
	}
	salt, integritySalt := make([]byte, 16), make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(integritySalt); err != nil {
		return nil, err
	}
	derived, err := storagecrypto.PBKDF2(ctx, sha256.New, newPassword, salt, record.iterations, 32)
	defer clear(derived)
	if err != nil {
		return nil, err
	}
	wrapped, err := storagecrypto.Wrap(derived, kek)
	if err != nil {
		return nil, err
	}
	record.wrapped, record.salt = wrapped, salt
	return encodeKeyRecord(record, integritySalt), ctx.Err()
}

func encodeDER(tag byte, value []byte) []byte {
	header := []byte{tag}
	if len(value) < 128 {
		header = append(header, byte(len(value)))
	} else {
		var raw [8]byte
		binary.BigEndian.PutUint64(raw[:], uint64(len(value)))
		i := 0
		for raw[i] == 0 {
			i++
		}
		header = append(header, 0x80|byte(len(raw)-i))
		header = append(header, raw[i:]...)
	}
	return append(header, value...)
}
