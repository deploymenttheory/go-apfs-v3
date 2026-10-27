package apfs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

func TestVolumeConversionRetainsIdentitySharedExtentsAndLaterEdits(t *testing.T) {
	ctx := context.Background()
	disk := newCloneMutationDisk(cloneMutationImage(t))
	before, err := openMutation(ctx, disk)
	if err != nil {
		t.Fatal(err)
	}
	id := before.v.UUID
	want := before.fs.all()
	var extents []buildRecord
	for _, record := range want {
		if prefix(record.key).kind == 8 {
			extents = append(extents, record)
		}
	}
	owner, err := UnlockMutation(ctx, disk)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	password := []byte("public-conversion-password-sentinel")
	report, err := ConvertVolumeEncryption(ctx, owner, id, EncryptionConversion{Encrypt: true, Password: password}, builtClock)
	if err != nil {
		t.Fatal("encrypt existing volume", err)
	}
	if report.VolumeID != id || !report.Encryption.Completed || !report.Encryption.Encrypted || report.Encryption.BeforeEncrypted {
		t.Fatal("incorrect conversion report", report)
	}
	encoded, err := json.Marshal(report)
	if err != nil || bytes.Contains(encoded, password) {
		t.Fatal("report exposed credential", err)
	}
	for _, r := range before.ownership.data {
		if bytes.Contains(disk.data[r.start*4096:r.end*4096], cloneData) {
			t.Fatal("converted allocated data remains plaintext")
		}
	}
	for _, r := range before.vmap.all() {
		address := le.Uint64(r.value[8:])
		if bytes.Contains(disk.data[address*4096:(address+1)*4096], []byte("org.go-apfs.inline")) {
			t.Fatal("retired current filesystem metadata remains plaintext")
		}
	}
	c, err := Open(disk)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Volumes[0].Unlock(ctx, []byte("wrong")); !errors.Is(err, filesystem.ErrAuthentication) {
		t.Fatal("wrong password accepted", err)
	}
	unlocked, err := c.Volumes[0].Unlock(ctx, password)
	if err != nil {
		t.Fatal("fresh keybag unlock", err)
	}
	defer unlocked.Close()
	m, err := openMutation(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range extents {
		now, ok := m.fs.get(r.key)
		if !ok || !bytes.Equal(now.value[8:16], r.value[8:16]) || le.Uint64(now.value)&((1<<56)-1) != le.Uint64(r.value) {
			t.Fatal("conversion relocated or detached shared data", r.key)
		}
	}
	if _, err := ConvertVolumeEncryption(ctx, owner, id, EncryptionConversion{}, builtClock); err != nil {
		t.Fatal("decrypt existing volume", err)
	}
	after, err := openMutation(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	if after.v.UUID != id || after.v.Encrypted || !reflect.DeepEqual(after.fs.all(), want) {
		t.Fatal("round trip changed inode identities, metadata, forks or stream ownership")
	}
	if _, err := ModifyVolume(ctx, owner, id, []Change{{Path: "/clone-a", Data: bytes.NewReader([]byte("independent later edit"))}}, builtClock); err != nil {
		t.Fatal("edit after completed decryption", err)
	}
	if got := cloneContents(t, disk, "/source", ""); !bytes.Equal(got, cloneData) {
		t.Fatal("converted clone mutation changed shared survivor")
	}
	if err := ValidateMutation(ctx, owner); err != nil {
		t.Fatal(err)
	}
}

func TestVolumeConversionRejectsInvalidTransitionsBeforeWriting(t *testing.T) {
	for _, conversion := range []EncryptionConversion{{}, {Encrypt: true}, {Password: []byte("unexpected")}, {Encrypt: true, Password: make([]byte, 4097)}} {
		disk := newCloneMutationDisk(builtContainer(t, nil))
		owner, err := UnlockMutation(context.Background(), disk)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ConvertVolumeEncryption(context.Background(), owner, "", conversion, builtClock)
		_ = owner.Close()
		if !errors.Is(err, fs.ErrInvalid) || disk.writes != 0 {
			t.Fatal("invalid transition wrote scratch", err, disk.writes)
		}
	}
}

func TestVolumeConversionPropagatesFailedStorageWrites(t *testing.T) {
	ctx := context.Background()
	initial := cloneMutationImage(t)
	disk := newCloneMutationDisk(initial)
	owner, err := UnlockMutation(ctx, disk)
	if err != nil {
		t.Fatal(err)
	}
	disk.failAt = 2 // Fail after the private transaction's first real write.
	_, err = ConvertVolumeEncryption(ctx, owner, "", EncryptionConversion{Encrypt: true, Password: []byte("public-failure-password")}, builtClock)
	_ = owner.Close()
	if !errors.Is(err, io.ErrClosedPipe) || disk.writes != 2 {
		t.Fatal("storage failure lost", err, disk.writes)
	}
}

func TestCompletedDecryptionIsDeterministicAcrossMetadataTreeGrowth(t *testing.T) {
	ctx := context.Background()
	disk := newCloneMutationDisk(builtContainer(t, nil))
	var changes []Change
	for i := range 200 {
		changes = append(changes, Change{Path: fmt.Sprintf("/file-%03d", i), Data: bytes.NewReader(nil)})
	}
	if _, err := Modify(ctx, disk, changes, builtClock); err != nil {
		t.Fatal(err)
	}
	owner, err := UnlockMutation(ctx, disk)
	if err != nil {
		t.Fatal(err)
	}
	password := []byte("public-deterministic-decryption-password")
	if _, err = ConvertVolumeEncryption(ctx, owner, "", EncryptionConversion{Encrypt: true, Password: password}, builtClock); err != nil {
		t.Fatal(err)
	}
	_ = owner.Close()
	var previous []byte
	for range 3 {
		copy := newCloneMutationDisk(disk.data)
		unlocked, err := UnlockMutation(ctx, copy, VolumeCredential{Password: password})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = ConvertVolumeEncryption(ctx, unlocked, "", EncryptionConversion{}, builtClock); err != nil {
			t.Fatal(err)
		}
		_ = unlocked.Close()
		if previous != nil && !bytes.Equal(previous, copy.data) {
			t.Fatal("completed decryption changed bytes for identical source and clock")
		}
		previous = copy.data
	}
}
