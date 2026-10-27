package apfs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

func TestEncryptedConstructionPreservesCloneStreamsAndOwnsKeyLifetime(t *testing.T) {
	ctx := context.Background()
	source, _ := declaredCloneInput(t)
	password := []byte("public-build-password")
	options := BuildOptions{Name: "Encrypted", Time: builtClock, Capacity: 8 << 20, Encryption: &VolumeEncryptionOptions{Password: password}}
	plan, err := Plan(ctx, source, options)
	if err != nil {
		t.Fatal(err)
	}
	clear(password)
	var raw, again bytes.Buffer
	if err = plan.Write(ctx, &raw); err != nil {
		t.Fatal(err)
	}
	if err = plan.Write(ctx, &again); err != nil || !bytes.Equal(raw.Bytes(), again.Bytes()) {
		t.Fatal("one plan changed its key material during write", err)
	}
	if bytes.Contains(raw.Bytes(), cloneData) || bytes.Contains(raw.Bytes(), []byte("org.go-apfs.large")) {
		t.Fatal("plaintext stream or filesystem metadata was published")
	}
	c, err := Open(bytes.NewReader(raw.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Volumes[0].Encrypted || c.Volumes[0].Flags != 8 {
		t.Fatal("volume is not software encrypted")
	}
	if _, err = c.Volumes[0].Stat(ctx, 2); !errors.Is(err, filesystem.ErrAuthentication) {
		t.Fatal("locked volume readable", err)
	}
	if view, err := c.Volumes[0].Unlock(ctx, []byte("wrong")); !errors.Is(err, filesystem.ErrAuthentication) {
		if view != nil {
			_ = view.Close()
		}
		t.Fatal("wrong password accepted", err)
	}
	unlocked, err := c.Volumes[0].Unlock(ctx, []byte("public-build-password"))
	if err != nil {
		t.Fatal(err)
	}
	defer unlocked.Close()
	for _, path := range []string{"/source", "/clone", "/alias", "/independent"} {
		id, err := filesystem.LookupExact(ctx, unlocked, path)
		if err != nil {
			t.Fatal(err)
		}
		for _, attribute := range []string{"", filesystem.ResourceFork, "org.go-apfs.large"} {
			var value filesystem.Value
			want := cloneData
			if attribute == "" {
				value, err = unlocked.OpenData(ctx, id)
			} else {
				value, err = unlocked.OpenAttribute(ctx, id, attribute)
				if attribute == filesystem.ResourceFork {
					want = cloneFork
				} else {
					want = cloneAttribute
				}
			}
			if err != nil {
				t.Fatal(path, attribute, err)
			}
			data, err := io.ReadAll(io.NewSectionReader(value, 0, value.Size()))
			_ = value.Close()
			if err != nil || !bytes.Equal(data, want) {
				t.Fatal(path, attribute, "readback", err)
			}
		}
	}
	disk := newCloneMutationDisk(raw.Bytes())
	owner, err := UnlockMutation(ctx, disk, VolumeCredential{VolumeUUID: c.Volumes[0].UUID, Password: []byte("public-build-password")})
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if err = ValidateMutation(ctx, owner); err != nil {
		t.Fatal("fresh encrypted ownership", err)
	}
	m, err := openMutationVolume(ctx, owner, c.Volumes[0].UUID)
	if err != nil {
		t.Fatal(err)
	}
	left, _ := m.lookupEntry("/source")
	right, _ := m.lookupEntry("/clone")
	a, _ := m.inodeRecord(left.id)
	b, _ := m.inodeRecord(right.id)
	if left.id == right.id || le.Uint64(a.value[8:]) != le.Uint64(b.value[8:]) {
		t.Fatal("encrypted clone sharing lost")
	}
	if _, err = ModifyVolume(ctx, owner, c.Volumes[0].UUID, []Change{{Path: "/clone", Data: bytes.NewReader([]byte("private encrypted edit"))}}, builtClock); err != nil {
		t.Fatal("fresh encrypted mutation", err)
	}
	if err = ValidateMutation(ctx, owner); err != nil {
		t.Fatal("post-edit encrypted ownership", err)
	}
	if err = plan.Close(); err != nil {
		t.Fatal(err)
	}
	if err = plan.Write(ctx, io.Discard); !errors.Is(err, fs.ErrClosed) {
		t.Fatal("closed plan retained writable keys", err)
	}
	if _, err = source.Stat(ctx, source.Root()); err != nil {
		t.Fatal("plan closed borrowed reader", err)
	}
}

func TestEncryptedPlansGenerateIndependentKeysAndOmitPasswordOptions(t *testing.T) {
	ctx := context.Background()
	source, _ := declaredCloneInput(t)
	password := []byte("public-credential-sentinel")
	options := BuildOptions{Name: "Fresh", Time: builtClock, Capacity: 8 << 20, ContainerUUID: [16]byte{1}, VolumeUUID: [16]byte{2}, Encryption: &VolumeEncryptionOptions{Password: password}}
	var previous []byte
	var previousKeyCheck []byte
	for range 2 {
		plan, err := Plan(ctx, source, options)
		if err != nil {
			t.Fatal(err)
		}
		var data bytes.Buffer
		if err := plan.Write(ctx, &data); err != nil {
			t.Fatal(err)
		}
		c, err := Open(bytes.NewReader(data.Bytes()))
		if err != nil {
			t.Fatal(err)
		}
		view, err := c.Volumes[0].Unlock(ctx, password)
		if err != nil {
			t.Fatal(err)
		}
		probe := make([]byte, 512)
		if err := view.keys.encrypt(probe, 0); err != nil {
			t.Fatal(err)
		}
		if previousKeyCheck != nil && bytes.Equal(previousKeyCheck, probe) {
			t.Fatal("fresh constructions reused the volume key")
		}
		previousKeyCheck = probe
		// The same explicit identities and input still produce different complete
		// ciphertext, and both independently authenticate and read successfully.
		if previous != nil && bytes.Equal(previous, data.Bytes()) {
			t.Fatal("fresh encrypted construction reused key material")
		}
		previous = append(previous[:0], data.Bytes()...)
		_ = view.Close()
		_ = plan.Close()
	}
	encoded, err := json.Marshal([]any{options, VolumeSpec{Encryption: options.Encryption}})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, password) || bytes.Contains(encoded, []byte("Password")) {
		t.Fatal("construction options exposed credentials")
	}
}

func TestEncryptedConstructionRefusesMissingCredentialsAndUnqualifiedRoles(t *testing.T) {
	source, _ := declaredCloneInput(t)
	for _, test := range []struct {
		encryption *VolumeEncryptionOptions
		role       uint16
		want       error
	}{
		{&VolumeEncryptionOptions{}, 0, fs.ErrInvalid},
		{&VolumeEncryptionOptions{Password: make([]byte, 4097)}, 0, fs.ErrInvalid},
		{&VolumeEncryptionOptions{Password: []byte("public")}, VolumeRoleData, filesystem.ErrUnsupported},
	} {
		_, err := PlanContainer(context.Background(), []VolumeSpec{{Reader: source, Name: "Refused", Encryption: test.encryption, Role: test.role}}, ContainerBuildOptions{Time: builtClock})
		if !errors.Is(err, test.want) {
			t.Fatal("invalid encrypted admission", err, test.want)
		}
	}
}
