//go:build native && darwin

package native

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/pack"
	"github.com/deploymenttheory/go-apfs-v3/session"
)

type nativeConstructionRoot struct {
	filesystem.Reader
	id uint64
}

func (r nativeConstructionRoot) Root() uint64 { return r.id }

func TestEncryptedConstructionWithApple(t *testing.T) {
	v := newVerifier(t)
	ctx := context.Background()
	type result struct {
		Name  string `json:"name"`
		Error string `json:"error,omitempty"`
	}
	var results []result
	record := func(name string, err error) bool {
		r := result{Name: name}
		if err != nil {
			r.Error = err.Error()
			t.Error(name, err)
		}
		results = append(results, r)
		return err == nil
	}
	defer func() {
		data, _ := json.MarshalIndent(results, "", "  ")
		if err := os.WriteFile(filepath.Join(v.Work, "result.json"), data, 0600); err != nil {
			t.Error(err)
		}
	}()
	for _, profile := range []string{"apfs", "apfsx"} {
		source := schema.CaseRef{Producer: v.Major, Recipe: "encrypted-volumes", Profile: profile, Stage: "clone-shared"}
		k := v.Cases[CaseKey(source)]
		recipe := v.Recipes[source.Recipe]
		lease, err := v.Corpus.AcquireImage(ctx, k)
		if !record(profile+" input", err) {
			continue
		}
		image, err := diskimage.Open(lease.Path())
		if !record(profile+" image", err) {
			continue
		}
		part, err := image.Partition(0)
		if err != nil {
			t.Fatal(err)
		}
		container, err := apfs.Open(part)
		if err != nil {
			t.Fatal(err)
		}
		var volumes []apfs.VolumeSpec
		for i := range container.Volumes {
			volume := &container.Volumes[i]
			reader := volume
			var encryption *apfs.VolumeEncryptionOptions
			if volume.Encrypted {
				password := []byte(recipe.Passwords["primary"])
				reader, err = volume.Unlock(ctx, password)
				if err != nil {
					t.Fatal(err)
				}
				defer reader.Close()
				encryption = &apfs.VolumeEncryptionOptions{Password: password}
			}
			root, err := filesystem.LookupExact(ctx, reader, "Fixture")
			if err != nil {
				t.Fatal(err)
			}
			volumes = append(volumes, apfs.VolumeSpec{Reader: nativeConstructionRoot{reader, root}, Name: volume.Name, CaseSensitive: volume.CaseSensitive, Reserve: int64(volume.ReserveBlocks) * 4096, Quota: int64(volume.QuotaBlocks) * 4096, Encryption: encryption})
		}
		work := filepath.Join(v.Work, profile)
		if err := os.MkdirAll(work, 0700); err != nil {
			t.Fatal(err)
		}
		clock := time.Date(2025, 6, 7, 8, 9, 10, 0, time.UTC)
		empty, err := session.Create(ctx, filepath.Join(work, "empty"), session.Options{Names: filesystem.NameRules{Format: "APFS", CaseSensitive: profile == "apfsx", NormalizationInsensitive: true}, Time: &clock})
		if err != nil {
			t.Fatal(err)
		}
		defer empty.Close()
		volumes = append(volumes, apfs.VolumeSpec{Reader: empty, Name: "Fresh Encrypted Peer", CaseSensitive: profile == "apfsx", Encryption: &apfs.VolumeEncryptionOptions{Password: []byte(recipe.Passwords["peer"])}})
		output := filepath.Join(work, "built.dmg")
		_, err = pack.CreateContainer(ctx, output, volumes, pack.ContainerOptions{Format: "UDZO", APFS: apfs.ContainerBuildOptions{Time: clock, Capacity: 1536 << 20}})
		if !record(profile+" build", err) {
			continue
		}
		out := encryptedConstructionOutput(profile, "")
		out.Source = source
		out.Name = "native-encrypted-construction-" + profile
		out.File = filepath.Base(output)
		pair := Paired{Name: out.Name, Output: out, Primary: "darwin", ByHost: map[string]schema.Output{"darwin": out}, Dirs: map[string]string{"darwin": work}, Passwords: recipe.Passwords}
		differences, err := v.VerifyOutput(ctx, pair)
		if err == nil && len(differences) != 0 {
			err = fmt.Errorf("native differences: %v", differences)
		}
		if record(profile+" native checker and complete readback", err) {
			_, err = v.Continuation(ctx, pair, schemaCase{recipe: recipe})
			record(profile+" native Go native continued allocation", err)
		}
		_ = image.Close()
		record(profile+" source release", lease.Release(nil))
	}
}
