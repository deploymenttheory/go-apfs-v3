package acceptance_test

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/inspect"
	"github.com/deploymenttheory/go-apfs-v3/pack"
	"github.com/deploymenttheory/go-apfs-v3/session"
)

func TestEncryptedConstructionPreservesNativeCloneAndPeerContents(t *testing.T) {
	cases, _ := loadCorpus(t)
	recipe := recipesByName(t)["encrypted-volumes"]
	const imagePassword = "public-construction-envelope"
	registerOutputPassword(t, "encrypted-construction.image", imagePassword)
	seen := map[string]bool{}
	for _, source := range cases {
		if source.Recipe != "encrypted-volumes" || source.Stage != "clone-shared" {
			continue
		}
		seen[fmt.Sprintf("%d/%s", source.Producer, source.Profile)] = true
		t.Run(fmt.Sprintf("macos-%d/%s", source.Producer, source.Profile), func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			storageImageUnchanged(t, source)
			image := openImage(t, ctx, source, recipe)
			defer closeFixture(t, image)
			report, err := inspect.Image(ctx, image)
			if err != nil {
				t.Fatal(err)
			}
			var volumes []apfs.VolumeSpec
			for _, observed := range source.Observation.Volumes {
				reader, closeReader := openVolume(t, ctx, report, observed, volumeName(observed), recipe, image)
				if closeReader != nil {
					defer closeReader()
				}
				root, err := filesystem.LookupExact(ctx, reader, "Fixture")
				if err != nil {
					t.Fatal(err)
				}
				volume := apfs.VolumeSpec{Reader: buildRoot{reader, root}, Name: volumeName(observed), CaseSensitive: observed.APFS.CaseSensitive, Reserve: observed.APFS.ReserveBytes, Quota: observed.APFS.QuotaBytes}
				if observed.APFS.Encrypted {
					volume.Encryption = &apfs.VolumeEncryptionOptions{Password: []byte(recipe.Passwords[observed.APFS.Password])}
				}
				volumes = append(volumes, volume)
			}
			empty, err := session.Create(ctx, filepath.Join(t.TempDir(), "empty-peer"), session.Options{Names: filesystem.NameRules{Format: "APFS", CaseSensitive: source.Profile == "apfsx", NormalizationInsensitive: true}, Time: &fixedClock})
			if err != nil {
				t.Fatal(err)
			}
			defer closeFixture(t, empty)
			volumes = append(volumes, apfs.VolumeSpec{Reader: empty, Name: "Fresh Encrypted Peer", CaseSensitive: source.Profile == "apfsx", Encryption: &apfs.VolumeEncryptionOptions{Password: []byte(recipe.Passwords["peer"])}})
			for _, cipher := range []string{"", "AES-128", "AES-256"} {
				options := pack.ContainerOptions{APFS: apfs.ContainerBuildOptions{Time: fixedClock, Capacity: 1536 << 20}, Format: "UDZO", FileCompression: "preserve"}
				var password []byte
				if cipher != "" {
					bits := uint32(128)
					if cipher == "AES-256" {
						bits = 256
					}
					password = []byte(imagePassword)
					options.Encryption = &diskimage.EncryptionOptions{KeyBits: bits, Password: password}
				}
				suffix := "plain"
				if cipher != "" {
					suffix = strings.ToLower(cipher)
				}
				name := outputName(source, "create-encrypted."+suffix+".UDZO.dmg")
				output := produceTwice(t, name, false, func(path string) error {
					result, err := pack.CreateContainer(ctx, path, volumes, options)
					if err == nil && len(result.VolumeEncryption) != 2 {
						return fmt.Errorf("encrypted volume report omitted a Disk user")
					}
					return err
				})
				checkConstructedContainer(t, ctx, output, source, source.Observation.Volumes, volumes, options.APFS, password)
				ref := ""
				if cipher != "" {
					ref = "encrypted-construction.image"
				}
				recordOutput(t, schema.Output{Name: name, File: filepath.Base(output), Operation: "create-encrypted", Format: "UDZO", Encrypted: cipher != "", Password: ref, Source: caseRef(source), Expect: schema.Expectation{Subtree: "Fixture", Volume: "Primary", Continuation: true, Container: &schema.ContainerExpectation{CapacityBytes: options.APFS.Capacity, EmptyVolumes: []string{"Fresh Encrypted Peer"}, EncryptedVolumes: map[string]string{"Primary": "primary", "Fresh Encrypted Peer": "peer"}, ImageCipher: cipher}}})
			}
		})
	}
	for _, producer := range schema.Producers {
		for _, profile := range []string{"apfs", "apfsx"} {
			if !seen[fmt.Sprintf("%d/%s", producer, profile)] {
				t.Fatalf("missing native encrypted construction source %d/%s", producer, profile)
			}
		}
	}
}
