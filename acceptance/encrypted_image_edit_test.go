package acceptance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/native"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
	"github.com/deploymenttheory/go-apfs-v3/inspect"
)

func TestEncryptedImageEditsMatchAppleStates(t *testing.T) {
	cases, _ := loadCorpus(t)
	recipe := recipesByName(t)["encrypted-image-edits"]
	registerOutputPassword(t, "encrypted-image-edits.image", recipe.Passwords["image"])
	indexed := indexCases(cases)
	seen := map[string]bool{}
	for _, before := range cases {
		if before.Recipe != recipe.Name || !strings.HasPrefix(before.Stage, "before-aes") {
			continue
		}
		seen[fmt.Sprintf("%d/%s/%s", before.Producer, before.Profile, before.Stage)] = true
		t.Run(fmt.Sprintf("macos-%d/%s/%s", before.Producer, before.Profile, before.Stage), func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			after := indexed[stageKey(before.Producer, recipe.Name, before.Profile, strings.Replace(before.Stage, "before-", "after-", 1))]
			if before.Observation.Image.Encryption == nil || after.Observation == nil || after.Observation.Image.Encryption == nil {
				t.Fatal("missing independent native encrypted before/after controls")
			}
			bits := uint32(128)
			if before.Stage == "before-aes256" {
				bits = 256
			}
			if before.Observation.Image.Encryption.Cipher != fmt.Sprintf("AES-%d", bits) || after.Observation.Image.Encryption.Cipher != fmt.Sprintf("AES-%d", bits) {
				t.Fatal("native cipher does not match declared derivation")
			}
			password := []byte(recipe.Passwords["image"])
			partition := encryptedEditPartition(t, ctx, before, password)
			sourceHash, err := schema.FileDigest(fixtureImage(t, before))
			if err != nil {
				t.Fatal(err)
			}
			for _, policy := range []string{"preserve", "rekey", "remove"} {
				for _, format := range []string{"UDRO", "UDZO"} {
					options := imageedit.Options{Partition: partition, Time: fixedClock, Format: format, ImagePassword: password}
					outputPasswordBytes, passwordRef := password, "encrypted-image-edits.image"
					switch policy {
					case "rekey":
						outputPasswordBytes, passwordRef = []byte(outputPassword), "output"
						options.Encryption = &diskimage.EncryptionOptions{Password: outputPasswordBytes}
					case "remove":
						outputPasswordBytes, passwordRef = nil, ""
						options.Decrypt = true
					}
					name := outputName(before, "edit."+policy+"."+format+".dmg")
					path := produceTwice(t, name, policy == "remove", func(path string) error {
						var report imageedit.Report
						var err error
						if policy == "rekey" {
							report, err = editEncryptedNativeTreeCLI(t, ctx, fixtureImage(t, before), path, options)
						} else {
							report, err = editEncryptedNativeTree(ctx, fixtureImage(t, before), path, options)
						}
						if err == nil && (report.SourceEncryption == nil || report.SourceEncryption.KeyBits != bits || (report.Encryption == nil) != (policy == "remove") || report.Encryption != nil && report.Encryption.KeyBits != bits) {
							return fmt.Errorf("output encryption policy changed: %+v", report)
						}
						return err
					})
					checkEncryptedEditedTree(t, ctx, path, outputPasswordBytes, before, after, recipe)
					if policy != "preserve" {
						if opened, err := diskimage.OpenWithPassword(ctx, path, password); err == nil {
							closeFixture(t, opened)
							t.Fatal("replaced/removed envelope still accepts original password")
						}
					}
					recordOutput(t, schema.Output{Name: name, File: filepath.Base(path), Operation: "edit", Format: format, Encrypted: policy != "remove", Password: passwordRef, Source: caseRef(before), Expect: schema.Expectation{View: after.Stage, NewIdentities: true, Continuation: policy == "preserve" && format == "UDZO"}})
				}
			}
			for _, invalid := range [][]byte{nil, {}, []byte(recipe.Passwords["wrong"])} {
				out := filepath.Join(t.TempDir(), "refused.dmg")
				_, err := imageedit.Edit(ctx, fixtureImage(t, before), out, imageedit.Options{Time: fixedClock, ImagePassword: invalid}, func(*imageedit.Editor) error { t.Fatal("invalid image password reached command callback"); return nil })
				if !errors.Is(err, filesystem.ErrAuthentication) {
					t.Fatal("wrong image credential refusal", err)
				}
				if _, err := os.Stat(out); !errors.Is(err, fs.ErrNotExist) {
					t.Fatal("wrong credential published output", err)
				}
			}
			if actual, err := schema.FileDigest(fixtureImage(t, before)); err != nil || actual != sourceHash {
				t.Fatal("encrypted native source changed", err)
			}
		})
	}
	for _, producer := range []int{15, 26, 27} {
		for _, profile := range recipe.Profiles {
			for _, stage := range []string{"before-aes128", "before-aes256"} {
				key := fmt.Sprintf("%d/%s/%s", producer, profile, stage)
				if !seen[key] {
					t.Errorf("missing native encrypted edit input %s", key)
				}
			}
		}
	}
}

// Replay the same native journey through the ordinary CLI on every portable
// host. -X makes the replacement a logical data write, retaining the existing
// independent fork and attributes; host metadata supplies no expected values.
func editEncryptedNativeTreeCLI(t *testing.T, ctx context.Context, source, destination string, options imageedit.Options) (imageedit.Report, error) {
	t.Helper()
	root := t.TempDir()
	payload, imagePassword, outputPasswordPath := filepath.Join(root, "payload"), filepath.Join(root, "image-password"), filepath.Join(root, "output-password")
	for path, data := range map[string][]byte{payload: []byte("Edited encrypted-image payload.\n"), imagePassword: options.ImagePassword, outputPasswordPath: options.Encryption.Password} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			return imageedit.Report{}, err
		}
	}
	args := []string{"edit", "--json", "--image", source, "--output", destination, "--partition", strconv.Itoa(options.Partition), "--format", options.Format, "--time", options.Time.Format("2006-01-02T15:04:05Z07:00"), "--image-password-file", imagePassword, "--output-password-file", outputPasswordPath, "--",
		"cp", "-X", "--from-host", payload, "/Fixture/file", "--next",
		"cp", "-a", "/Fixture/tree", "/Fixture/copied", "--next",
		"chmod", "0640", "/Fixture/copied/nested/leaf", "--next",
		"mv", "/Fixture/copied/nested/leaf", "/Fixture/copied/nested/renamed", "--next",
		"ln", "-s", "renamed", "/Fixture/copied/nested/leaf", "--next",
		"xattr", "-w", "org.apfs.fixture", "edited attribute", "/Fixture/file", "--next",
		"ln", "/Fixture/file", "/Fixture/third-alias"}
	var output, diagnostics bytes.Buffer
	command := exec.CommandContext(ctx, portableCommandBinary(t), args...)
	command.Stdout, command.Stderr = &output, &diagnostics
	if err := command.Run(); err != nil {
		return imageedit.Report{}, fmt.Errorf("encrypted image CLI edit: %w: %s", err, diagnostics.String())
	}
	for _, credential := range [][]byte{options.ImagePassword, options.Encryption.Password} {
		if bytes.Contains(output.Bytes(), credential) || bytes.Contains(diagnostics.Bytes(), credential) {
			return imageedit.Report{}, fmt.Errorf("encrypted image command exposed a credential")
		}
	}
	var report imageedit.Report
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		return report, err
	}
	return report, nil
}

func editEncryptedNativeTree(ctx context.Context, source, destination string, options imageedit.Options) (imageedit.Report, error) {
	return imageedit.Edit(ctx, source, destination, options, func(editor *imageedit.Editor) error {
		if _, err := editor.Apply([]imageedit.Change{{Path: "/Fixture/file", Data: bytes.NewReader([]byte("Edited encrypted-image payload.\n"))}}); err != nil {
			return err
		}
		if _, err := editor.Copy([]imageedit.CopyCommand{{Sources: []string{"/Fixture/tree"}, Destination: "/Fixture/copied", Options: imageedit.CopyOptions{Archive: true}}}); err != nil {
			return err
		}
		_, err := editor.Apply([]imageedit.Change{
			{Operation: "chmod", Path: "/Fixture/copied/nested/leaf", Mode: "0640"},
			{Operation: "mv", Path: "/Fixture/copied/nested/leaf", Destination: "/Fixture/copied/nested/renamed"},
			{Operation: "ln", Symbolic: true, Path: "renamed", Destination: "/Fixture/copied/nested/leaf"},
			{Operation: "xattr", Path: "/Fixture/file", Attribute: "org.apfs.fixture", AttributeMode: "replace", Data: bytes.NewReader([]byte("edited attribute"))},
			{Operation: "ln", Path: "/Fixture/file", Destination: "/Fixture/third-alias"},
		})
		return err
	})
}

func checkEncryptedEditedTree(t *testing.T, ctx context.Context, path string, password []byte, before, after corpus.Case, recipe schema.Recipe) {
	t.Helper()
	var image *diskimage.Image
	var err error
	if password == nil {
		image, err = diskimage.Open(path)
	} else {
		image, err = diskimage.OpenWithPassword(ctx, path, password)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer closeFixture(t, image)
	if password != nil && (image.Encryption == nil || fmt.Sprintf("AES-%d", image.Encryption.KeyBits) != before.Observation.Image.Encryption.Cipher) {
		t.Fatal("source AES strength changed", image.Encryption)
	}
	report, err := inspect.Image(ctx, image)
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Observation.Views) != 1 || len(after.Observation.Views) != 1 || len(after.Observation.Volumes) != 1 {
		t.Fatal("encrypted edit oracle must have exactly one live volume")
	}
	reader, close := openVolume(t, ctx, report, after.Observation.Volumes[0], volumeName(after.Observation.Volumes[0]), recipe, image)
	if close != nil {
		defer close()
	}
	existing := map[string]bool{}
	for _, entry := range before.Observation.Views[0].Entries {
		existing[entry.Path] = true
	}
	if len(recipe.Stages) != 2 || recipe.Stages[1].Name != "after" {
		t.Fatal("encrypted edit recipe no longer declares the qualified ordered workload")
	}
	expected, err := native.ProjectEditedViewClocks(before.Observation.Views[0], after.Observation.Views[0], recipe.Stages[1].Steps, before.Profile, fixedClock.UnixNano())
	if err != nil {
		t.Fatal(err)
	}
	compareViewWith(t, ctx, filepath.Base(path), reader, expected, compareOptions{ignoreIDFor: func(path string) bool { return !existing[path] }})
}

func TestNestedEncryptedImageCredentialsRemainIndependent(t *testing.T) {
	cases, _ := loadCorpus(t)
	recipe := recipesByName(t)["encrypted-images"]
	seen := map[int]bool{}
	for _, k := range cases {
		if k.Recipe != recipe.Name || k.Profile != "apfs" || k.Stage != "aes256-nested" {
			continue
		}
		seen[k.Producer] = true
		t.Run(fmt.Sprintf("macos-%d", k.Producer), func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			hash, err := schema.FileDigest(fixtureImage(t, k))
			if err != nil {
				t.Fatal(err)
			}
			imagePassword, volumePassword := []byte(recipe.Passwords["image"]), []byte(recipe.Passwords["volume"])
			partition := encryptedEditPartition(t, ctx, k, imagePassword)
			for _, tc := range []struct {
				name          string
				image, volume []byte
				want          error
				exact         string
			}{
				{"missing-image", nil, volumePassword, filesystem.ErrAuthentication, ""},
				{"exchanged", volumePassword, imagePassword, filesystem.ErrAuthentication, ""},
				{"wrong-volume", imagePassword, []byte(recipe.Passwords["wrong"]), filesystem.ErrAuthentication, ""},
				{"no-volume", imagePassword, nil, filesystem.ErrUnsupported, "software-encrypted APFS image editing: unsupported feature"},
				{"both-correct", imagePassword, volumePassword, filesystem.ErrUnsupported, "software-encrypted APFS image editing: unsupported feature"},
			} {
				out := filepath.Join(t.TempDir(), "refused.dmg")
				_, err := imageedit.Edit(ctx, fixtureImage(t, k), out, imageedit.Options{Partition: partition, Time: fixedClock, ImagePassword: tc.image, VolumePassword: tc.volume}, func(*imageedit.Editor) error { t.Fatal("encrypted APFS write reached callback"); return nil })
				if !errors.Is(err, tc.want) || tc.exact != "" && err.Error() != tc.exact {
					t.Fatalf("%s: wrong refusal: %v", tc.name, err)
				}
				if _, err := os.Stat(out); !errors.Is(err, fs.ErrNotExist) {
					t.Fatal("nested refusal published output", err)
				}
			}
			// Exercise the same distinction through real ordinary CLI processes
			// on every portable host, with exact-byte credential files.
			root := t.TempDir()
			imagePasswordPath, volumePasswordPath := filepath.Join(root, "image-password"), filepath.Join(root, "volume-password")
			if err := os.WriteFile(imagePasswordPath, imagePassword, 0600); err != nil {
				t.Fatal(err)
			}
			for _, tc := range []struct {
				volume  []byte
				status  int
				message string
			}{{[]byte(recipe.Passwords["wrong"]), 1, filesystem.ErrAuthentication.Error()}, {volumePassword, 5, "software-encrypted APFS image editing: unsupported feature"}} {
				if err := os.WriteFile(volumePasswordPath, tc.volume, 0600); err != nil {
					t.Fatal(err)
				}
				out := filepath.Join(t.TempDir(), "refused.dmg")
				command := exec.CommandContext(ctx, portableCommandBinary(t), "chmod", "--image", fixtureImage(t, k), "--output", out, "--partition", strconv.Itoa(partition), "--image-password-file", imagePasswordPath, "--password-file", volumePasswordPath, "0600", "/Fixture/example.txt")
				var stdout, diagnostics bytes.Buffer
				command.Stdout, command.Stderr = &stdout, &diagnostics
				err := command.Run()
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != tc.status || !strings.Contains(diagnostics.String(), tc.message) || stdout.Len() != 0 {
					t.Fatalf("nested CLI credential boundary: %v, %s", err, diagnostics.String())
				}
				if bytes.Contains(diagnostics.Bytes(), imagePassword) || bytes.Contains(diagnostics.Bytes(), volumePassword) {
					t.Fatal("nested CLI exposed a credential")
				}
				if _, err := os.Stat(out); !errors.Is(err, fs.ErrNotExist) {
					t.Fatal("nested CLI refusal published output", err)
				}
			}
			if actual, err := schema.FileDigest(fixtureImage(t, k)); err != nil || actual != hash {
				t.Fatal("nested admission changed source", err)
			}
		})
	}
	for _, producer := range []int{15, 26, 27} {
		if !seen[producer] {
			t.Errorf("missing native nested encryption control for macOS %d", producer)
		}
	}
}

func encryptedEditPartition(t *testing.T, ctx context.Context, k corpus.Case, password []byte) int {
	t.Helper()
	image, err := diskimage.OpenWithPassword(ctx, fixtureImage(t, k), password)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFixture(t, image)
	index := -1
	for _, part := range image.Partitions {
		if part.Type == diskimage.APFSType || part.Type == diskimage.HFSType {
			if index != -1 {
				t.Fatal("encrypted edit control has multiple filesystem partitions")
			}
			index = part.Index
		}
	}
	if index == -1 {
		t.Fatal("encrypted edit control lacks its declared filesystem partition")
	}
	return index
}
