package acceptance_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
	"github.com/deploymenttheory/go-apfs-v3/session"
)

type nativeSecurity struct {
	OwnerUUID, GroupUUID string
	ACL                  *struct {
		Count, Flags uint32
		Entries      []struct {
			GUID          string
			Flags, Rights uint32
		}
	}
}
type permissionInheritanceState struct {
	Files         fileObservation
	Security      map[string]nativeSecurity
	CheckerStatus int
}
type permissionInheritanceCase struct {
	ID                  string
	Source, NativeAfter hfsGrowthArchive
	Before, After       permissionInheritanceState
	Operations          []struct {
		Op, Path, Mode, Source string
		Preserve, NoAttributes bool
		ActorUID               *uint32
		UID, GID               *uint32
	}
}
type permissionInheritanceManifest struct {
	Schema, Major            int
	Contract, CommandsSHA256 string
	OriginalManifestSHA256   string
	Producer                 struct {
		System, Version, Build, Architecture, Revision, Run string
		ActorUID, ActorGID                                  uint32
		Sources, Tools                                      map[string]string
	}
	Cases []permissionInheritanceCase
}

// Public getattrlist reports the independently observed kauth fields. Apple's
// canonical network-order layout lets these exact fields qualify hidden on-disk
// ACL bytes, including GUID/order/rights, without calling the Go filesec port.
func nativeSecurityBytes(t *testing.T, value nativeSecurity) []byte {
	t.Helper()
	if value.ACL == nil {
		return nil
	}
	if int(value.ACL.Count) != len(value.ACL.Entries) || len(value.ACL.Entries) > 128 {
		t.Fatal("native ACL entry count")
	}
	b := make([]byte, 44+24*len(value.ACL.Entries))
	binary.BigEndian.PutUint32(b, 0x012cc16d)
	for _, field := range []struct {
		text string
		off  int
	}{{value.OwnerUUID, 4}, {value.GroupUUID, 20}} {
		guid, err := hex.DecodeString(field.text)
		if err != nil || len(guid) != 16 {
			t.Fatal("native identity GUID", err)
		}
		copy(b[field.off:], guid)
	}
	binary.BigEndian.PutUint32(b[36:], value.ACL.Count)
	binary.BigEndian.PutUint32(b[40:], value.ACL.Flags)
	for n, ace := range value.ACL.Entries {
		guid, err := hex.DecodeString(ace.GUID)
		if err != nil || len(guid) != 16 {
			t.Fatal("native ACE GUID", err)
		}
		off := 44 + n*24
		copy(b[off:], guid)
		binary.BigEndian.PutUint32(b[off+16:], ace.Flags)
		binary.BigEndian.PutUint32(b[off+20:], ace.Rights)
	}
	return b
}

func permissionFiles(t *testing.T, state permissionInheritanceState) fileObservation {
	t.Helper()
	want := state.Files
	want.Entries = append([]nativeFile(nil), want.Entries...)
	if state.CheckerStatus != 0 || len(state.Security) != len(want.Entries) {
		t.Fatal("incomplete native permission observation")
	}
	for i := range want.Entries {
		entry := &want.Entries[i]
		security, ok := state.Security[entry.Path]
		if !ok {
			t.Fatal("missing native security", entry.Path)
		}
		attrs := map[string]nativeValue{}
		for name, value := range entry.RawAttributes {
			attrs[name] = value
		}
		if value := nativeSecurityBytes(t, security); value != nil {
			digest := sha256.Sum256(value)
			attrs["com.apple.system.Security"] = nativeValue{Size: int64(len(value)), SHA256: hex.EncodeToString(digest[:])}
		}
		entry.RawAttributes = attrs
	}
	return want
}

func permissionChanges(c permissionInheritanceCase) []imageedit.Change {
	var changes []imageedit.Change
	for _, operation := range c.Operations {
		change := imageedit.Change{Operation: operation.Op, Path: "/Fixture/" + operation.Path, Mode: operation.Mode}
		if operation.ActorUID != nil {
			change.ActorUID = filesystem.Observed(*operation.ActorUID)
		}
		switch operation.Op {
		case "replace":
			change.Operation, change.Data = "cp", bytes.NewReader([]byte("Written permission contents\n"))
		case "create":
			change.Operation, change.Data = "cp", bytes.NewReader([]byte("Created inherited contents\n"))
		case "chown":
			change.Metadata = &filesystem.Metadata{}
			if operation.UID != nil {
				change.Metadata.UID = filesystem.Observed(*operation.UID)
			}
			if operation.GID != nil {
				change.Metadata.GID = filesystem.Observed(*operation.GID)
			}
		}
		changes = append(changes, change)
	}
	return changes
}

func comparePermissions(t *testing.T, reader filesystem.Reader, before, expected fileObservation, when time.Time) {
	t.Helper()
	previous := map[string]nativeFile{}
	for _, entry := range before.Entries {
		previous[entry.Path] = entry
	}
	forward, reverse := map[uint64]uint64{}, map[uint64]uint64{}
	for i := range expected.Entries {
		entry := &expected.Entries[i]
		id, err := filesystem.LookupExact(context.Background(), reader, entry.Path)
		if err != nil {
			t.Fatal(entry.Path, err)
		}
		if old, ok := forward[entry.Object]; ok && old != id {
			t.Fatal("permission edit separated hard links")
		}
		if old, ok := reverse[id]; ok && old != entry.Object {
			t.Fatal("permission edit conflated native identities")
		}
		forward[entry.Object], reverse[id] = id, entry.Object
		if old, ok := previous[entry.Path]; ok {
			if old.Object != id {
				t.Fatal("permission edit replaced original identity", entry.Path)
			}
			if old.ChangeNS != entry.ChangeNS {
				entry.ChangeNS = when.UnixNano()
			}
			if old.ModifyNS != entry.ModifyNS && entry.ModifyNS > when.UnixNano() {
				entry.ModifyNS = when.UnixNano()
			}
		} else {
			if entry.BirthSeconds > when.Unix() {
				entry.BirthSeconds, entry.BirthNS = when.Unix(), nil
			}
			if entry.ModifyNS > when.UnixNano() {
				entry.ModifyNS = when.UnixNano()
			}
			if entry.AccessNS > when.UnixNano() {
				entry.AccessNS = when.UnixNano()
			}
			entry.ChangeNS = when.UnixNano()
		}
		entry.Object = id
	}
	compareMetadataState(t, reader, expected, "")
}

func TestNativePermissionInheritance(t *testing.T) {
	testNativePermissions(t, "APFS_NATIVE_PERMISSION_INHERITANCE", "testdata/permission-inheritance", "permission-inheritance", "APFS_PERMISSION_INHERITANCE_OUTPUT", false)
}

func TestNativeCopyPermissions(t *testing.T) {
	testNativePermissions(t, "APFS_NATIVE_COPY_PERMISSIONS", "testdata/copy-permissions", "copy-permissions", "APFS_COPY_PERMISSIONS_OUTPUT", true)
}

func testNativePermissions(t *testing.T, env, retained, contract, outputEnv string, copies bool) {
	root := os.Getenv(env)
	if root == "" {
		root = retained
	}
	tools := 4
	if copies {
		tools = 5
	}
	paths, err := filepath.Glob(filepath.Join(root, "macos-*", "manifest.json"))
	if err != nil || len(paths) == 0 {
		t.Fatal("native permission controls absent", err)
	}
	majors := map[int]bool{}
	for _, path := range paths {
		var manifest permissionInheritanceManifest
		data, err := os.ReadFile(path)
		if err != nil || json.Unmarshal(data, &manifest) != nil {
			t.Fatal("native permission manifest", err)
		}
		if manifest.Schema != 1 || manifest.Contract != contract ||
			len(manifest.Cases) != 4 || len(manifest.Producer.Revision) != 40 || manifest.Producer.Run == "" ||
			manifest.Producer.System != "macOS" || manifest.Producer.Build == "" || manifest.Producer.Architecture == "" ||
			len(manifest.Producer.Sources) != 13 || len(manifest.Producer.Tools) != tools || majors[manifest.Major] {
			t.Fatal("native permission provenance")
		}
		if copies && os.Getenv(env) != "" {
			for _, c := range manifest.Cases {
				var modes bool
				for _, op := range c.Operations {
					modes = modes || op.Path == "inherited/preserved-setid"
				}
				if !modes {
					t.Fatal("fresh cp controls omit set-ID preservation", c.ID)
				}
			}
		}
		majors[manifest.Major] = true
		directory := filepath.Dir(path)
		if manifest.OriginalManifestSHA256 != "" {
			verifyDigest(t, directory, "original-manifest.json", manifest.OriginalManifestSHA256)
		}
		verifyDigest(t, directory, "commands.json", manifest.CommandsSHA256)
		for name, digest := range manifest.Producer.Sources {
			verifyDigest(t, directory, name, digest)
		}
		t.Run("macos-"+strconv.Itoa(manifest.Major), func(t *testing.T) {
			for _, c := range manifest.Cases {
				t.Run(c.ID, func(t *testing.T) {
					source := openNativeDiskArchive(t, directory, c.Source)
					verifyDigest(t, directory, c.NativeAfter.Image, c.NativeAfter.SHA256)
					kind := "hfs"
					if strings.HasPrefix(c.ID, "apfs") {
						kind = "apfs"
					}
					compareMetadataState(t, metadataReader(t, source, kind), permissionFiles(t, c.Before), kind)
					when := time.Unix(1749283750, 0)
					if copies {
						ctx := context.Background()
						dir := filepath.Join(t.TempDir(), "session")
						scratch, err := session.Capture(ctx, metadataReader(t, source, kind), dir, session.Options{UID: manifest.Producer.ActorUID, GID: manifest.Producer.ActorGID, Time: &when})
						if err != nil {
							t.Fatal(err)
						}
						for _, op := range c.Operations {
							if op.Op == "copy" {
								_, err = scratch.Copy(ctx, []string{"/Fixture/" + op.Source}, "/Fixture/"+op.Path, session.CopyOptions{Preserve: op.Preserve, NoAttributes: op.NoAttributes})
							} else {
								_, err = scratch.Chmod(ctx, []string{"/Fixture/" + op.Path}, op.Mode, session.WalkOptions{})
							}
							if err != nil {
								scratch.Close()
								t.Fatal("session copy", op, err)
							}
						}
						if err = scratch.Close(); err != nil {
							t.Fatal(err)
						}
						reopened, err := session.Open(ctx, dir)
						if err != nil {
							t.Fatal(err)
						}
						comparePermissions(t, reopened, c.Before.Files, permissionFiles(t, c.After), when)
						if err = reopened.Close(); err != nil {
							t.Fatal(err)
						}
					}
					outputRoot := os.Getenv(outputEnv)
					if outputRoot == "" {
						outputRoot = t.TempDir()
					}
					outputRoot = filepath.Join(outputRoot, "macos-"+strconv.Itoa(manifest.Major))
					if err := os.MkdirAll(outputRoot, 0700); err != nil {
						t.Fatal(err)
					}
					for _, format := range []string{"UDRO", "UDZO"} {
						output := filepath.Join(outputRoot, c.ID+"-"+format+".dmg")
						_, err := imageedit.Edit(context.Background(), source, output, imageedit.Options{Time: when, Format: format, ActorUID: filesystem.Observed(manifest.Producer.ActorUID)}, func(editor *imageedit.Editor) error {
							// Later creation inherits the ACL of the earlier new child
							// across separate commands on one shared scratch disk.
							for index, change := range permissionChanges(c) {
								op := c.Operations[index]
								if op.Op == "copy" {
									command := imageedit.CopyCommand{Sources: []string{"/Fixture/" + op.Source}, Destination: "/Fixture/" + op.Path, Options: imageedit.CopyOptions{Preserve: op.Preserve, NoAttributes: op.NoAttributes}}
									if _, err := editor.Copy([]imageedit.CopyCommand{command}); err != nil {
										return err
									}
								} else if _, err := editor.Apply([]imageedit.Change{change}); err != nil {
									return err
								}
							}
							return nil
						})
						if err != nil {
							t.Fatal(format, err)
						}
						comparePermissions(t, metadataReader(t, output, kind), c.Before.Files, permissionFiles(t, c.After), when)
					}
					refused := filepath.Join(t.TempDir(), "refused.dmg")
					_, err := imageedit.Apply(context.Background(), source, refused, imageedit.Options{Time: when}, []imageedit.Change{{Path: "/Fixture/write-user", Data: bytes.NewReader([]byte("must refuse without actor"))}})
					if !errors.Is(err, filesystem.ErrUnsupported) {
						t.Fatal("set-ID write without logical UID", err)
					}
					digest := fileDigest(t, source)
					if _, err = os.Stat(refused); !errors.Is(err, fs.ErrNotExist) || hex.EncodeToString(digest[:]) != c.Source.UncompressedSHA256 {
						t.Fatal("permission refusal published or changed source", err)
					}
				})
			}
		})
	}
	required := os.Getenv("APFS_REQUIRED_NATIVE_MAJORS")
	if required == "" {
		required = "15,26,27"
	}
	for _, value := range strings.Split(required, ",") {
		major, err := strconv.Atoi(value)
		if err != nil || major != 15 && major != 26 && major != 27 {
			t.Fatal("invalid required native permission major", value)
		}
		if !majors[major] {
			t.Fatal("missing native permission major", major)
		}
	}
}
