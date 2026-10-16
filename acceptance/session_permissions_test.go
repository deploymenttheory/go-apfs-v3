package acceptance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/session"
)

// Replay the independently observed Darwin operations through persisted logical
// scratch as well as image editing. A new actor context captures the previous
// reader; no host UID or process authorization is substituted for the native one.
func TestNativeSessionPermissionInheritance(t *testing.T) {
	root := nativeInput(t, "APFS_NATIVE_PERMISSION_INHERITANCE", "testdata/permission-inheritance")
	paths, err := filepath.Glob(filepath.Join(root, "macos-*", "manifest.json"))
	if err != nil || len(paths) == 0 {
		t.Fatal("native session permission controls absent", err)
	}
	majors := map[int]bool{}
	for _, name := range paths {
		var m permissionInheritanceManifest
		data, err := os.ReadFile(name)
		if err != nil || json.Unmarshal(data, &m) != nil || m.Contract != "permission-inheritance" {
			t.Fatal("native session permission manifest", err)
		}
		majors[m.Major] = true
		dir := filepath.Dir(name)
		verifyDigest(t, dir, "commands.json", m.CommandsSHA256)
		for name, hash := range m.Producer.Sources {
			verifyDigest(t, dir, name, hash)
		}
		t.Run(fmt.Sprintf("macos-%d", m.Major), func(t *testing.T) {
			for _, c := range m.Cases {
				t.Run(c.ID, func(t *testing.T) {
					source := openNativeDiskArchive(t, dir, c.Source)
					kind := "hfs"
					if strings.HasPrefix(c.ID, "apfs") {
						kind = "apfs"
					}
					when := time.Unix(1749283750, 0)
					actor := m.Producer.ActorUID
					scratch, err := session.Capture(context.Background(), metadataReader(t, source, kind), filepath.Join(t.TempDir(), "session"), session.Options{UID: actor, GID: m.Producer.ActorGID, Time: &when})
					if err != nil {
						t.Fatal(err)
					}
					defer func() { scratch.Close() }()
					ctx := context.Background()
					for _, op := range c.Operations {
						if op.ActorUID != nil && *op.ActorUID != actor {
							actor = *op.ActorUID
							next, err := session.Capture(ctx, scratch, filepath.Join(t.TempDir(), "session"), session.Options{UID: actor, GID: m.Producer.ActorGID, Time: &when})
							if err != nil {
								t.Fatal("logical actor capture", err)
							}
							if err = scratch.Close(); err != nil {
								t.Fatal(err)
							}
							scratch = next
						}
						path := "/Fixture/" + op.Path
						switch op.Op {
						case "chmod":
							_, err = scratch.Chmod(ctx, []string{path}, op.Mode, session.WalkOptions{})
						case "chown":
							owner := ""
							if op.UID != nil {
								owner = fmt.Sprint(*op.UID)
							}
							if op.GID != nil {
								owner += ":" + fmt.Sprint(*op.GID)
							}
							_, err = scratch.Chown(ctx, []string{path}, owner, session.WalkOptions{})
						case "mkdir":
							_, err = scratch.Mkdir(ctx, []string{path}, session.MkdirOptions{})
						case "replace":
							_, err = scratch.ReplaceData(ctx, path, bytes.NewReader([]byte("Written permission contents\n")))
						case "create":
							payload := "Written permission contents\n"
							if op.Op == "create" {
								payload = "Created inherited contents\n"
							}
							host := filepath.Join(t.TempDir(), "payload")
							if err = os.WriteFile(host, []byte(payload), 0644); err != nil {
								t.Fatal(err)
							}
							_, err = scratch.Copy(ctx, []string{host}, path, session.CopyOptions{FromHost: true, NoAttributes: true})
						default:
							t.Fatal("unsupported native session control", op)
						}
						if err != nil {
							t.Fatal("native session operation", op, err)
						}
					}
					comparePermissions(t, scratch, c.Before.Files, permissionFiles(t, c.After), when)
				})
			}
		})
	}
	requireNativeVersions(t, majors)
}
