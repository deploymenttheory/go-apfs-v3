//go:build native && darwin

package fixture

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// This contract deliberately bypasses the framework inventory for its positive
// claims, so a green matrix must exercise the live kernel ownership adapter.
func TestKernelOwnershipMatchesNativeImagePaths(t *testing.T) {
	if err := RequireDisposableHost(); err != nil {
		t.Fatal(err)
	}
	base := os.Getenv("APFS_NATIVE_WORK")
	major, err := strconv.Atoi(os.Getenv("APFS_EXPECT_MAJOR"))
	if base == "" || err != nil || major <= 0 {
		t.Fatal("APFS_NATIVE_WORK and APFS_EXPECT_MAJOR are required for retained native ownership evidence")
	}
	base = filepath.Join(base, "kernel-image-ownership-contract")
	if err := os.MkdirAll(base, 0o700); err != nil {
		t.Fatal(err)
	}
	work, err := os.MkdirTemp(base, "images-")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("retained native ownership evidence: %s", work)
	ctx := context.Background()
	transcript := &Transcript{}
	disk := &HostDisk{C: Exec{}, T: transcript}
	type claim struct {
		Image, Device string
		Owned         bool
		Error         string `json:",omitempty"`
	}
	evidence := struct {
		KernelVersion string
		Architecture  string
		Commit        string
		RawBytes      int64
		RawSHA256     map[string]string
		ToolsSHA256   map[string]string
		Claims        []claim
		Commands      []schema.Command
	}{Architecture: runtime.GOARCH, Commit: os.Getenv("GITHUB_SHA"), RawBytes: 2 << 20, RawSHA256: map[string]string{}, ToolsSHA256: map[string]string{}}
	var attachments []*Attachment
	// Cleanup happens once per successful attachment. Errors remain fatal, and
	// the original transcript is serialized after every existing close request.
	defer func() {
		for i := len(attachments) - 1; i >= 0; i-- {
			if err := disk.Detach(ctx, attachments[i]); err != nil {
				t.Errorf("owned native cleanup %s: %v", attachments[i].Image, err)
			}
		}
		for image, before := range evidence.RawSHA256 {
			if after, err := schema.FileDigest(image); err != nil || after != before {
				t.Errorf("blank native ownership control changed: %s: %v", image, err)
			}
		}
		evidence.Commands = transcript.Commands
		data, err := json.MarshalIndent(evidence, "", "  ")
		file := filepath.Join(work, "ownership-evidence.json")
		if err == nil {
			err = os.WriteFile(file, append(data, '\n'), 0o600)
		}
		if err != nil {
			t.Errorf("retain original native ownership evidence: %v", err)
			return
		}
		digest, err := schema.FileDigest(file)
		if err != nil {
			t.Error(err)
			return
		}
		t.Logf("native ownership evidence SHA256=%s commands=%d", digest, len(transcript.Commands))
	}()
	version, err := disk.run(ctx, "ownership-kernel-version", false, nil, "sw_vers", "-productVersion")
	if err != nil {
		t.Fatal(err)
	}
	evidence.KernelVersion = strings.TrimSpace(string(version))
	actualMajor, err := strconv.Atoi(strings.SplitN(evidence.KernelVersion, ".", 2)[0])
	if err != nil || actualMajor != major {
		t.Fatalf("native ownership host is %q, expected major %d", evidence.KernelVersion, major)
	}
	for _, program := range []string{"/usr/bin/hdiutil", "/usr/sbin/ioreg"} {
		digest, err := schema.FileDigest(program)
		if err != nil {
			t.Fatal(err)
		}
		evidence.ToolsSHA256[program] = digest
	}
	for _, name := range []string{"first", "second"} {
		dir := filepath.Join(work, name)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		image := filepath.Join(dir, "ownership.raw")
		if err := disk.CreateRaw(ctx, image, evidence.RawBytes); err != nil {
			t.Fatal(err)
		}
		digest, err := schema.FileDigest(image)
		if err != nil {
			t.Fatal(err)
		}
		evidence.RawSHA256[image] = digest
		att, err := disk.Attach(ctx, image, AttachOptions{Raw: true, NoInventory: true})
		if err != nil {
			t.Fatal(err)
		}
		attachments = append(attachments, att)
		owned, err := disk.kernelImageOwnership(ctx, att)
		row := claim{Image: image, Device: att.Dev, Owned: owned}
		if err != nil {
			row.Error = err.Error()
		}
		evidence.Claims = append(evidence.Claims, row)
		if err != nil || !owned {
			t.Fatalf("native kernel failed to bind %s to %s: %v", att.Dev, image, err)
		}
	}
	if attachments[0].Dev == attachments[1].Dev {
		t.Fatal("two live private images received the same native whole device")
	}
	crossed := &Attachment{Image: attachments[0].Image, Dev: attachments[1].Dev, RDev: attachments[1].RDev}
	start := len(transcript.Commands)
	owned, err := disk.kernelImageOwnership(ctx, crossed)
	row := claim{Image: crossed.Image, Device: crossed.Dev, Owned: owned}
	if err != nil {
		row.Error = err.Error()
	}
	evidence.Claims = append(evidence.Claims, row)
	if err != nil || owned {
		t.Fatalf("crossed same-basename native binding was not refused: owned=%t: %v", owned, err)
	}
	if err := disk.Detach(ctx, crossed); err != nil {
		t.Fatalf("leave positively bound foreign image alone: %v", err)
	}
	for _, command := range transcript.Commands[start:] {
		if len(command.Argv) > 1 && filepath.Base(command.Argv[0]) == "hdiutil" && command.Argv[1] == "detach" {
			t.Fatalf("crossed image issued a native detach: %v", command.Argv)
		}
	}
}
