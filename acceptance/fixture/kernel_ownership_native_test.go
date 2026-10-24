//go:build native && darwin

package fixture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	base := os.Getenv("APFS_NATIVE_WORK")
	major, err := strconv.Atoi(os.Getenv("APFS_EXPECT_MAJOR"))
	if base == "" || err != nil || major <= 0 {
		t.Fatal("APFS_NATIVE_WORK and APFS_EXPECT_MAJOR are required for retained native ownership evidence")
	}
	if !schema.IsSupportedProducer(major) {
		t.Fatalf("unsupported native ownership macOS major %d; supported producers are %v", major, schema.Producers)
	}
	if err := RequireDisposableHost(); err != nil {
		t.Fatal(err)
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
	recorder := &ownershipEvidenceCommander{C: Exec{}, Dir: work, Phase: "host-provenance"}
	disk := &HostDisk{C: recorder, T: transcript}
	type claim struct {
		Kind, Image, Device string
		ExpectedOwned       bool
		Owned               bool
		ExpectedState       AttachmentOwnership
		State               AttachmentOwnership
		Error               string `json:",omitempty"`
	}
	evidence := struct {
		Schema         int
		KernelVersion  string
		OSBuild        string
		Architecture   string
		Commit         string
		RunID          string
		RunAttempt     string
		RawBytes       int64
		RawSHA256      map[string]string
		ToolsSHA256    map[string]string
		SymlinkAliases map[string]string
		Claims         []claim
		Commands       []schema.Command
		CommandResults []ownershipCommandEvidence
		ContractError  string `json:",omitempty"`
		RetentionError string `json:",omitempty"`
	}{Schema: 2, Architecture: runtime.GOARCH, Commit: os.Getenv("GITHUB_SHA"), RunID: os.Getenv("GITHUB_RUN_ID"), RunAttempt: os.Getenv("GITHUB_RUN_ATTEMPT"), RawBytes: 2 << 20, RawSHA256: map[string]string{}, ToolsSHA256: map[string]string{}}
	type attachedImage struct {
		name       string
		attachment *Attachment
	}
	var attachments []attachedImage
	var contractErr error
	collect := func(phase string) {
		recorder.Phase = phase
		contractErr = errors.Join(contractErr, collectOwnershipInventories(ctx, disk))
	}
	checkClaim := func(kind string, att *Attachment, expected AttachmentOwnership) {
		recorder.Phase = kind
		state, err := disk.kernelAttachmentOwnership(ctx, att)
		row := claim{Kind: kind, Image: att.Image, Device: att.Dev, ExpectedOwned: expected == OwnershipOwned, Owned: state == OwnershipOwned, ExpectedState: expected, State: state}
		if err != nil {
			row.Error = err.Error()
		}
		evidence.Claims = append(evidence.Claims, row)
		if err != nil || state != expected {
			contractErr = errors.Join(contractErr, fmt.Errorf("%s: native kernel binding %s to %s: state=%s, expected=%s", kind, att.Dev, att.Image, state, expected), err)
		}
	}
	// Cleanup happens once per successful attachment. Errors remain fatal, and
	// the original transcript is serialized after every existing close request.
	defer func() {
		for i := len(attachments) - 1; i >= 0; i-- {
			item := attachments[i]
			recorder.Phase = "detach-" + item.name
			if err := disk.Detach(ctx, item.attachment); err != nil {
				contractErr = errors.Join(contractErr, fmt.Errorf("owned native cleanup %s: %w", item.attachment.Image, err))
			}
			collect("after-detach-" + item.name)
			checkClaim("post-detach-"+item.name, item.attachment, OwnershipAbsent)
		}
		for image, before := range evidence.RawSHA256 {
			if after, err := schema.FileDigest(image); err != nil || after != before {
				contractErr = errors.Join(contractErr, fmt.Errorf("blank native ownership control changed: %s: %v", image, err))
			}
		}
		evidence.Commands = transcript.Commands
		evidence.CommandResults = recorder.Results
		if contractErr != nil {
			evidence.ContractError = contractErr.Error()
		}
		if recorder.Err != nil {
			evidence.RetentionError = recorder.Err.Error()
		}
		data, err := json.MarshalIndent(evidence, "", "  ")
		file := filepath.Join(work, "ownership-evidence.json")
		if err == nil {
			err = os.WriteFile(file, append(data, '\n'), 0o600)
		}
		if err != nil {
			contractErr = errors.Join(contractErr, fmt.Errorf("retain original native ownership evidence: %w", err))
		} else {
			digest, err := schema.FileDigest(file)
			if err != nil {
				contractErr = errors.Join(contractErr, err)
			} else {
				t.Logf("native ownership evidence SHA256=%s commands=%d", digest, len(transcript.Commands))
			}
		}
		if err := errors.Join(contractErr, recorder.Err); err != nil {
			t.Error(err)
		}
	}()
	version, err := disk.run(ctx, "ownership-kernel-version", false, nil, "sw_vers", "-productVersion")
	if err != nil {
		t.Fatal(err)
	}
	evidence.KernelVersion = strings.TrimSpace(string(version))
	build, err := disk.run(ctx, "ownership-os-build", false, nil, "sw_vers", "-buildVersion")
	if err != nil {
		t.Fatal(err)
	}
	evidence.OSBuild = strings.TrimSpace(string(build))
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
		recorder.Phase = "attach-" + name
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
		// Parsing/attach failure must not prevent the independent platform
		// scopes from being captured. HostDisk retains its owned cleanup too.
		collect("after-attach-" + name)
		if err != nil {
			contractErr = errors.Join(contractErr, fmt.Errorf("attach native control %s: %w", name, err))
			continue
		}
		attachments = append(attachments, attachedImage{name, att})
	}
	// Collect both image states before interpreting any registry output. A
	// failed adapter assertion remains fatal after complete evidence retention.
	for _, item := range attachments {
		checkClaim("positive-"+item.name, item.attachment, OwnershipOwned)
	}
	if len(attachments) != 2 {
		contractErr = errors.Join(contractErr, errors.New("two successful native attachments are required for crossed full-path controls"))
		return
	}
	first, second := attachments[0].attachment, attachments[1].attachment
	if first.Dev == second.Dev {
		t.Fatal("two live private images received the same native whole device")
	}
	alias := filepath.Join(work, "ownership-alias.raw")
	if err := os.Symlink(first.Image, alias); err != nil {
		contractErr = errors.Join(contractErr, fmt.Errorf("create native image path alias: %w", err))
	} else if target, err := os.Readlink(alias); err != nil {
		contractErr = errors.Join(contractErr, fmt.Errorf("retain native image alias target: %w", err))
	} else {
		evidence.SymlinkAliases = map[string]string{alias: target}
		checkClaim("positive-symlink-alias", &Attachment{Image: alias, Dev: first.Dev, RDev: first.RDev}, OwnershipOwned)
	}
	for i, pair := range [][2]*Attachment{{first, second}, {second, first}} {
		crossed := &Attachment{Image: pair[0].Image, Dev: pair[1].Dev, RDev: pair[1].RDev}
		phase := fmt.Sprintf("crossed-%d", i+1)
		collect(phase)
		checkClaim(phase, crossed, OwnershipForeign)
		start := len(transcript.Commands)
		refusalErr := disk.Detach(ctx, crossed)
		var refusal *AttachmentOwnershipError
		if !errors.As(refusalErr, &refusal) || refusal.State != OwnershipForeign {
			contractErr = errors.Join(contractErr, fmt.Errorf("foreign device was not refused as unreleased: %v", refusalErr))
		}
		for _, command := range transcript.Commands[start:] {
			if len(command.Argv) > 1 && filepath.Base(command.Argv[0]) == "hdiutil" && command.Argv[1] == "detach" {
				contractErr = errors.Join(contractErr, fmt.Errorf("crossed image issued a native detach: %v", command.Argv))
			}
		}
	}
}
