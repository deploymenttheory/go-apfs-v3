package native

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

type verificationCommandDisk struct {
	fixture.Disk
	t         *fixture.Transcript
	verifyErr error
	attachErr error
	detachErr error
}

func (d *verificationCommandDisk) SetTranscript(t *fixture.Transcript) { d.t = t }

func (d *verificationCommandDisk) Verify(_ context.Context, image string, _ []byte) error {
	status := 0
	if d.verifyErr != nil {
		status = 1
	}
	_ = d.t.Record(fixture.Command{Label: "verify", Argv: []string{"hdiutil", "verify", image}, Expected: "0"}, fixture.Result{Status: status})
	return d.verifyErr
}

func (d *verificationCommandDisk) Attach(_ context.Context, image string, opts fixture.AttachOptions) (*fixture.Attachment, error) {
	if !opts.NoInventory || !opts.ReadOnly {
		return nil, errors.New("expected read-only sector-preserving attachment")
	}
	status := 0
	if d.attachErr != nil {
		status = 1
	}
	_ = d.t.Record(fixture.Command{Label: "attach", Argv: []string{"hdiutil", "attach", image}, Expected: "0"}, fixture.Result{Status: status})
	if d.attachErr != nil {
		return nil, d.attachErr
	}
	return &fixture.Attachment{Image: image, Dev: "/dev/disk27", RDev: "/dev/rdisk27"}, nil
}

func (*verificationCommandDisk) DeviceDigest(context.Context, string, string) (string, int64, error) {
	return "native-device-digest", 4096, nil
}

func (d *verificationCommandDisk) Detach(context.Context, *fixture.Attachment) error {
	// Synthetic incomplete inventory: this tests retention of a successful
	// command whose ownership interpretation fails, not native inventory shape.
	stdout := []byte(`<plist><dict><key>images</key><array><dict><key>image-path</key><string>/unidentified-image.dmg</string></dict></array></dict></plist>`)
	_ = d.t.Record(fixture.Command{Label: "hdiutil-info", Argv: []string{"hdiutil", "info", "-plist"}, Expected: "0"}, fixture.Result{Stdout: stdout})
	return d.detachErr
}

func verificationInput(t *testing.T, disk *verificationCommandDisk, encrypted bool) (*Verifier, Paired) {
	t.Helper()
	root := t.TempDir()
	ref := schema.CaseRef{Producer: 15, Recipe: "snapshot-history", Profile: "apfsx", Stage: "before"}
	out := schema.Output{Name: "snapshot.repack.UDZO.dmg", File: "source.dmg", Operation: "repack", Source: ref, Format: "UDZO", Expect: schema.Expectation{DiskSHA256: "native-device-digest"}}
	if encrypted {
		out.Encrypted, out.Password = true, "native-control-password"
	}
	k := corpus.Case{Observation: &schema.Observation{Views: []schema.View{{Volume: 0}}}}
	v := &Verifier{Disk: disk, Work: filepath.Join(root, "work"), Cases: map[string]corpus.Case{CaseKey(ref): k}}
	p := Paired{Name: out.Name, Output: out, Primary: "darwin", ByHost: map[string]schema.Output{"darwin": out}, Dirs: map[string]string{"darwin": root}, Passwords: map[string]string{out.Password: "independent-test-password"}}
	// ForSubtest installs an initial recorder even before an observer runs.
	disk.t = &fixture.Transcript{}
	return v, p
}

func TestSectorPreservingVerificationFailureRetainsNativeOwnershipEvidence(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		name := "plaintext container verification"
		if encrypted {
			name = "encrypted pre-observer hash"
		}
		t.Run(name, func(t *testing.T) {
			cause := errors.New("hdiutil inventory cannot establish whether /dev/disk27 is still attached")
			disk := &verificationCommandDisk{detachErr: cause}
			v, p := verificationInput(t, disk, encrypted)
			if _, err := v.VerifyOutput(context.Background(), p); !errors.Is(err, cause) {
				t.Fatalf("native ownership failure changed: %v", err)
			}
			commands := recordedCommands(t, filepath.Join(v.Work, "verify", sanitize(p.Name), "verification-commands.json"))
			want := 3
			if encrypted {
				want = 2 // The decrypt/hash failure precedes container verification.
			}
			if len(commands) != want || commands[len(commands)-1].Label != "hdiutil-info" || commands[len(commands)-1].Status != "0" || commands[len(commands)-1].StdoutText == "" || commands[len(commands)-1].StdoutSHA256 == "" {
				t.Fatalf("native operations or complete ownership evidence lost: %+v", commands)
			}
			for _, command := range commands {
				if strings.Contains(command.StdoutText+command.StderrText+strings.Join(command.Argv, " "), "independent-test-password") {
					t.Fatal("password entered retained command evidence")
				}
			}
		})
	}
}

func TestVerificationRetainsEarlyNativeFailureAndJoinsDiagnosticIOError(t *testing.T) {
	for _, stage := range []string{"container checker", "encrypted attach"} {
		t.Run(stage, func(t *testing.T) {
			cause := errors.New("native operation failed")
			disk := &verificationCommandDisk{}
			encrypted := stage == "encrypted attach"
			if encrypted {
				disk.attachErr = cause
			} else {
				disk.verifyErr = cause
			}
			v, p := verificationInput(t, disk, encrypted)
			if _, err := v.VerifyOutput(context.Background(), p); !errors.Is(err, cause) {
				t.Fatalf("early native failure changed: %v", err)
			}
			commands := recordedCommands(t, filepath.Join(v.Work, "verify", sanitize(p.Name), "verification-commands.json"))
			if len(commands) != 1 || commands[0].Status != "1" {
				t.Fatalf("failed first command missing: %+v", commands)
			}
			v.Work = filepath.Join(t.TempDir(), "not-a-directory")
			if err := os.WriteFile(v.Work, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := v.VerifyOutput(context.Background(), p)
			if !errors.Is(err, cause) || !errors.Is(err, syscall.ENOTDIR) || !strings.Contains(err.Error(), "retain complete verification commands") {
				t.Fatalf("diagnostic IO masked native error or disappeared: %v", err)
			}
		})
	}
}

func TestSuccessfulVerificationDoesNotCreateFailureEvidence(t *testing.T) {
	disk := &verificationCommandDisk{}
	v, p := verificationInput(t, disk, false)
	if differences, err := v.VerifyOutput(context.Background(), p); err != nil || len(differences) != 0 {
		t.Fatalf("successful container verification changed: %v %v", differences, err)
	}
	if _, err := os.Stat(filepath.Join(v.Work, "verify", sanitize(p.Name), "verification-commands.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("success created failure evidence: %v", err)
	}
}
