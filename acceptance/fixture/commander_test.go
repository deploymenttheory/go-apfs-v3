package fixture

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestTranscriptRetainsLargeAPFSInventoriesOnly(t *testing.T) {
	listing := []byte(strings.Replace(inventoryListing, "<dict>", "<dict>"+strings.Repeat(" ", 17<<10), 1))
	for _, tc := range []struct {
		name string
		argv []string
		keep bool
	}{
		{"global-inventory", []string{"diskutil", "apfs", "list", "-plist"}, true},
		{"scoped-inventory", []string{"diskutil", "apfs", "list", "-plist", "disk6"}, true},
		{"resolved-inventory-program", []string{"/usr/sbin/diskutil", "apfs", "list", "-plist"}, true},
		{"diskutil-info", []string{"diskutil", "info", "-plist", "disk6"}, false},
		{"ordinary-listing", []string{"diskutil", "list", "-plist"}, false},
		{"plain-apfs-listing", []string{"diskutil", "apfs", "list"}, false},
		{"different-program", []string{"other", "apfs", "list", "-plist"}, false},
		{"extra-arguments", []string{"diskutil", "apfs", "list", "-plist", "disk6", "extra"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var transcript Transcript
			if err := transcript.Record(Command{Argv: tc.argv, Expected: "0"}, Result{Stdout: listing, Stderr: listing}); err != nil {
				t.Fatal(err)
			}
			got := transcript.Commands[0]
			sum := sha256.Sum256(listing)
			if got.StdoutSHA256 != fmt.Sprintf("%x", sum) || got.StderrSHA256 != got.StdoutSHA256 || got.StderrText != "" {
				t.Fatal("large-command digest or unchanged stderr bound differs")
			}
			if (got.StdoutText != "") != tc.keep || tc.keep && got.StdoutText != string(listing) {
				t.Fatal("command-specific stdout retention differs")
			}
			if tc.keep {
				obs := observedAPFSInventory()
				obs.Commands = transcript.Commands
				if _, err := APFSInventory(obs); err != nil {
					t.Fatal("retained large inventory cannot supply its native verdict:", err)
				}
			}
		})
	}
}

func TestTranscriptBoundsAPFSInventoryTextWithoutChangingDigests(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
		keep bool
	}{
		{"exact-bound", bytes.Repeat([]byte("x"), retainedAPFSListingTextLimit), true},
		{"oversized", bytes.Repeat([]byte("x"), retainedAPFSListingTextLimit+1), false},
		{"invalid-utf8", append(bytes.Repeat([]byte("x"), 17<<10), 0xff), false},
		{"binary-nul", append(bytes.Repeat([]byte("x"), 17<<10), 0), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var transcript Transcript
			if err := transcript.Record(Command{Argv: []string{"diskutil", "apfs", "list", "-plist"}, Expected: "0"}, Result{Stdout: tc.data}); err != nil {
				t.Fatal(err)
			}
			entry := transcript.Commands[0]
			sum := sha256.Sum256(tc.data)
			if entry.StdoutSHA256 != fmt.Sprintf("%x", sum) || (entry.StdoutText != "") != tc.keep || tc.keep && entry.StdoutText != string(tc.data) {
				t.Fatal("APFS text bound lost original bytes or changed the full digest")
			}
		})
	}
}
