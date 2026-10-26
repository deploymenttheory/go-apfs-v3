package native

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func TestEncryptedVolumeVerificationRequiresCompleteDecryptedCheck(t *testing.T) {
	// Original command records from the bounded native baseline comparison,
	// run 40321409252. These are Apple's checks of Go password-change outputs;
	// the recorded stdout digests remain unchanged.
	data, err := os.ReadFile("testdata/apfs-encrypted-volume-verification.json")
	if err != nil {
		t.Fatal(err)
	}
	var commands map[string]schema.Command
	if err := json.Unmarshal(data, &commands); err != nil {
		t.Fatal(err)
	}
	for major, command := range commands {
		t.Run(major, func(t *testing.T) {
			output := command.StdoutText
			if got := fmt.Sprintf("%x", sha256.Sum256([]byte(output))); got != command.StdoutSHA256 {
				t.Fatal("original native verification transcript changed")
			}
			volume := &schema.APFSVolume{VolumeUUID: "0E39A557-6418-4083-81EA-11D0BB5C2D78", Snapshots: []schema.Snapshot{{Name: "com.apple.asr.47208", XID: 7}}}
			device := "/dev/rdisk8s1"
			if major == "27" {
				device = "/dev/rdisk6s1"
				volume.VolumeUUID = "CE49C4DD-0D86-4B49-9962-64B61CFCCED1"
				volume.Snapshots[0].Name = "com.apple.asr.74788"
			}
			if err := validateAPFSVerification(output, device, volume); err != nil {
				t.Fatal(err)
			}
			for _, phase := range []string{"Checking the fsroot tree", "Checking the extent ref tree", "Verifying allocated space", volume.VolumeUUID, volume.Snapshots[0].Name, "transaction ID 7", "File system check exit code is 0"} {
				if err := validateAPFSVerification(strings.ReplaceAll(output, phase, "omitted"), device, volume); err == nil {
					t.Errorf("accepted incomplete verification without %q", phase)
				}
			}
			for _, message := range []string{"Skipping encrypted volume", "warning: invalid o_cksum", "error: could not read"} {
				if err := validateAPFSVerification(output+"\n"+message, device, volume); err == nil {
					t.Errorf("accepted failed verification: %s", message)
				}
			}
		})
	}
}
