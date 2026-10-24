package fixture

import (
	"context"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func TestCaptureToolStepsCannotBypassTheSharedAttachmentLifecycle(t *testing.T) {
	for _, verb := range []string{"attach", "detach"} {
		t.Run(verb, func(t *testing.T) {
			for _, argument := range []string{verb, "$ACTION"} {
				commander := &fakeCommander{}
				capture := &Capture{C: commander, t: &Transcript{}, vars: &Vars{Values: map[string]string{"ACTION": verb}}}
				err := capture.runTool(context.Background(), &schema.ToolStep{Program: "hdiutil", Args: []string{argument, "/dev/disk42"}, Expect: "0"})
				if err == nil || !strings.Contains(err.Error(), "shared Disk attachment lifecycle") || len(commander.calls) != 0 {
					t.Fatalf("raw recipe bypass reached the native commander: %v, calls=%v", err, commander.calls)
				}
			}
		})
	}
}
