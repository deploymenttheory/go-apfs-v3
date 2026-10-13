package copyfile

import (
	"bytes"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/link"
	"github.com/deploymenttheory/go-apfs-v3/internal/metadata"
)

func TestCopyMetadataRejectsUnsupportedStateAndUnrelatedFields(t *testing.T) {
	stamp := filesystem.Observed(time.Unix(1749283750, 0))
	base := filesystem.Metadata{Mode: filesystem.Observed(uint32(0100644)), UID: filesystem.Observed(uint32(501)), GID: filesystem.Observed(uint32(20)), BSDFlags: filesystem.Observed(uint32(0)), BirthTime: stamp, ModifyTime: stamp, AccessTime: stamp}
	for _, change := range []func(*filesystem.Change){
		func(c *filesystem.Change) { c.Metadata.ChangeTime = stamp },
		func(c *filesystem.Change) { c.Metadata.UID = filesystem.Observed(^uint32(0)) },
		func(c *filesystem.Change) { c.Metadata.Mode.Value |= 04000 },
		func(c *filesystem.Change) { c.Metadata.BSDFlags.Value = 32 },
		func(c *filesystem.Change) { c.Metadata.AccessTime.State = filesystem.Uncaptured },
		func(c *filesystem.Change) { c.Mode = "0755" },
		func(c *filesystem.Change) { c.Symbolic = true },
		func(c *filesystem.Change) {
			c.Attributes = map[string]block.Source{filesystem.Decmpfs: bytes.NewReader([]byte("active compression"))}
		},
		func(c *filesystem.Change) {
			c.Attributes = map[string]block.Source{"com.apple.system.Security": bytes.NewReader([]byte("invalid filesec"))}
		},
		func(c *filesystem.Change) { c.RemoveAttributes = []string{"org.example", "org.example"} },
		func(c *filesystem.Change) {
			c.RemoveAttributes = []string{"org.example"}
			c.Attributes = map[string]block.Source{"org.example": bytes.NewReader(nil)}
		},
	} {
		m := base
		c := filesystem.Change{Operation: "copy-metadata", Path: "/file", Metadata: &m}
		if err := ValidateMetadata(c); err != nil {
			t.Fatal("supported copy state refused", err)
		}
		change(&c)
		if err := ValidateMetadata(c); err == nil {
			t.Fatalf("unsupported copy state admitted: %+v", c)
		}
	}
	for _, c := range []filesystem.Change{
		{Operation: "ln", Path: "/file", Destination: "/alias", Attributes: map[string]block.Source{"org.example": bytes.NewReader(nil)}},
		{Operation: "ln", Path: "/file", Destination: "/alias", RemoveAttributes: []string{"org.example"}},
	} {
		if err := link.Validate(c); err == nil {
			t.Fatal("link silently ignored copy attributes")
		}
	}
	for _, c := range []filesystem.Change{
		{Operation: "touch", Path: "/file", Attributes: map[string]block.Source{"org.example": bytes.NewReader(nil)}},
		{Operation: "chmod", Path: "/file", Mode: "0755", RemoveAttributes: []string{"org.example"}},
	} {
		if err := metadata.ValidateChange(c); err == nil {
			t.Fatal("metadata command silently ignored copy attributes")
		}
	}
}
