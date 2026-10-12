package link

import (
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

func TestLiteralTargetBoundariesAndIgnoredFieldRefusals(t *testing.T) {
	for _, target := range []string{"x", "../missing", "/outside", "-target", strings.Repeat("\u00e9", 511) + "a"} {
		if err := Target(target); err != nil {
			t.Fatal(target, err)
		}
	}
	for _, target := range []string{"", "bad\x00target", "bad\xfftarget"} {
		if err := Target(target); !errors.Is(err, fs.ErrInvalid) {
			t.Fatal("invalid literal target", err)
		}
	}
	if err := Target(strings.Repeat("x", 1024)); !errors.Is(err, filesystem.ErrLimit) {
		t.Fatal("unqualified target length", err)
	}
	c := filesystem.Change{Operation: "ln", Path: "/source", Destination: "/alias"}
	for _, alter := range []func(*filesystem.Change){
		func(c *filesystem.Change) { c.Mode = "0755" },
		func(c *filesystem.Change) { c.Recursive = true },
		func(c *filesystem.Change) { c.Attribute = "ignored" },
		func(c *filesystem.Change) { c.Metadata = &filesystem.Metadata{} },
	} {
		bad := c
		alter(&bad)
		if err := Validate(bad); !errors.Is(err, fs.ErrInvalid) {
			t.Fatal("ignored link field accepted", bad, err)
		}
	}
}
