package fixture

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExpandResolvesEveryReferenceKind(t *testing.T) {
	payloads := t.TempDir()
	if err := os.WriteFile(filepath.Join(payloads, "attr"), []byte{0xfe, 0xed}, 0o644); err != nil {
		t.Fatal(err)
	}
	v := &Vars{Payloads: payloads, Passwords: map[string]string{"primary": "päss"}}
	v.Set("MOUNT", "/tmp/m")
	v.SetKeyed("MOUNT", "Primary", "/tmp/primary")
	v.SetKeyed("SNAPSHOT", "before", "com.apple.asr.12")
	cases := map[string]string{
		"$MOUNT/Fixture":                "/tmp/m/Fixture",
		"$MOUNT:Primary/Fixture/data":   "/tmp/primary/Fixture/data",
		"-E -S $PASSWORD:primary":       "-E -S päss",
		"$HEX:attr":                     "feed",
		"$FILE:attr":                    filepath.Join(payloads, "attr"),
		"$SNAPSHOT:before":              "com.apple.asr.12",
		"no references":                 "no references",
		"$MOUNT:Primary/a and $MOUNT/b": "/tmp/primary/a and /tmp/m/b",
	}
	for in, want := range cases {
		got, err := v.Expand(in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if got != want {
			t.Errorf("%s: got %q want %q", in, got, want)
		}
	}
}

func TestExpandRejectsUnknownReferences(t *testing.T) {
	v := &Vars{Payloads: t.TempDir()}
	v.Set("MOUNT", "/m")
	for _, in := range []string{"$DEV", "$MOUNT:Secondary", "$PASSWORD:x", "$HEX:missing", "$FILE:missing"} {
		if _, err := v.Expand(in); err == nil {
			t.Errorf("%s was expanded", in)
		}
	}
}
