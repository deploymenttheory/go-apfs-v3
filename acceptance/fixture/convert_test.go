package fixture

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"
)

type conversionCommander struct {
	commands []Command
	result   Result
}

func (c *conversionCommander) Run(_ context.Context, cmd Command) Result {
	c.commands = append(c.commands, cmd)
	return c.result
}

func TestConvertUsesExplicitRawInputAndExactEncryptionPolicy(t *testing.T) {
	password := []byte("exact public password λ\nwith trailing space ")
	for _, tc := range []struct {
		name, source string
		opts         ConvertOptions
		want         []string
	}{
		{
			name: "ordinary image with raw suffix", source: "image.raw",
			want: []string{"hdiutil", "convert", "image.raw", "-format", "UDZO", "-o", "output.dmg"},
		},
		{
			name: "raw sectors with image suffix", source: "sectors.dmg", opts: ConvertOptions{Raw: true},
			want: []string{"hdiutil", "convert", "sectors.dmg", "-format", "UDZO", "-srcimagekey", "diskimage-class=CRawDiskImage", "-o", "output.dmg"},
		},
		{
			name: "raw AES-128", source: "sectors", opts: ConvertOptions{Raw: true, Encryption: "AES-128", Password: password},
			want: []string{"hdiutil", "convert", "sectors", "-format", "UDZO", "-srcimagekey", "diskimage-class=CRawDiskImage", "-encryption", "AES-128", "-stdinpass", "-o", "output.dmg"},
		},
		{
			name: "raw AES-256", source: "sectors", opts: ConvertOptions{Raw: true, Encryption: "AES-256", Password: password},
			want: []string{"hdiutil", "convert", "sectors", "-format", "UDZO", "-srcimagekey", "diskimage-class=CRawDiskImage", "-encryption", "AES-256", "-stdinpass", "-o", "output.dmg"},
		},
		{
			name: "ordinary encrypted image", source: "image.raw", opts: ConvertOptions{Encryption: "AES-256", Password: password},
			want: []string{"hdiutil", "convert", "image.raw", "-format", "UDZO", "-encryption", "AES-256", "-stdinpass", "-o", "output.dmg"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			commander := &conversionCommander{}
			disk := &HostDisk{C: commander, T: &Transcript{}}
			if err := disk.Convert(context.Background(), tc.source, "UDZO", "output.dmg", tc.opts); err != nil {
				t.Fatal(err)
			}
			if len(commander.commands) != 1 {
				t.Fatal("unexpected native command count", len(commander.commands))
			}
			if !slices.Equal(commander.commands[0].Argv, tc.want) {
				t.Fatal("source recognition or output encryption command differs", commander.commands[0].Argv, tc.want)
			}
			var wantStdin []byte
			if tc.opts.Encryption != "" {
				wantStdin = append(bytes.Clone(password), 0)
			}
			if !bytes.Equal(commander.commands[0].Stdin, wantStdin) || !bytes.Equal(password, []byte("exact public password λ\nwith trailing space ")) {
				t.Fatal("conversion changed password bytes or stdin framing")
			}
		})
	}
}

func TestConvertReturnsNativeFailureWithoutRetry(t *testing.T) {
	commander := &conversionCommander{result: Result{Status: 1, Stderr: []byte("image not recognized")}}
	transcript := &Transcript{}
	disk := &HostDisk{C: commander, T: transcript}
	err := disk.Convert(context.Background(), "sectors", "UDZO", "output.dmg", ConvertOptions{Raw: true, Encryption: "AES-128", Password: []byte("public")})
	if err == nil || !strings.Contains(err.Error(), "image not recognized") || len(commander.commands) != 1 || len(transcript.Commands) != 1 || transcript.Commands[0].Status != "1" {
		t.Fatal("native conversion failure was lost or retried", err)
	}
}
