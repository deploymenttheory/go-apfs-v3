package main

import (
	"flag"
	"fmt"
	"io"
	"io/fs"

	"github.com/deploymenttheory/go-apfs-v3/pack"
)

func addPackCompressionFlag(f *flag.FlagSet) *string {
	return f.String("file-compression", "preserve", "file storage: preserve, zlib or none; independent of DMG encoding")
}

func validatePackCompression(policy string) error {
	if policy != "preserve" && policy != "zlib" && policy != "none" {
		return fmt.Errorf("--file-compression must be preserve, zlib or none: %w", fs.ErrInvalid)
	}
	return nil
}

func writePackCompressionReport(out io.Writer, policy string, outcomes []pack.CompressionOutcome) error {
	compressed, decompressed, skipped := 0, 0, 0
	for _, result := range outcomes {
		switch result.Action {
		case "compressed":
			compressed++
		case "decompressed":
			decompressed++
		case "uncompressed":
			skipped++
		}
	}
	if _, err := fmt.Fprintf(out, "File compression: %s; %d compressed, %d decompressed, %d left uncompressed\n", policy, compressed, decompressed, skipped); err != nil {
		return err
	}
	for _, result := range outcomes {
		if result.Action != "uncompressed" {
			continue
		}
		path := result.Path
		if result.Volume != "" {
			path = result.Volume + ":" + path
		}
		if _, err := fmt.Fprintf(out, "Left uncompressed: %q (%s)\n", path, result.Reason); err != nil {
			return err
		}
	}
	return nil
}
