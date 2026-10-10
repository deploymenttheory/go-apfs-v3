package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/deploymenttheory/go-apfs-v3/workspace"
)

func workspaceCommand(ctx context.Context, args []string, out, diagnostics io.Writer) (err error) {
	if len(args) == 0 || args[0] != "verify" {
		return fmt.Errorf("use filesystem commands with --session; usage: apfs workspace verify [--json] WORKSPACE")
	}
	flags := flag.NewFlagSet("workspace verify", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	jsonOutput := flags.Bool("json", false, "emit preservation report")
	if err = flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return fmt.Errorf("usage: apfs workspace verify [--json] WORKSPACE")
	}
	w, err := workspace.Open(ctx, flags.Arg(0))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, w.Close()) }()
	return printWorkspaceReport(out, w.Report(), *jsonOutput)
}

func printWorkspaceReport(out io.Writer, report workspace.Report, jsonOutput bool) error {
	if jsonOutput {
		return json.NewEncoder(out).Encode(struct {
			Schema int `json:"schema"`
			workspace.Report
		}{1, report})
	}
	_, err := fmt.Fprintf(out, "Preserved %d objects in %d entries; %d unique blob bytes.\nModified files: %d; created objects: %d; metadata edits: %d; attribute edits: %d.\nMapped names: %d; symlink records: %d; hard links: %d; hard-link copies: %d.\nMetadata: %s.\n", report.Objects, report.Entries, report.StoredBytes, report.ModifiedFiles, report.CreatedObjects, report.MetadataObjects, report.AttributeObjects, report.MappedNames, report.SymlinksRecorded, report.HardLinks, report.HardLinksCopied, report.Metadata)
	return err
}
