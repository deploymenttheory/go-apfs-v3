package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/workspace"
)

func workspaceCommand(ctx context.Context, args []string, out, diagnostics io.Writer) (err error) {
	if len(args) == 0 || (args[0] != "verify" && args[0] != "replace" && args[0] != "edit") {
		return fmt.Errorf("usage: apfs workspace verify [--json] WORKSPACE; apfs workspace replace [--json] WORKSPACE PATH CONTENTS NEW_WORKSPACE; apfs workspace edit [--json] WORKSPACE CHANGES.json NEW_WORKSPACE")
	}
	flags := flag.NewFlagSet("workspace "+args[0], flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	jsonOutput := flags.Bool("json", false, "emit the preservation report as JSON")
	if err = flags.Parse(args[1:]); err != nil {
		return err
	}
	arguments := 1
	if args[0] == "replace" {
		arguments = 4
	}
	if args[0] == "edit" {
		arguments = 3
	}
	if flags.NArg() != arguments {
		return fmt.Errorf("usage: apfs workspace verify [--json] WORKSPACE; apfs workspace replace [--json] WORKSPACE PATH CONTENTS NEW_WORKSPACE; apfs workspace edit [--json] WORKSPACE CHANGES.json NEW_WORKSPACE")
	}
	w, err := workspace.Open(ctx, flags.Arg(0))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, w.Close()) }()
	if args[0] == "edit" {
		report, err := editWorkspace(ctx, w, flags.Arg(1), flags.Arg(2))
		if err != nil {
			return err
		}
		return printWorkspaceReport(out, report, *jsonOutput)
	}
	if args[0] == "replace" {
		id, err := filesystem.Lookup(ctx, w, flags.Arg(1))
		if err != nil {
			return err
		}
		data, err := block.Open(flags.Arg(2))
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, data.Close()) }()
		report, err := w.ReplaceData(ctx, []workspace.DataReplacement{{Object: id, Data: data}}, flags.Arg(3), workspace.Limits{})
		if err != nil {
			return err
		}
		return printWorkspaceReport(out, report, *jsonOutput)
	}
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
