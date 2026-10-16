package main

import (
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/receipt"
)

// expectedCaseOutputs is the reviewed transport contract of existing writers.
// It is evaluated before execution, independently of whichever files appear.
func expectedCaseOutputs(spec replayTest, c receipt.Case) []string {
	if spec.Output == "" {
		return nil
	}
	root := path.Join(spec.Output, "macos-"+strconv.Itoa(c.Source))
	id := path.Base(c.NativeCase)
	variant := c.Variant
	var names []string
	add := func(parts ...string) { names = append(names, path.Join(append([]string{root}, parts...)...)) }
	switch spec.Layout {
	case "construction", "containers":
		if spec.Layout == "containers" {
			root = path.Join(root, "containers")
		}
		root = path.Join(root, id)
		if slices.Contains([]string{"UDRO", "UDZO"}, variant) {
			add(variant + ".dmg")
		}
		if encoding, _, ok := strings.Cut(variant, "/encrypted-aes"); ok {
			add("encrypted", encoding+".dmg")
		}
		if strings.HasPrefix(variant, "file-compression/") {
			encoding := "UDRO"
			if strings.Contains(id, "case-sensitive") || id == "hfsx" {
				encoding = "UDZO"
			}
			add(variant, encoding+".dmg")
			add(variant, "report.json")
		}
		if variant == "empty/UDZO" {
			add("empty", "UDZO.dmg")
		}
	case "repacking":
		if strings.HasPrefix(variant, "raw-encrypted") {
			if strings.Contains(variant, "encrypted-aes") {
				add("hfsplus-encrypted-raw", "encrypted", "UDZO.dmg")
			} else {
				add("hfsplus-encrypted-raw", "UDZO.dmg")
			}
			break
		}
		root = path.Join(root, id)
		if slices.Contains([]string{"UDRO", "UDZO"}, variant) {
			add(variant + ".dmg")
		}
		if encoding, _, ok := strings.Cut(variant, "/encrypted-aes"); ok {
			add("encrypted", encoding+".dmg")
		}
		if strings.HasPrefix(variant, "encrypted-input/") {
			add(strings.TrimPrefix(variant, "encrypted-input/") + ".dmg")
		}
	case "statistics-transitions":
		if segment, encoding, ok := strings.Cut(variant, "/"); ok {
			add(id, segment+"-"+encoding+".dmg")
		}
	case "checkpoint-recovery":
		if strings.HasPrefix(variant, "interrupted-") {
			stem := "fault-" + strings.TrimPrefix(variant, "interrupted-")
			add(stem + ".dmg")
			add(stem + "-interrupted.raw.gz")
			add("faults.json")
			break
		}
		if variant == "UDRO" || variant == "UDZO" {
			add(id + "-" + variant + ".dmg")
			if variant == "UDRO" {
				add(id + "-edited.dmg")
			}
		}
	default:
		if variant == "" {
			switch spec.Input {
			case "preservation":
				add(id, "workspace", "metadata", "manifest.json")
				for _, name := range []string{"example.txt", "empty", "binary.bin"} {
					add(id, "appledouble", id+"-"+name+".appledouble")
				}
			case "replacement", "tree-edits", "metadata-edits", "file-commands":
				for _, state := range []string{"before", "after"} {
					add(id, state, "metadata", "manifest.json")
				}
			}
			break
		}
		if variant == "catalog" || variant == "catalog-final" {
			add(id, variant+".dmg")
			break
		}
		encoding, step, _ := strings.Cut(variant, "/")
		if encoding != "UDRO" && encoding != "UDZO" {
			break
		}
		if step != "" {
			add(id, step+"-"+encoding+".dmg")
			break
		}
		var phases []string
		switch spec.Input {
		case "apfs-editing", "hfs-editing", "hfs-journaled-editing":
			phases = []string{"peak", "final"}
		case "apfs-directory-editing":
			phases = []string{"catalog", "catalog-final"}
		case "apfs-metadata-editing", "hfs-metadata-editing", "hfs-journaled-metadata-editing":
			phases = []string{"metadata", "metadata-final"}
		case "apfs-link-editing", "hfs-link-editing", "hfs-journaled-link-editing":
			phases = []string{"links", "links-final", "removed"}
		case "apfs-copy", "hfs-copy", "hfs-journaled-copy":
			phases = []string{"copy", "copy-final"}
		case "apfs-geometry", "hfs-metadata-growth", "hfs-fragmented-metadata", "hfs-metadata-lifecycle":
			phases = []string{"edited"}
		default:
			add(id + "-" + encoding + ".dmg")
			if spec.Input == "hfs-recovery" && encoding == "UDRO" {
				add(id + "-edited.dmg")
			}
		}
		for _, phase := range phases {
			add(id, phase+"-"+encoding+".dmg")
		}
	}
	slices.Sort(names)
	return names
}
