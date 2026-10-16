package main

import (
	"errors"
	"fmt"
	"strings"
)

// The workflow contract already binds all bytes. Additionally enforce the
// replay convention: every executor must retain its own original ledger even
// when its output archives also carry copies to Apple readback jobs.
func auditReplayEvidence(workflow string) error {
	_, jobs, found := strings.Cut(workflow, "\njobs:\n")
	if !found {
		return errors.New("workflow jobs missing")
	}
	matches := jobPattern.FindAllStringSubmatchIndex(jobs, -1)
	for index, match := range matches {
		end := len(jobs)
		if index+1 < len(matches) {
			end = matches[index+1][0]
		}
		section := jobs[match[0]:end]
		if !strings.Contains(section, "go run ./acceptance/qualification") || !strings.Contains(section, " -replay") {
			continue
		}
		_, evidence, exists := strings.Cut(section, "      - name: Retain required case execution evidence\n")
		if !exists {
			return fmt.Errorf("replay executor %s must retain original execution evidence", jobs[match[2]:match[3]])
		}
		evidence, _, _ = strings.Cut(evidence, "\n      - ")
		for _, required := range []string{"if: always()", "uses: actions/upload-artifact@", "name: qualification-", "${{ github.job }}", "${{ strategy.job-index }}", "include-hidden-files: true", "replay-*/plan.json", "replay-*/receipt.json", "replay-*/events.jsonl", "replay-*/inputs.json", "replay-*/source-inputs.json", "if-no-files-found: error"} {
			if !strings.Contains(evidence, required) {
				return fmt.Errorf("replay evidence missing required retention setting: %s", required)
			}
		}
	}
	return nil
}
