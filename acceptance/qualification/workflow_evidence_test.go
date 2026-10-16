package main

import (
	"strings"
	"testing"
)

func TestReplayExecutorCannotRelyOnlyOnReadbackCopies(t *testing.T) {
	data, err := regularFile("../..", ".github/workflows/native.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(data)
	if err = auditReplayEvidence(workflow); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"name: Retain required case execution evidence", "if: always()", "include-hidden-files: true", "replay-*/source-inputs.json", "replay-*/events.jsonl", "if-no-files-found: error"} {
		t.Run(mutation, func(t *testing.T) {
			// Change only the producer's proof step, preserving the independent
			// readback job and its copied producer receipts.
			start := strings.Index(workflow, "\n  replay:\n")
			finish := strings.Index(workflow[start:], "\n  image_building_replay:\n") + start
			start += strings.Index(workflow[start:finish], "      - name: Retain required case execution evidence\n")
			changed := workflow[:start] + strings.Replace(workflow[start:finish], mutation, "missing-setting", 1) + workflow[finish:]
			if err := auditReplayEvidence(changed); err == nil {
				t.Fatal("producer lost original evidence without invalidating the workflow")
			}
		})
	}
}
