package receipt

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStoredEventsRequireOriginalBytesAndIndependentObligations(t *testing.T) {
	for _, scenario := range []string{"valid", "changed-bytes", "truncated", "wrong-origin", "missing-case", "skipped-case", "rehashed-skipped-case", "oversized-declaration", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			plan := referencePlan()
			record := referenceReceipt(t, plan)
			origin := record.Origin
			var stream bytes.Buffer
			for _, event := range executionEvents(plan) {
				if err := json.NewEncoder(&stream).Encode(event); err != nil {
					t.Fatal(err)
				}
			}
			data := stream.Bytes()
			digest := sha256.Sum256(data)
			record.Events.Bytes, record.Events.SHA256 = int64(len(data)), hex.EncodeToString(digest[:])
			switch scenario {
			case "changed-bytes":
				data = append(data, '\n')
			case "truncated":
				data = data[:len(data)-1]
			case "wrong-origin":
				origin.Run = "another-run"
			case "missing-case":
				plan.Cases = plan.Cases[:1]
			case "skipped-case", "rehashed-skipped-case":
				data = []byte(strings.Replace(string(data), `"Action":"pass","Package":"`+AcceptancePackage+`","Test":"`+plan.Cases[0].Test+`"`,
					`"Action":"skip","Package":"`+AcceptancePackage+`","Test":"`+plan.Cases[0].Test+`"`, 1))
				if scenario == "rehashed-skipped-case" {
					digest = sha256.Sum256(data)
					record.Events.Bytes, record.Events.SHA256 = int64(len(data)), hex.EncodeToString(digest[:])
				}
			case "oversized-declaration":
				record.Events.Bytes = MaxEventBytes + 1
			}
			directory := t.TempDir()
			if err := os.WriteFile(filepath.Join(directory, record.Events.Path), data, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "cancelled" {
				cancel()
			}
			err := VerifyStoredEvents(ctx, directory, plan, origin, record, nil)
			if (err == nil) != (scenario == "valid") {
				t.Fatal("stored execution admission", scenario, err)
			}
		})
	}
}
