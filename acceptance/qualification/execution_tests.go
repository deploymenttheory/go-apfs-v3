package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/corpus"
	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/receipt"
)

// Go emits all package and test verdicts in the original stream, including
// ordinary unit tests outside the registered acceptance cases. Keep those
// executions so a scheduling change cannot silently drop library assertions.
type executionIndexedTest struct {
	Receipt string `json:"original_receipt_sha256"`
	Package string `json:"package"`
	Test    string `json:"test,omitempty"`
	Status  string `json:"status"`
}

func indexReplayTests(ctx context.Context, directory, original string, record receipt.Receipt) ([]executionIndexedTest, error) {
	if record.Plan.Stage != "replay" || record.Events.Bytes > receipt.MaxEventBytes {
		return nil, errors.New("bounded original Go execution stream required")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	info, err := root.Lstat(record.Events.Path)
	if err != nil || !info.Mode().IsRegular() || info.Size() != record.Events.Bytes {
		return nil, errors.Join(err, errors.New("original Go execution stream size or type changed"))
	}
	input, err := root.Open(record.Events.Path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = input.Close() }()
	digest := sha256.New()
	bounded := &io.LimitedReader{R: input, N: record.Events.Bytes + 1}
	scanner := bufio.NewScanner(io.TeeReader(bounded, digest))
	scanner.Buffer(make([]byte, 64<<10), 8<<20)
	states := map[string]string{}
	identities := map[string]executionIndexedTest{}
	for scanner.Scan() {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		var fields map[string]json.RawMessage
		if err = corpus.StrictJSON(scanner.Bytes(), &fields); err != nil {
			return nil, err
		}
		var event receipt.Event
		if err = json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, err
		}
		if event.Action == "fail" || event.Action == "build-fail" {
			return nil, errors.New("failed original Go execution cannot enter a coverage comparison")
		}
		if !slices.Contains([]string{"start", "run", "pass", "skip"}, event.Action) {
			continue
		}
		if event.Package == "" || strings.ContainsRune(event.Package+event.Test, '\x00') {
			return nil, errors.New("original Go execution lacks an unambiguous package/test identity")
		}
		key := event.Package + "\x00" + event.Test
		state := states[key]
		if event.Action == "start" || event.Action == "run" {
			if state != "" || (event.Test == "") != (event.Action == "start") || event.Test != "" && states[event.Package+"\x00"] != "running" {
				return nil, errors.New("duplicate or out-of-order original Go execution")
			}
			if len(states) >= 100000 {
				return nil, errors.New("original Go test inventory exceeds bound")
			}
			states[key] = "running"
			continue
		}
		if state != "running" || event.Test != "" && states[event.Package+"\x00"] != "running" {
			return nil, errors.New("original Go verdict lacks its unique active execution")
		}
		states[key] = event.Action
		identities[key] = executionIndexedTest{Receipt: original, Package: event.Package, Test: event.Test, Status: event.Action}
	}
	if err = scanner.Err(); err != nil {
		return nil, err
	}
	if bounded.N != 1 || hex.EncodeToString(digest.Sum(nil)) != record.Events.SHA256 {
		return nil, errors.New("original Go event bytes changed before coverage indexing")
	}
	if len(identities) == 0 || len(identities) != len(states) {
		return nil, errors.New("original Go test or package completion missing")
	}
	result := make([]executionIndexedTest, 0, len(identities))
	for _, item := range identities {
		result = append(result, item)
	}
	slices.SortFunc(result, func(a, b executionIndexedTest) int {
		if order := strings.Compare(a.Package, b.Package); order != 0 {
			return order
		}
		return strings.Compare(a.Test, b.Test)
	})
	return result, nil
}
