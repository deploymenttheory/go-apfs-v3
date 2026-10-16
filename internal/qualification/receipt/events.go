package receipt

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/corpus"
)

const AcceptancePackage = "github.com/deploymenttheory/go-apfs-v3/acceptance"

// Event is Go's test2json wire contract. Output is streamed rather than retained
// in memory. Unknown additional Go fields remain compatible; verdict admission
// requires an explicit run/pass pair for every independently required node.
type Event struct {
	Action  string
	Package string
	Test    string
	Output  string
}

func CheckEvents(input io.Reader, plan Plan, optional map[string]bool, output io.Writer) ([]Verdict, error) {
	if err := plan.Validate(); err != nil {
		return nil, err
	}
	states := map[string]string{}
	packageName := AcceptancePackage
	if plan.Stage != "replay" {
		packageName = "apple-native"
	}
	for _, name := range plan.RequiredRuns {
		states[name] = "absent"
	}
	packageRun, packagePass := false, false
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64<<10), 8<<20)
	for scanner.Scan() {
		var fields map[string]json.RawMessage
		if err := corpus.StrictJSON(scanner.Bytes(), &fields); err != nil {
			return nil, fmt.Errorf("invalid/duplicate Go event fields: %w", err)
		}
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, fmt.Errorf("invalid Go execution event: %w", err)
		}
		if event.Output != "" {
			if _, err := io.WriteString(output, event.Output); err != nil {
				return nil, err
			}
		}
		if event.Action == "fail" || event.Action == "build-fail" || event.Action == "build-output" && strings.Contains(event.Output, "FAIL") {
			return nil, fmt.Errorf("test/build failure: %s %s", event.Package, event.Test)
		}
		if event.Package != packageName {
			continue
		}
		if event.Test == "" {
			switch event.Action {
			case "start":
				if packageRun || packagePass {
					return nil, errors.New("duplicate acceptance package execution")
				}
				packageRun = true
			case "pass":
				if !packageRun || packagePass {
					return nil, errors.New("acceptance package verdict out of order")
				}
				packagePass = true
			case "skip":
				return nil, errors.New("acceptance package did not execute")
			}
			continue
		}
		if optional[event.Test] {
			// An unavailable continuation has no verdict and cannot satisfy a
			// continuation obligation in another invocation or completion plan.
			continue
		}
		state, required := states[event.Test]
		if !required {
			return nil, fmt.Errorf("unplanned test execution: %s", event.Test)
		}
		switch event.Action {
		case "run":
			if !packageRun || packagePass || state != "absent" {
				return nil, fmt.Errorf("duplicate/out-of-order execution: %s", event.Test)
			}
			states[event.Test] = "running"
		case "pass":
			if state != "running" {
				return nil, fmt.Errorf("verdict without a unique execution: %s", event.Test)
			}
			states[event.Test] = "passed"
		case "skip":
			return nil, fmt.Errorf("required case skipped: %s", event.Test)
		case "output", "pause", "cont":
			if state != "running" {
				return nil, fmt.Errorf("event outside active execution: %s", event.Test)
			}
		default:
			return nil, fmt.Errorf("unknown test event: %s", event.Action)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if !packageRun || !packagePass {
		return nil, errors.New("acceptance package completion missing")
	}
	for _, name := range plan.RequiredRuns {
		if states[name] != "passed" {
			return nil, fmt.Errorf("required execution missing: %s", name)
		}
	}
	verdicts := make([]Verdict, 0, len(plan.Cases))
	for _, c := range plan.Cases {
		verdicts = append(verdicts, Verdict{c, "pass"})
	}
	return verdicts, nil
}
