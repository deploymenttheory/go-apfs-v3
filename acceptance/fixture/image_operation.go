package fixture

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// imageOperation runs the attach/detach command under the same bounded,
// jittered wait. prepare re-establishes permission before every attempt; it
// may report that no command is needed, or refuse an uncertain attachment.
// Only explicit native busy results are retried. Parsing, ownership and
// filesystem verdicts remain outside the retryable command boundary.
func (d *HostDisk) imageOperation(ctx context.Context, what string, prepare func() (Command, bool, error)) (Result, error) {
	var result Result
	var busyErr error
	err := Settle(ctx, d.T, what, BusyWait, func() (bool, string, error) {
		if err := ctx.Err(); err != nil {
			return false, "", err
		}
		cmd, settled, err := prepare()
		if err != nil || settled {
			return settled, "", err
		}
		if err := ctx.Err(); err != nil {
			return false, "", err
		}
		cmd.Expected = "record"
		result = d.C.Run(ctx, cmd)
		if err := errors.Join(d.T.Record(cmd, result), ctx.Err()); err != nil {
			return false, "", err
		}
		if result.Status == 0 {
			return true, "", nil
		}
		failure := fmt.Errorf("%s: exit %d: %s", strings.Join(cmd.Argv, " "), result.Status, strings.TrimSpace(string(result.Stderr)))
		verb := cmd.Argv[1]
		if !imageOperationBusy(verb, result) {
			return false, "", failure
		}
		if verb == "attach" && len(result.Stdout) != 0 {
			return false, "", errors.Join(failure, errors.New("failed attach returned partial output; refusing another attachment"))
		}
		busyErr = failure
		return false, failure.Error(), nil
	})
	if err != nil {
		return result, errors.Join(err, busyErr)
	}
	return result, nil
}

func imageOperationBusy(verb string, result Result) bool {
	if result.Err != nil {
		return false
	}
	if result.Status == 16 {
		return true
	}
	// hdiutil also reports an attach framework refusal with status 1. Do
	// not classify arbitrary messages which merely mention a busy resource.
	return verb == "attach" && result.Status == 1 &&
		strings.TrimSpace(string(result.Stderr)) == "hdiutil: attach failed - Resource busy"
}
