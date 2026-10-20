package fixture

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// Budget bounds a wait for macOS disk state: at most Attempts checks, the
// pause before each retry drawn uniformly from zero to an exponentially
// growing ceiling (Base doubling up to Max), so parallel lanes waiting on
// DiskArbitration do not retry in lockstep.
type Budget struct {
	Attempts  int
	Base, Max time.Duration
}

// Budgets for the waits this package performs. Short waits cover
// DiskArbitration catching up with an attach, mount or detach; the busy
// budget covers a disk-image framework still releasing a previous image;
// migration covers FileVault converting a volume.
var (
	ShortWait     = Budget{Attempts: 10, Base: 100 * time.Millisecond, Max: time.Second}
	BusyWait      = Budget{Attempts: 6, Base: 250 * time.Millisecond, Max: 2 * time.Second}
	MigrationWait = Budget{Attempts: 60, Base: time.Second, Max: 3 * time.Second}
)

// Check reports whether the awaited state holds. It returns settled true
// when it does; settled false with a reason when the state may still
// arrive; and an error when waiting cannot help, which ends the wait at
// once. A check observes state or performs one idempotent step whose
// failure it classifies itself: callers never hand it a command to repeat
// blindly, and verdicts such as digests or comparisons are never checks.
type Check func() (settled bool, reason string, err error)

// sleep and jitter are replaced by tests.
var (
	sleep = func(ctx context.Context, d time.Duration) error {
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		}
	}
	jitter = func(ceiling time.Duration) time.Duration {
		if ceiling <= 0 {
			return 0
		}
		return time.Duration(rand.Int64N(int64(ceiling) + 1))
	}
)

// Settle runs check until it reports the state settled, it returns an
// error, or the budget is spent. Every retry is recorded in t (when not
// nil) and counted under what, so a run can report how often each wait
// fired.
func Settle(ctx context.Context, t *Transcript, what string, budget Budget, check Check) error {
	start := time.Now()
	ceiling := budget.Base
	var reason string
	for attempt := 1; ; attempt++ {
		settled, why, err := check()
		if err != nil {
			return err
		}
		if settled {
			return nil
		}
		reason = why
		if attempt >= budget.Attempts {
			break
		}
		countWait(what)
		if t != nil {
			t.Commands = append(t.Commands, schema.Command{Label: "wait:" + what, Argv: []string{"wait", what, strconv.Itoa(attempt)}, Expected: "record", Status: "retry", StderrText: why})
		}
		if err := sleep(ctx, jitter(ceiling)); err != nil {
			return err
		}
		ceiling = min(ceiling*2, budget.Max)
	}
	return &NotSettledError{What: what, Checks: budget.Attempts, Waited: time.Since(start).Round(time.Millisecond), Reason: reason}
}

// NotSettledError reports a wait whose budget was spent; callers that can
// proceed without the state (and let a later step decide) test for it.
type NotSettledError struct {
	What   string
	Checks int
	Waited time.Duration
	Reason string
}

func (e *NotSettledError) Error() string {
	return fmt.Sprintf("%s did not settle after %d checks over %s: %s", e.What, e.Checks, e.Waited, e.Reason)
}

var (
	waitsMu sync.Mutex
	waits   = map[string]int{}
)

func countWait(what string) {
	waitsMu.Lock()
	defer waitsMu.Unlock()
	waits[what]++
}

// WaitCount is how many retries one kind of wait needed.
type WaitCount struct {
	What    string
	Retries int
}

// WaitCounts reports the retries every kind of wait needed so far in this
// process, most frequent first.
func WaitCounts() []WaitCount {
	waitsMu.Lock()
	defer waitsMu.Unlock()
	out := make([]WaitCount, 0, len(waits))
	for what, n := range waits {
		out = append(out, WaitCount{what, n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Retries != out[j].Retries {
			return out[i].Retries > out[j].Retries
		}
		return out[i].What < out[j].What
	})
	return out
}
