package fixture

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// instantWaits replaces the helper's clock so tests do not sleep, and
// records the jitter ceilings it was asked for.
func instantWaits(t *testing.T) *[]time.Duration {
	t.Helper()
	var ceilings []time.Duration
	oldSleep, oldJitter := sleep, jitter
	sleep = func(context.Context, time.Duration) error { return nil }
	jitter = func(ceiling time.Duration) time.Duration { ceilings = append(ceilings, ceiling); return ceiling }
	t.Cleanup(func() { sleep, jitter = oldSleep, oldJitter })
	return &ceilings
}

func TestSettleRetriesUntilTheStateHoldsAndRecordsEachWait(t *testing.T) {
	ceilings := instantWaits(t)
	tr := &Transcript{}
	checks := 0
	err := Settle(context.Background(), tr, "test-settles", Budget{Attempts: 5, Base: 100 * time.Millisecond, Max: 300 * time.Millisecond}, func() (bool, string, error) {
		checks++
		return checks == 4, "not yet", nil
	})
	if err != nil || checks != 4 {
		t.Fatalf("settled after %d checks with %v, want 4 checks and no error", checks, err)
	}
	if len(tr.Commands) != 3 || tr.Commands[0].Label != "wait:test-settles" || tr.Commands[0].StderrText != "not yet" {
		t.Fatalf("each retry must be in the transcript with its reason, got %+v", tr.Commands)
	}
	want := []time.Duration{100 * time.Millisecond, 200 * time.Millisecond, 300 * time.Millisecond}
	if len(*ceilings) != len(want) {
		t.Fatalf("jitter ceilings %v, want %v", *ceilings, want)
	}
	for i := range want {
		if (*ceilings)[i] != want[i] {
			t.Fatalf("jitter ceilings %v, want %v (doubling up to the maximum)", *ceilings, want)
		}
	}
	found := false
	for _, c := range WaitCounts() {
		if c.What == "test-settles" && c.Retries >= 3 {
			found = true
		}
	}
	if !found {
		t.Fatalf("retries are counted per kind of wait, got %+v", WaitCounts())
	}
}

func TestSettleReturnsAnErrorAtOnce(t *testing.T) {
	instantWaits(t)
	boom := errors.New("not a wait")
	checks := 0
	err := Settle(context.Background(), nil, "test-error", BusyWait, func() (bool, string, error) {
		checks++
		return false, "", boom
	})
	if !errors.Is(err, boom) || checks != 1 {
		t.Fatalf("an error must end the wait at once, got %v after %d checks", err, checks)
	}
}

func TestSettleReportsWhatDidNotSettleWhenTheBudgetIsSpent(t *testing.T) {
	instantWaits(t)
	checks := 0
	err := Settle(context.Background(), nil, "test-spent", Budget{Attempts: 3, Base: time.Millisecond, Max: time.Millisecond}, func() (bool, string, error) {
		checks++
		return false, "still missing", nil
	})
	var notSettled *NotSettledError
	if !errors.As(err, &notSettled) || checks != 3 || !strings.Contains(err.Error(), "test-spent") || !strings.Contains(err.Error(), "still missing") {
		t.Fatalf("a spent budget must name the wait and its last reason after exactly the budgeted checks, got %v after %d checks", err, checks)
	}
}

func TestSettleStopsWhenTheContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := Settle(ctx, nil, "test-cancel", ShortWait, func() (bool, string, error) { return false, "waiting", nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled context must end the wait, got %v", err)
	}
}
