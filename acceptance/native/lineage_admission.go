package native

import "sync"

// lineageAdmission bounds complete filesystem lineages, including their cleanup.
// The caller supplies priority order; acquiring a slot before starting a callback
// prevents a later lineage from taking the place of an earlier waiting one.
// One admission pool is shared by both native tests when all phases run together.
type lineageAdmission struct {
	slots chan struct{}
}

func newLineageAdmission(limit int) *lineageAdmission {
	if limit < 1 {
		panic("native lineage parallelism must be positive")
	}
	return &lineageAdmission{slots: make(chan struct{}, limit)}
}

// run waits for every callback, even when an earlier subtest reports failure.
// Callbacks must return only after the entire lineage and its cleanup finish.
func (a *lineageAdmission) run(keys []string, run func(string)) {
	var done sync.WaitGroup
	for _, key := range keys {
		a.slots <- struct{}{}
		done.Go(func() {
			defer func() { <-a.slots }()
			run(key)
		})
	}
	done.Wait()
}
