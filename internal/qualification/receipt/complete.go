package receipt

import (
	"errors"
	"fmt"
)

type Expected struct {
	Plan   Plan   `json:"plan"`
	Origin Origin `json:"origin"`
}

// Complete joins exactly the caller-declared executions. Required obligations
// never come from the available receipt directory. There is no "best effort"
// mode and no implicit cross-run, cross-host or cross-revision inheritance.
func Complete(expected []Expected, actual []Receipt) error {
	if len(expected) == 0 || len(expected) != len(actual) {
		return errors.New("complete qualification receipt set missing/extra")
	}
	want := map[string]Expected{}
	for _, execution := range expected {
		fingerprint, err := execution.Plan.Fingerprint()
		if err != nil {
			return err
		}
		if _, exists := want[fingerprint]; exists {
			return errors.New("duplicate required execution fingerprint")
		}
		want[fingerprint] = execution
	}
	for _, record := range actual {
		execution, exists := want[record.Fingerprint]
		if !exists {
			return fmt.Errorf("unexpected/duplicate receipt fingerprint: %s", record.Fingerprint)
		}
		if err := Verify(execution.Plan, execution.Origin, record); err != nil {
			return err
		}
		delete(want, record.Fingerprint)
	}
	if len(want) != 0 {
		return errors.New("required qualification executions absent")
	}
	return nil
}
