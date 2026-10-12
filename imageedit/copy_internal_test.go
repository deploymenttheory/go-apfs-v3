package imageedit

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/edit"
)

type copyInput struct {
	*bytes.Reader
	closed                int
	readError, closeError error
}

func (v *copyInput) Close() error { v.closed++; return v.closeError }
func (v *copyInput) ReadAt(p []byte, off int64) (int, error) {
	if v.readError != nil {
		return 0, v.readError
	}
	return v.Reader.ReadAt(p, off)
}

func TestCopyOwnsInputsOnlyAfterSuccessfulReadAndClose(t *testing.T) {
	for _, fault := range []string{"read", "close", "cancel"} {
		t.Run(fault, func(t *testing.T) {
			plan := copyPlan{limits: edit.DefaultLimits()}
			defer plan.close()
			input := &copyInput{Reader: bytes.NewReader([]byte("immutable input"))}
			ctx := context.Background()
			want := error(io.ErrClosedPipe)
			switch fault {
			case "read":
				input.readError = want
			case "close":
				input.closeError = want
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = context.Canceled
			}
			var total int64
			if _, err := plan.own(ctx, input, &total); !errors.Is(err, want) || input.closed != 1 {
				t.Fatal("input failure or ownership close lost", err, input.closed)
			}
		})
	}
}

func TestCopyScratchLimitSpansAllBatchCommands(t *testing.T) {
	plan := copyPlan{limits: edit.DefaultLimits()}
	plan.limits.ValueBytes, plan.limits.TotalBytes = 5, 5
	defer plan.close()
	var firstCommand, secondCommand int64
	first := &copyInput{Reader: bytes.NewReader([]byte("first"))}
	owned, err := plan.own(context.Background(), first, &firstCommand)
	if err != nil || first.closed != 1 {
		t.Fatal(err, first.closed)
	}
	second := &copyInput{Reader: bytes.NewReader([]byte("x"))}
	if _, err = plan.own(context.Background(), second, &secondCommand); !errors.Is(err, filesystem.ErrLimit) || second.closed != 1 {
		t.Fatal("batch total reset or input not closed", err, second.closed)
	}
	data := make([]byte, owned.Size())
	if _, err = owned.ReadAt(data, 0); err != nil || string(data) != "first" {
		t.Fatal("owned payload changed after refusal", err)
	}
}
