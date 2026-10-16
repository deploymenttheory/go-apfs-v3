package receipt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"reflect"
)

const MaxEventBytes int64 = 512 << 20

// VerifyStoredEvents checks a retained receipt and its original event stream
// against caller-declared obligations and origin. It does not grant a new
// filesystem verdict, validate output bytes or choose an inheritance policy.
func VerifyStoredEvents(ctx context.Context, directory string, want Plan, origin Origin, record Receipt, optional map[string]bool) error {
	if err := Verify(want, origin, record); err != nil {
		return err
	}
	if record.Events.Bytes > MaxEventBytes {
		return errors.New("stored execution stream exceeds bound")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	info, err := root.Lstat(record.Events.Path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() != record.Events.Bytes {
		return errors.New("stored execution stream size/type differs")
	}
	input, err := root.Open(record.Events.Path)
	if err != nil {
		return err
	}
	defer func() { _ = input.Close() }()
	bounded := &io.LimitedReader{R: &eventContextReader{ctx: ctx, input: input}, N: record.Events.Bytes + 1}
	digest := sha256.New()
	verdicts, err := CheckEvents(io.TeeReader(bounded, digest), want, optional, io.Discard)
	if err != nil {
		return err
	}
	if bounded.N != 1 || hex.EncodeToString(digest.Sum(nil)) != record.Events.SHA256 || !reflect.DeepEqual(verdicts, record.Verdicts) {
		return errors.New("stored execution bytes or actual verdicts differ")
	}
	return nil
}

type eventContextReader struct {
	ctx   context.Context
	input io.Reader
}

func (r *eventContextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.input.Read(buffer)
}
