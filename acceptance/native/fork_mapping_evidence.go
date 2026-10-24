package native

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

const forkMappingReceiptLimit = 64 << 20
const forkMappingReceiptMemberLimit = 16 << 20

var errForkMappingEvidence = errors.New("paired fork evidence could not be retained")

// One serial diagnostic owns this budget. Limits apply to successfully written
// receipt bytes, including the aggregate pair receipt which repeats arm data.
type forkMappingEvidence struct{ bytes int64 }

func (e *forkMappingEvidence) write(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return errors.Join(errForkMappingEvidence, err)
	}
	data = append(data, '\n')
	if int64(len(data)) > forkMappingReceiptMemberLimit || int64(len(data)) > forkMappingReceiptLimit-e.bytes {
		return fmt.Errorf("%w: receipt exceeds 16MiB member/64MiB aggregate bound", errForkMappingEvidence)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.Join(errForkMappingEvidence, err)
	}
	n, writeErr := f.Write(data)
	e.bytes += int64(n)
	if writeErr == nil && n != len(data) {
		writeErr = io.ErrShortWrite
	}
	if err := errors.Join(writeErr, f.Close()); err != nil {
		return errors.Join(errForkMappingEvidence, err)
	}
	return nil
}

// Include the unchanged writer's own receipt without rewriting its bytes.
func (e *forkMappingEvidence) include(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return errors.Join(errForkMappingEvidence, err)
	}
	if !info.Mode().IsRegular() || info.Size() > forkMappingReceiptMemberLimit || info.Size() > forkMappingReceiptLimit-e.bytes {
		return fmt.Errorf("%w: writer receipt exceeds bound", errForkMappingEvidence)
	}
	e.bytes += info.Size()
	return nil
}
