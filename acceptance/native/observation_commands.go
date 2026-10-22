package native

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
)

// retainFailedObservationCommands also covers observer errors that return no
// observation, including failed snapshot cleanup during cross-version parity.
// The separate file preserves the original observations and continuation logs.
func retainFailedObservationCommands(work string, transcript *fixture.Transcript, resultErr error) error {
	if resultErr == nil {
		return nil
	}
	data, err := json.MarshalIndent(transcript.Commands, "", "  ")
	if err == nil {
		err = os.MkdirAll(work, 0o755)
	}
	if err == nil {
		err = os.WriteFile(filepath.Join(work, "observation-commands.json"), append(data, '\n'), 0o644)
	}
	if err != nil {
		return errors.Join(resultErr, fmt.Errorf("retain failed observation commands: %w", err))
	}
	return resultErr
}
