package completeoutput

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// Every failed write/flush and a cancelled commit must leave a new destination
// absent. A pre-existing entry must survive even a publication-time race.
func TestFailedOutputIsNeverPublished(t *testing.T) {
	for _, cause := range []string{"write", "flush", "cancel", "race"} {
		t.Run(cause, func(t *testing.T) {
			ctx, stop := context.WithCancel(context.Background())
			defer stop()
			path := filepath.Join(t.TempDir(), "output")
			err := Publish(ctx, path, func(out io.Writer) error {
				if _, e := out.Write([]byte("incomplete")); e != nil {
					return e
				}
				switch cause {
				case "write":
					return io.ErrShortWrite
				case "flush":
					return out.(*os.File).Close()
				case "cancel":
					stop()
				case "race":
					return os.WriteFile(path, []byte("existing"), 0600)
				}
				return nil
			})
			if err == nil {
				t.Fatal("failure published successfully")
			}
			b, e := os.ReadFile(path)
			if cause == "race" {
				if e != nil || string(b) != "existing" {
					t.Fatal("raced destination overwritten")
				}
			} else if !errors.Is(e, fs.ErrNotExist) {
				t.Fatal("partial destination visible", e)
			}
			matches, e := filepath.Glob(filepath.Join(filepath.Dir(path), ".apfs-pack-*"))
			if e != nil || len(matches) != 0 {
				t.Fatal("scratch leaked", matches, e)
			}
		})
	}
}
