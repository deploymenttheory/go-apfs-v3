package fixture

import (
	"compress/gzip"
	"io"
	"os"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// Fields that the derivation path needs to hand the observer.
type captureCredentials struct {
	currentPasswordRef string
	currentRejected    []string
	sentinels          []schema.Sentinel
}

func secondsToDuration(s int) time.Duration { return time.Duration(s) * time.Second }

func gunzipCopy(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	gz, err := gzip.NewReader(in)
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, gz); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
