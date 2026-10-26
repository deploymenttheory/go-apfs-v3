package native

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// ShareIdenticalOutputs keeps every host's path and manifest, while avoiding
// three physical copies of deterministic output bytes on the native runner.
// Verify every original copy before replacing anything: a corrupt host's copy
// must fail, never be hidden by substituting another host's correct bytes.
// Outputs are immutable inputs; continuations edit separate writable copies.
func ShareIdenticalOutputs(hosts map[string]HostOutputs) (int64, error) {
	byDigest := map[string][]string{}
	sizes := map[string]int64{}
	for host, outputs := range hosts {
		for _, output := range outputs.Manifest.Outputs {
			if !filepath.IsLocal(output.File) {
				return 0, fmt.Errorf("%s: nonlocal output path %q", host, output.File)
			}
			name := filepath.Join(outputs.Dir, output.File)
			info, err := os.Lstat(name)
			if err != nil {
				return 0, err
			}
			if !info.Mode().IsRegular() || info.Size() != output.Bytes {
				return 0, fmt.Errorf("%s: output %s changed size or type", host, output.Name)
			}
			digest, err := schema.FileDigest(name)
			if err != nil {
				return 0, err
			}
			if digest != output.SHA256 {
				return 0, fmt.Errorf("%s: output %s digest %s, manifest says %s", host, output.Name, digest, output.SHA256)
			}
			byDigest[digest] = append(byDigest[digest], name)
			sizes[digest] = info.Size()
		}
	}
	var saved int64
	for digest, names := range byDigest {
		original, err := os.Stat(names[0])
		if err != nil {
			return saved, err
		}
		for _, name := range names[1:] {
			info, err := os.Stat(name)
			if err != nil {
				return saved, err
			}
			if os.SameFile(original, info) {
				continue
			}
			tmp, err := os.MkdirTemp(filepath.Dir(name), ".identical-output-*")
			if err != nil {
				return saved, err
			}
			link := filepath.Join(tmp, "image")
			err = os.Link(names[0], link)
			if err == nil {
				err = os.Rename(link, name)
			}
			_ = os.RemoveAll(tmp)
			if err != nil {
				return saved, err
			}
			saved += sizes[digest]
		}
	}
	return saved, nil
}
