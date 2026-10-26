package native

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func TestIdenticalOutputStorageVerifiesEveryOriginalBeforeSharing(t *testing.T) {
	root := t.TempDir()
	hosts := map[string]HostOutputs{}
	for _, host := range []string{"darwin", "linux", "windows"} {
		dir := filepath.Join(root, host)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		var outputs []schema.Output
		for _, name := range []string{"identical", "independent"} {
			contents := "identical bytes"
			if name == "independent" {
				contents = host
			}
			if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
				t.Fatal(err)
			}
			outputs = append(outputs, schema.Output{Name: name, File: name, Bytes: int64(len(contents)), SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(contents)))})
		}
		hosts[host] = HostOutputs{Dir: dir, Manifest: schema.Outputs{Outputs: outputs}}
	}
	corrupt := filepath.Join(hosts["windows"].Dir, "identical")
	if err := os.WriteFile(corrupt, []byte("corrupted bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := shareIdenticalOutputs(hosts); err == nil {
		t.Fatal("replaced a corrupt copy with another host's correct bytes")
	}
	darwin, _ := os.Stat(filepath.Join(hosts["darwin"].Dir, "identical"))
	linux, _ := os.Stat(filepath.Join(hosts["linux"].Dir, "identical"))
	if os.SameFile(darwin, linux) {
		t.Fatal("changed evidence before checking every original")
	}
	if err := os.WriteFile(corrupt, []byte("identical bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if saved, err := shareIdenticalOutputs(hosts); err != nil || saved != 30 {
		t.Fatalf("storage sharing: saved %d, error %v", saved, err)
	}
	darwin, _ = os.Stat(filepath.Join(hosts["darwin"].Dir, "identical"))
	for host, outputs := range hosts {
		for _, output := range outputs.Manifest.Outputs {
			name := filepath.Join(outputs.Dir, output.File)
			digest, err := schema.FileDigest(name)
			if err != nil || digest != output.SHA256 {
				t.Fatalf("changed %s/%s: %v", host, output.Name, err)
			}
			info, _ := os.Stat(name)
			if output.Name == "identical" && !os.SameFile(darwin, info) {
				t.Fatalf("%s: identical image still uses separate storage", host)
			}
		}
	}
	if saved, err := shareIdenticalOutputs(hosts); err != nil || saved != 0 {
		t.Fatalf("repeat sharing: saved %d, error %v", saved, err)
	}
}
