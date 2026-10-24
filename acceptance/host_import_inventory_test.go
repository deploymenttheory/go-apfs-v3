package acceptance_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

func hostInputValue(name string, data []byte) schema.HostInputValue {
	sum := sha256.Sum256(data)
	return schema.HostInputValue{Name: name, Bytes: int64(len(data)), SHA256: hex.EncodeToString(sum[:]), Hex: hex.EncodeToString(data)}
}

func hostInputField(field, state, format, reason string) schema.HostInputField {
	return schema.HostInputField{Field: field, State: state, SourceFormat: format, Reason: reason}
}

type hostInputPlatformObserver func(string, os.FileInfo) (schema.HostInputEntry, error)

// observeHostInputTree observes ordinary files directly. It never asks a
// session, workspace, host import reader or generated image what was present.
func observeHostInputTree(root string, source schema.CaseRef, nativePaths map[string]string) (schema.HostInputInventory, error) {
	return observeHostInputTreeWith(root, source, nativePaths, observeHostInputPlatform)
}

func observeHostInputTreeWith(root string, source schema.CaseRef, nativePaths map[string]string, platform hostInputPlatformObserver) (schema.HostInputInventory, error) {
	result := schema.HostInputInventory{Schema: schema.HostInputSchema, Host: runtime.GOOS, Arch: runtime.GOARCH, Go: runtime.Version(), Commit: os.Getenv("GITHUB_SHA"), Source: source}
	metadataBytes := 1024
	err := filepath.WalkDir(root, func(filename string, de fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if len(result.Entries) >= schema.HostInputMaxEntries {
			return fmt.Errorf("host input inventory exceeds %d entries", schema.HostInputMaxEntries)
		}
		rel, err := filepath.Rel(root, filename)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if len(rel) > 4096 {
			return fmt.Errorf("host input path exceeds bound")
		}
		before, err := os.Lstat(filename)
		if err != nil {
			return err
		}
		kind := ""
		var dataHash, target string
		switch {
		case before.IsDir():
			kind = "dir"
		case before.Mode().IsRegular():
			kind = "file"
			if before.Size() < 0 || before.Size() > 1<<20 {
				return fmt.Errorf("host input data %s exceeds 1MiB bound", rel)
			}
			f, err := os.Open(filename)
			if err != nil {
				return err
			}
			h := sha256.New()
			n, readErr := io.Copy(h, io.LimitReader(f, before.Size()+1))
			if err := errors.Join(readErr, f.Close()); err != nil {
				return err
			}
			if n != before.Size() {
				return fmt.Errorf("host input %s changed size while inventoried", rel)
			}
			dataHash = hex.EncodeToString(h.Sum(nil))
		case before.Mode()&os.ModeSymlink != 0:
			kind = "symlink"
			value, err := os.Readlink(filename)
			if err != nil {
				return err
			}
			if len(value) > 4096 {
				return fmt.Errorf("host input symlink exceeds bound")
			}
			target = hex.EncodeToString([]byte(value))
		default:
			return fmt.Errorf("host input %s has an unqualified type", rel)
		}
		// Observe clocks after the inventory's own read, then require content
		// identity/size/mtime to remain unchanged throughout the observation.
		after, err := os.Lstat(filename)
		if err != nil {
			return err
		}
		if !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
			return fmt.Errorf("host input %s changed during independent readback", rel)
		}
		entry, err := platform(filename, after)
		if err != nil {
			return fmt.Errorf("host input %s metadata: %w", rel, err)
		}
		entry.Entry.Path = rel
		entry.Entry.NameBytes = hex.EncodeToString([]byte(after.Name()))
		entry.Entry.Kind = kind
		entry.Entry.SHA256, entry.Entry.Target = dataHash, target
		if kind == "dir" {
			entry.Entry.Size, entry.Entry.Links = 0, 0
		} else {
			entry.Entry.Size = after.Size()
		}
		entry.NativePath = nativePaths[rel]
		if entry.NativePath == "" {
			return fmt.Errorf("host input %s lacks its original native logical binding", rel)
		}
		sort.Slice(entry.Fields, func(i, j int) bool { return entry.Fields[i].Field < entry.Fields[j].Field })
		sort.Slice(entry.Attributes, func(i, j int) bool { return entry.Attributes[i].Name < entry.Attributes[j].Name })
		sort.Slice(entry.NamedStreams, func(i, j int) bool { return entry.NamedStreams[i].Name < entry.NamedStreams[j].Name })
		encoded, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		metadataBytes += len(encoded) + 1
		if metadataBytes > schema.HostInputMaxBytes {
			return fmt.Errorf("host input exceeds aggregate sidecar bound during enumeration")
		}
		result.Entries = append(result.Entries, entry)
		return nil
	})
	if err != nil {
		return schema.HostInputInventory{}, err
	}
	sort.Slice(result.Entries, func(i, j int) bool { return result.Entries[i].Entry.Path < result.Entries[j].Entry.Path })
	data, err := json.Marshal(result)
	if err != nil || len(data) > schema.HostInputMaxBytes {
		return schema.HostInputInventory{}, errors.Join(err, fmt.Errorf("host inventory exceeds sidecar bound"))
	}
	return result, nil
}

// materializeObservedHostInput starts with immutable native logical data. All
// host metadata is then observed independently, not copied from that oracle.
func materializeObservedHostInput(t *testing.T, ctx context.Context, root string, source filesystem.Reader, entries []schema.Entry, nativeView schema.View) map[string]string {
	t.Helper()
	materializeNativeHostTree(t, ctx, root, source, entries)
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	nativePaths := map[string]string{".": "Fixture/tree"}
	var payload schema.Entry
	for _, entry := range entries {
		nativePaths[entry.Path] = "Fixture/tree/" + entry.Path
		if entry.Kind == "file" && entry.Size > 0 && payload.Path == "" {
			payload = entry
		}
		if entry.Kind != "symlink" {
			mode := os.FileMode(0o644)
			if entry.Kind == "dir" {
				mode = 0o755
			}
			if err := os.Chmod(filepath.Join(root, filepath.FromSlash(entry.Path)), mode); err != nil {
				t.Fatal(err)
			}
		}
	}
	if payload.Path == "" || payload.Size > 1<<20 {
		t.Fatal("native host-import payload is missing or outside bounds")
	}
	id, err := filesystem.LookupExact(ctx, source, "Fixture/tree/"+payload.Path)
	if err != nil {
		t.Fatal(err)
	}
	value, err := source.OpenData(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	data, readErr := io.ReadAll(io.NewSectionReader(value, 0, value.Size()))
	if err := errors.Join(readErr, value.Close()); err != nil {
		t.Fatal(err)
	}
	if got := hostInputValue("", data); got.SHA256 != payload.SHA256 || got.Bytes != payload.Size {
		t.Fatal("materialized host input changed the immutable native logical payload")
	}
	if err := os.Mkdir(filepath.Join(root, "metadata-dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	nativePaths["metadata-dir"] = "Fixture/tree"
	for _, name := range []string{"observed", "unicode-雪-😀", "metadata-dir/value"} {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), data, 0o644); err != nil {
			t.Fatal(err)
		}
		nativePaths[name] = "Fixture/tree/" + payload.Path
	}
	if err := os.Link(filepath.Join(root, "observed"), filepath.Join(root, "observed-alias")); err != nil {
		t.Fatal(err)
	}
	nativePaths["observed-alias"] = nativePaths["observed"]
	var empty schema.Entry
	for _, entry := range nativeView.Entries {
		if entry.Kind == "file" && entry.Size == 0 {
			empty = entry
			break
		}
	}
	if empty.Path == "" {
		t.Fatal("native host-import empty-file oracle is missing")
	}
	if err := os.WriteFile(filepath.Join(root, "empty"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	nativePaths["empty"] = empty.Path
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "unicode-雪-😀"), 0o654); err != nil {
		t.Fatal(err)
	}
	if err := configureHostInputMetadata(root); err != nil {
		t.Fatal("configure actual host metadata:", err)
	}
	// An explicit future access time avoids relatime changing source state
	// between two identical imports. Actual final times are inventoried below.
	access := time.Date(2035, 4, 5, 6, 7, 8, 0, time.UTC)
	modify := fixedClock.Add(time.Hour)
	if err := filepath.WalkDir(root, func(filename string, e fs.DirEntry, err error) error {
		if err != nil || e.Type()&os.ModeSymlink != 0 {
			return err
		}
		return os.Chtimes(filename, access, modify)
	}); err != nil {
		t.Fatal(err)
	}
	return nativePaths
}

func checkObservedHostInputUnchanged(t *testing.T, root string, before schema.HostInputInventory, nativePaths map[string]string) {
	t.Helper()
	after, err := observeHostInputTree(root, before.Source, nativePaths)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("host import changed its independently observed original input")
	}
}

func hostInputOutputPrefix(source schema.CaseRef) string {
	return fmt.Sprintf("macos-%d.%s.%s.%s.", source.Producer, source.Recipe, source.Profile, source.Stage)
}

func writeHostInputSidecar(t *testing.T, inventory schema.HostInputInventory) *schema.HostInputReference {
	t.Helper()
	data, err := json.MarshalIndent(inventory, "", "  ")
	if err != nil || len(data)+1 > schema.HostInputMaxBytes {
		t.Fatal("encode bounded host inventory:", err)
	}
	data = append(data, '\n')
	name := hostInputOutputPrefix(inventory.Source) + "host-input.json"
	if filepath.Base(name) != name || path.Base(name) != name {
		t.Fatal("invalid host inventory artifact name")
	}
	if err := os.WriteFile(filepath.Join(outputDir(t), name), data, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return &schema.HostInputReference{File: name, Bytes: int64(len(data)), SHA256: hex.EncodeToString(sum[:])}
}
