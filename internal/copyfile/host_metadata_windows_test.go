package copyfile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"golang.org/x/sys/windows"
)

// This uses the real hostMetadata allocation and Windows calls, not an
// intentionally misaligned stand-in. Windows CI supplies the runtime verdict.
func TestHostMetadataReadsWindowsBasicInformation(t *testing.T) {
	root := t.TempDir()
	filename := filepath.Join(root, "native-雪-😀")
	if err := os.WriteFile(filename, []byte("ordinary host timestamp control"), 0644); err != nil {
		t.Fatal(err)
	}
	stamp := time.Date(2025, 6, 7, 8, 9, 10, 123456700, time.UTC)
	if err := os.Chtimes(filename, stamp.Add(time.Hour), stamp); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Link(filename, alias); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "literal-link")
	if err := os.Symlink(filename, link); err != nil {
		t.Fatal(err)
	}
	identities := map[string]string{}
	for iteration := 0; iteration < 32; iteration++ {
		for _, path := range []string{root, filename, alias, link} {
			got, key, err := hostMetadata(path)
			if err != nil {
				t.Fatalf("hostMetadata iteration %d: %v", iteration, err)
			}
			identities[path] = key
			pointer, err := windows.UTF16PtrFromString(path)
			if err != nil {
				t.Fatal(err)
			}
			h, err := windows.CreateFile(pointer, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
			if err != nil {
				t.Fatal("reference CreateFileW", err)
			}
			var original windows.ByHandleFileInformation
			var basic [5]uint64 // independent aligned native reference, not the product layout
			if err := errors.Join(windows.GetFileInformationByHandle(h, &original), windows.GetFileInformationByHandleEx(h, windows.FileBasicInfo, (*byte)(unsafe.Pointer(&basic[0])), 40), windows.CloseHandle(h)); err != nil {
				t.Fatal("reference GetFileInformationByHandle/Ex/CloseHandle", err)
			}
			change := windows.Filetime{LowDateTime: uint32(basic[3]), HighDateTime: uint32(basic[3] >> 32)}
			want := []time.Time{time.Unix(0, original.CreationTime.Nanoseconds()).UTC(), time.Unix(0, original.LastAccessTime.Nanoseconds()).UTC(), time.Unix(0, original.LastWriteTime.Nanoseconds()).UTC(), time.Unix(0, change.Nanoseconds()).UTC()}
			for i, field := range []filesystem.Observation[time.Time]{got.BirthTime, got.AccessTime, got.ModifyTime, got.ChangeTime} {
				if field.State != filesystem.Present || !field.Value.Equal(want[i]) {
					t.Fatalf("%s: actual native timestamp %d differs: %+v want %s", path, i, field, want[i])
				}
			}
			if got.ChangeTime.State != filesystem.Present || got.ChangeTime.Value.IsZero() {
				t.Fatal("metadata change time was not independently acquired", path, got.ChangeTime)
			}
		}
	}
	if identities[filename] == "" || identities[filename] != identities[alias] || identities[link] == identities[filename] {
		t.Fatal("no-follow metadata acquisition lost original host identity", identities)
	}
}
