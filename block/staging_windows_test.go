package block

import (
	"context"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestStagingWindowsSparseAllocation(t *testing.T) {
	source := sparseStagingSource{size: 64 << 20}
	stage, err := Stage(context.Background(), source, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	raw, err := stage.file.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var flags uint32
	var attributes windows.ByHandleFileInformation
	// FILE_STANDARD_INFO from winbase.h.
	var storage struct {
		AllocationSize int64
		EndOfFile      int64
		NumberOfLinks  uint32
		DeletePending  byte
		Directory      byte
	}
	var operationErr error
	if err = raw.Control(func(fd uintptr) {
		handle := windows.Handle(fd)
		if operationErr = windows.GetVolumeInformationByHandle(handle, nil, 0, nil, nil, &flags, nil, 0); operationErr != nil {
			return
		}
		if operationErr = windows.GetFileInformationByHandle(handle, &attributes); operationErr != nil {
			return
		}
		operationErr = windows.GetFileInformationByHandleEx(handle, windows.FileStandardInfo,
			(*byte)(unsafe.Pointer(&storage)), uint32(unsafe.Sizeof(storage)))
	}); err != nil {
		t.Fatal(err)
	}
	if operationErr != nil {
		t.Fatal(operationErr)
	}
	if flags&windows.FILE_SUPPORTS_SPARSE_FILES == 0 {
		t.Skip("scratch filesystem does not support sparse allocation; portable byte checks still apply")
	}
	if attributes.FileAttributes&windows.FILE_ATTRIBUTE_SPARSE_FILE == 0 {
		t.Fatal("scratch was not marked sparse")
	}
	if storage.EndOfFile != source.Size() || storage.AllocationSize > 1<<20 {
		t.Fatalf("64 MiB disk allocated unwritten ranges: logical=%d allocated=%d", storage.EndOfFile, storage.AllocationSize)
	}
	buffer := make([]byte, 128<<10)
	for _, offset := range []int64{0, source.Size() / 2, source.Size() - int64(len(buffer))} {
		if err = ReadFull(stage, buffer, offset); err != nil {
			t.Fatal(err)
		}
		for i, got := range buffer {
			want := byte(0)
			if offset+int64(i) == 0 || offset+int64(i) == source.Size()-1 {
				want = 0x5a
			}
			if got != want {
				t.Fatalf("scratch byte %d: got %x want %x", offset+int64(i), got, want)
			}
		}
	}
	t.Logf("scratch logical=%d allocated=%d", storage.EndOfFile, storage.AllocationSize)
}
