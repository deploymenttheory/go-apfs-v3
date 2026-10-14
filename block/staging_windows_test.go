package block

import (
	"context"
	"errors"
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
	if err = stage.Sync(); err != nil {
		t.Fatal(err)
	}
	raw, err := stage.file.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var flags uint32
	var attributes windows.ByHandleFileInformation
	// FILE_ALLOCATED_RANGE_BUFFER from winioctl.h. Query actual ranges after
	// flushing: pre-flush allocation information can reflect deferred writes.
	type allocatedRange struct {
		Offset int64
		Length int64
	}
	request := allocatedRange{Length: source.Size()}
	var ranges [4]allocatedRange
	var returned uint32
	var operationErr error
	if err = raw.Control(func(fd uintptr) {
		handle := windows.Handle(fd)
		if operationErr = windows.GetVolumeInformationByHandle(handle, nil, 0, nil, nil, &flags, nil, 0); operationErr != nil {
			return
		}
		if operationErr = windows.GetFileInformationByHandle(handle, &attributes); operationErr != nil {
			return
		}
		if flags&windows.FILE_SUPPORTS_SPARSE_FILES == 0 {
			return
		}
		operationErr = windows.DeviceIoControl(handle, windows.FSCTL_QUERY_ALLOCATED_RANGES,
			(*byte)(unsafe.Pointer(&request)), uint32(unsafe.Sizeof(request)),
			(*byte)(unsafe.Pointer(&ranges[0])), uint32(unsafe.Sizeof(ranges)), &returned, nil)
	}); err != nil {
		t.Fatal(err)
	}
	if flags&windows.FILE_SUPPORTS_SPARSE_FILES == 0 {
		if operationErr != nil {
			t.Fatal(operationErr)
		}
		t.Skip("scratch filesystem does not support sparse allocation; portable byte checks still apply")
	}
	if attributes.FileAttributes&windows.FILE_ATTRIBUTE_SPARSE_FILE == 0 {
		t.Fatal("scratch was not marked sparse")
	}
	if errors.Is(operationErr, windows.ERROR_INVALID_FUNCTION) || errors.Is(operationErr, windows.ERROR_NOT_SUPPORTED) {
		t.Skip("scratch filesystem does not support querying sparse ranges; portable byte checks still apply")
	}
	if operationErr != nil {
		t.Fatal(operationErr)
	}
	if int64(attributes.FileSizeHigh)<<32|int64(attributes.FileSizeLow) != source.Size() {
		t.Fatal("scratch logical length changed")
	}
	rangeSize := uint32(unsafe.Sizeof(request))
	if returned%rangeSize != 0 || returned > uint32(unsafe.Sizeof(ranges)) {
		t.Fatal("invalid allocated-range response", returned)
	}
	var allocated int64
	var covered [2]bool
	for _, r := range ranges[:returned/rangeSize] {
		if r.Offset < 0 || r.Length <= 0 || r.Offset > source.Size() || r.Length > source.Size()-r.Offset {
			t.Fatal("allocated range outside scratch", r)
		}
		allocated += r.Length
		for i, position := range []int64{0, source.Size() - 1} {
			if position >= r.Offset && position-r.Offset < r.Length {
				covered[i] = true
			}
		}
	}
	if !covered[0] || !covered[1] || allocated > 1<<20 {
		t.Fatalf("64 MiB scratch allocation: ranges=%v, allocated=%d, payload covered=%v", ranges[:returned/rangeSize], allocated, covered)
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
	t.Logf("scratch logical=%d allocated=%d ranges=%v", source.Size(), allocated, ranges[:returned/rangeSize])
}
