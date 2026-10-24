package copyfile

import (
	"encoding/binary"
	"testing"
	"unsafe"
)

func TestWindowsFileBasicInformationMatchesNativeABI(t *testing.T) {
	var value windowsFileBasicInformation
	if unsafe.Sizeof(value) != 40 || unsafe.Alignof(value) != 8 {
		t.Fatalf("FILE_BASIC_INFO requires 40 bytes aligned to 8, got size %d alignment %d", unsafe.Sizeof(value), unsafe.Alignof(value))
	}
	fields := []struct {
		name   string
		offset uintptr
		want   uintptr
	}{{"CreationTime", unsafe.Offsetof(value.CreationTime), 0}, {"LastAccessTime", unsafe.Offsetof(value.LastAccessTime), 8}, {"LastWriteTime", unsafe.Offsetof(value.LastWriteTime), 16}, {"ChangeTime", unsafe.Offsetof(value.ChangeTime), 24}, {"FileAttributes", unsafe.Offsetof(value.FileAttributes), 32}}
	for _, field := range fields {
		if field.offset != field.want {
			t.Errorf("native %s offset %d, want %d", field.name, field.offset, field.want)
		}
	}
	// Independently specified native bytes must land in the corresponding
	// timestamp and DWORD fields, including a nonzero high FILETIME word.
	raw := unsafe.Slice((*byte)(unsafe.Pointer(&value)), int(unsafe.Sizeof(value)))
	for offset := 0; offset < 32; offset += 8 {
		binary.LittleEndian.PutUint64(raw[offset:], 0x0123456789abcdef+uint64(offset))
	}
	binary.LittleEndian.PutUint32(raw[32:], 0x12345678)
	if value.CreationTime != 0x0123456789abcdef || value.LastAccessTime != 0x0123456789abcdf7 || value.LastWriteTime != 0x0123456789abcdff || value.ChangeTime != 0x0123456789abce07 || value.FileAttributes != 0x12345678 {
		t.Fatal("native basic-information bytes decoded into different fields", value)
	}
}
