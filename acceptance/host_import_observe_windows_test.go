package acceptance_test

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
	"golang.org/x/sys/windows"
)

// FILE_BASIC_INFO contains four LARGE_INTEGERs, not four merely uint32-aligned
// FILETIMEs. The separate native observer must satisfy the SDK ABI independently
// of the product adapter. See Microsoft's go-winio/fileinfo.go aligned layout.
type hostInputWindowsBasicInfo struct {
	CreationTime, AccessTime, ModifyTime, ChangeTime uint64
	FileAttributes                                   uint32
	_                                                uint32
}

func observeHostInputPlatform(filename string, info os.FileInfo) (v schema.HostInputEntry, resultErr error) {
	name, err := windows.UTF16PtrFromString(filename)
	if err != nil {
		return v, err
	}
	h, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return v, err
	}
	defer func() { resultErr = errors.Join(resultErr, windows.CloseHandle(h)) }()
	var st windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &st); err != nil {
		return v, err
	}
	v.Identity = fmt.Sprintf("%d:%d:%d", st.VolumeSerialNumber, st.FileIndexHigh, st.FileIndexLow)
	v.Entry.ID = uint64(st.FileIndexHigh)<<32 | uint64(st.FileIndexLow)
	v.SourceLinks, v.SourceFlags = uint64(st.NumberOfLinks), uint64(st.FileAttributes)
	if !info.IsDir() {
		v.Entry.Links = st.NumberOfLinks
	}
	// Preserve the actual directory API's UTF-16 name, rather than deriving
	// supposed native bytes by re-encoding Go's UTF-8 filename bridge.
	var found windows.Win32finddata
	search, err := windows.FindFirstFile(name, &found)
	if err != nil {
		return v, err
	}
	defer func() { resultErr = errors.Join(resultErr, windows.FindClose(search)) }()
	end := 0
	for end < len(found.FileName) && found.FileName[end] != 0 {
		end++
	}
	if end == 0 || end == len(found.FileName) {
		return v, fmt.Errorf("invalid native UTF-16 filename")
	}
	v.NameUTF16 = hostInputUTF16(found.FileName[:end])
	v.Fields = []schema.HostInputField{
		hostInputField("identity", "present", "windows-file-id", ""), hostInputField("links", "present", "windows-file-id", ""),
		hostInputField("mode", "unavailable", "windows-file-attributes", "Windows file attributes do not expose a POSIX mode"),
		hostInputField("uid", "unavailable", "windows-security-descriptor", "Windows owner SIDs have no configured numeric UID mapping"),
		hostInputField("gid", "unavailable", "windows-security-descriptor", "Windows group SIDs have no configured numeric GID mapping"),
		hostInputField("bsdFlags", "unavailable", "windows-file-attributes", "Windows attributes are not Darwin BSD flags"),
		hostInputField("sourceFlags", "present", "windows-file-attributes", ""),
		hostInputField("resourceFork", "unavailable", "windows-named-streams", "Windows streams have no implicit Darwin resource fork mapping"),
	}
	v.Security, err = hostInputWindowsSecurity(h)
	if err != nil {
		return v, err
	}
	state := v.Security.State
	if state == "null" || state == "empty" {
		state = "present"
	}
	v.Fields = append(v.Fields, hostInputField("acl", state, "windows-security-descriptor", v.Security.Reason))
	v.NamedStreams, err = hostInputWindowsStreams(h, filename)
	if errors.Is(err, windows.ERROR_NOT_SUPPORTED) || errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		v.Fields = append(v.Fields, hostInputField("attributes", "unavailable", "windows-named-streams", "filesystem does not enumerate named streams"))
	} else if err != nil {
		return v, err
	} else {
		v.Fields = append(v.Fields, hostInputField("attributes", "present", "windows-named-streams", ""))
	}
	// Observe the actual basic-info timestamps after our own stream reads.
	// ChangeTime independently detects owner/security-only source changes.
	var basic hostInputWindowsBasicInfo
	if err := windows.GetFileInformationByHandleEx(h, windows.FileBasicInfo, (*byte)(unsafe.Pointer(&basic)), uint32(unsafe.Sizeof(basic))); err != nil {
		return v, err
	}
	stamp := func(ticks uint64) int64 {
		value := windows.Filetime{LowDateTime: uint32(ticks), HighDateTime: uint32(ticks >> 32)}
		return time.Unix(0, value.Nanoseconds()).UnixNano()
	}
	v.Entry.Times = schema.Times{Birth: stamp(basic.CreationTime), Access: stamp(basic.AccessTime), Modify: stamp(basic.ModifyTime), Change: stamp(basic.ChangeTime)}
	for _, field := range []string{"birthTime", "accessTime", "modifyTime", "changeTime"} {
		v.Fields = append(v.Fields, hostInputField(field, "present", "windows-file-basic-info", ""))
	}
	slices.SortFunc(v.Fields, func(a, b schema.HostInputField) int { return strings.Compare(a.Field, b.Field) })
	return v, nil
}

func TestHostInputWindowsBasicInfoMatchesNativeSizeAlignmentAndOffsets(t *testing.T) {
	var record hostInputWindowsBasicInfo
	if unsafe.Sizeof(record) != 40 || unsafe.Alignof(record) != 8 || uintptr(unsafe.Pointer(&record))%8 != 0 {
		t.Fatalf("FILE_BASIC_INFO ABI: size=%d alignment=%d address%%8=%d", unsafe.Sizeof(record), unsafe.Alignof(record), uintptr(unsafe.Pointer(&record))%8)
	}
	if offsets := [5]uintptr{unsafe.Offsetof(record.CreationTime), unsafe.Offsetof(record.AccessTime), unsafe.Offsetof(record.ModifyTime), unsafe.Offsetof(record.ChangeTime), unsafe.Offsetof(record.FileAttributes)}; offsets != [5]uintptr{0, 8, 16, 24, 32} {
		t.Fatal("FILE_BASIC_INFO native field offsets changed", offsets)
	}
}

func hostInputUTF16(units []uint16) string {
	buf := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(buf[2*i:], u)
	}
	return hex.EncodeToString(buf)
}

func hostInputWindowsSecurity(h windows.Handle) (schema.HostInputSecurity, error) {
	result := schema.HostInputSecurity{Format: "windows-security-descriptor"}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if errors.Is(err, windows.ERROR_NOT_SUPPORTED) {
		result.State, result.Reason = "unavailable", "filesystem cannot return a security descriptor"
		return result, nil
	}
	if err != nil {
		return result, err
	}
	if sd == nil {
		return result, fmt.Errorf("missing security descriptor")
	}
	n := sd.Length()
	if n == 0 || n > 64<<10 {
		return result, fmt.Errorf("security descriptor size exceeds its bound")
	}
	data := append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(sd)), int(n))...)
	result.Values = []schema.HostInputValue{hostInputValue("security-descriptor", data)}
	acl, _, err := sd.DACL()
	switch {
	case errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND):
		result.State = "absent"
	case err != nil:
		return result, err
	case acl == nil:
		result.State = "null"
	case acl.AceCount == 0:
		result.State = "empty"
	default:
		result.State = "present"
	}
	return result, nil
}

func hostInputWindowsStreams(h windows.Handle, filename string) ([]schema.HostInputValue, error) {
	var buf []byte
	for size := 4096; size <= 1<<20; size *= 2 {
		buf = make([]byte, size)
		err := windows.GetFileInformationByHandleEx(h, windows.FileStreamInfo, &buf[0], uint32(len(buf)))
		if errors.Is(err, windows.ERROR_HANDLE_EOF) {
			return nil, nil
		}
		if errors.Is(err, windows.ERROR_MORE_DATA) || errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || errors.Is(err, windows.ERROR_BAD_LENGTH) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return hostInputWindowsStreamRecords(buf, filename)
	}
	return nil, fmt.Errorf("stream inventory exceeded its bounded buffer")
}

func hostInputWindowsStreamRecords(buf []byte, filename string) ([]schema.HostInputValue, error) {
	var result []schema.HostInputValue
	seen := map[string]bool{}
	total := int64(0)
	for entries := 0; ; entries++ {
		if entries > schema.HostInputMaxAttributes || len(buf) < 24 {
			return nil, fmt.Errorf("invalid stream inventory size")
		}
		next, n := int(binary.LittleEndian.Uint32(buf)), int(binary.LittleEndian.Uint32(buf[4:]))
		size, allocated := int64(binary.LittleEndian.Uint64(buf[8:])), int64(binary.LittleEndian.Uint64(buf[16:]))
		if n == 0 || n%2 != 0 || n > len(buf)-24 || size < 0 || allocated < 0 {
			return nil, fmt.Errorf("invalid stream record")
		}
		units := make([]uint16, n/2)
		for i := range units {
			units[i] = binary.LittleEndian.Uint16(buf[24+i*2:])
			if units[i] == 0 {
				return nil, fmt.Errorf("embedded NUL in stream name")
			}
		}
		key := hostInputUTF16(units)
		if seen[key] {
			return nil, fmt.Errorf("duplicate stream name")
		}
		seen[key] = true
		name := string(utf16.Decode(units))
		if name != "::$DATA" {
			if !strings.HasPrefix(name, ":") || !strings.HasSuffix(name, ":$DATA") || size > schema.HostInputMaxValueBytes || total+size > schema.HostInputMaxBytes || len(result) >= schema.HostInputMaxAttributes {
				return nil, fmt.Errorf("unsupported or oversized named stream")
			}
			value, err := hostInputReadWindowsStream(filename, units, size)
			if err != nil {
				return nil, err
			}
			entry := hostInputValue(name, value)
			entry.NameUTF16 = key
			result = append(result, entry)
			total += size
		}
		if next == 0 {
			break
		}
		if next%8 != 0 || next < 24+n || next > len(buf)-24 {
			return nil, fmt.Errorf("invalid linked stream offset")
		}
		buf = buf[next:]
	}
	slices.SortFunc(result, func(a, b schema.HostInputValue) int { return strings.Compare(a.NameUTF16, b.NameUTF16) })
	return result, nil
}

func hostInputReadWindowsStream(filename string, stream []uint16, size int64) (data []byte, resultErr error) {
	base, err := windows.UTF16FromString(filename)
	if err != nil {
		return nil, err
	}
	path := append(append(base[:len(base)-1:len(base)-1], stream...), 0)
	h, err := windows.CreateFile(&path[0], windows.FILE_READ_DATA, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, windows.CloseHandle(h)) }()
	data = make([]byte, size)
	for at := 0; at < len(data); {
		var n uint32
		err := windows.ReadFile(h, data[at:], &n, nil)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, io.ErrUnexpectedEOF
		}
		at += int(n)
	}
	var extra [1]byte
	var n uint32
	err = windows.ReadFile(h, extra[:], &n, nil)
	if err != nil && !errors.Is(err, windows.ERROR_HANDLE_EOF) {
		return nil, err
	}
	if n != 0 {
		return nil, fmt.Errorf("named stream changed length")
	}
	return data, nil
}

func configureHostInputMetadata(root string) error {
	filename := filepath.Join(root, "observed")
	for name, value := range map[string][]byte{"apfs.acceptance.binary": {0, 1, 127, 128, 255, 0, 104, 111, 115, 116}, "apfs.acceptance.empty": {}} {
		if err := os.WriteFile(filename+":"+name, value, 0600); err != nil {
			return err
		}
	}
	return nil
}
