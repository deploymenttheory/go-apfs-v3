package copyfile

// windowsFileBasicInformation is the native FILE_BASIC_INFO layout: four
// LARGE_INTEGER timestamps, a DWORD and trailing padding. uint64 fields supply
// the required eight-byte alignment on both supported Windows architectures;
// a byte slice can otherwise be placed at a misaligned stack address.
// This portable declaration allows its ABI to be checked without Windows APIs.
// Microsoft uses the same alignment in go-winio/fileinfo.go.
type windowsFileBasicInformation struct {
	CreationTime, LastAccessTime, LastWriteTime, ChangeTime uint64
	FileAttributes                                          uint32
	_                                                       uint32
}
