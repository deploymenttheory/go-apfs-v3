package native

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"reflect"
	"slices"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// AppleDoubleValue describes serialized bytes without loading large forks.
type AppleDoubleValue struct {
	Bytes  int64
	SHA256 string
}

// AppleDoubleAttribute retains serialized order, names, flags and empty values.
// ACL text is opaque; it is not the filesystem's native security blob.
type AppleDoubleAttribute struct {
	Name  string
	Flags uint16
	AppleDoubleValue
}

// AppleDoubleRecord is an independent description of Apple's two-entry format.
// Neither this reader nor the native unpack verdict imports the product codec.
type AppleDoubleRecord struct {
	FinderInfo [32]byte
	Resource   AppleDoubleValue
	Flags      uint16
	DebugTag   uint32
	Attributes []AppleDoubleAttribute
}

// ReadAppleDouble hashes every serialized value through bounded sections. It
// admits FinderInfo/resource-fork entries with the optional ATTR extension.
func ReadAppleDouble(r io.ReaderAt, size int64) (AppleDoubleRecord, error) {
	var record AppleDoubleRecord
	bad := func(reason string) (AppleDoubleRecord, error) {
		return record, fmt.Errorf("AppleDouble evidence: %s", reason)
	}
	if size < 82 {
		return bad("short header")
	}
	header := make([]byte, 82)
	if _, err := r.ReadAt(header, 0); err != nil {
		return record, err
	}
	be := binary.BigEndian
	if be.Uint32(header) != 0x00051607 || be.Uint32(header[4:]) != 0x00020000 || be.Uint16(header[24:]) != 2 {
		return bad("unsupported header")
	}
	var finder, resource [2]int64
	for offset := 26; offset < 50; offset += 12 {
		span := [2]int64{int64(be.Uint32(header[offset+4:])), int64(be.Uint32(header[offset+8:]))}
		if span[0] < 50 || span[0]+span[1] > size {
			return bad("entry outside source")
		}
		switch be.Uint32(header[offset:]) {
		case 9:
			if finder != [2]int64{} {
				return bad("duplicate FinderInfo")
			}
			finder = span
		case 2:
			if resource != [2]int64{} {
				return bad("duplicate resource fork")
			}
			resource = span
		default:
			return bad("unsupported entry")
		}
	}
	if finder[0] != 50 || finder[1] < 32 || finder[0]+finder[1] > resource[0] {
		return bad("overlapping entries")
	}
	copy(record.FinderInfo[:], header[50:82])
	value := func(offset, length int64) (AppleDoubleValue, error) {
		h := sha256.New()
		n, err := io.Copy(h, io.NewSectionReader(r, offset, length))
		if err == nil && n != length {
			err = io.ErrUnexpectedEOF
		}
		return AppleDoubleValue{n, hex.EncodeToString(h.Sum(nil))}, err
	}
	var err error
	if record.Resource, err = value(resource[0], resource[1]); err != nil {
		return record, err
	}
	if finder[1] == 32 {
		return record, nil
	}
	if finder[1] < 70 {
		return bad("short ATTR header")
	}
	header = make([]byte, 120)
	if _, err := r.ReadAt(header, 0); err != nil {
		return record, err
	}
	if !bytes.Equal(header[84:88], []byte("ATTR")) || !bytes.Equal(header[104:116], make([]byte, 12)) {
		return bad("invalid ATTR header")
	}
	total, start, length := int64(be.Uint32(header[92:])), int64(be.Uint32(header[96:])), int64(be.Uint32(header[100:]))
	count := int(be.Uint16(header[118:]))
	if count > 4096 || start < 120 || start > 65554 || start+length != total || total > finder[0]+finder[1] {
		return bad("invalid ATTR bounds")
	}
	record.Flags, record.DebugTag = be.Uint16(header[116:]), be.Uint32(header[88:])
	header = make([]byte, start)
	if _, err := r.ReadAt(header, 0); err != nil {
		return record, err
	}
	var spans [][2]int64
	cursor := 120
	for range count {
		if cursor+11 > len(header) {
			return bad("short attribute record")
		}
		b := header[cursor:]
		offset, length, nameLength := int64(be.Uint32(b)), int64(be.Uint32(b[4:])), int(b[10])
		end := cursor + 11 + nameLength
		if nameLength < 2 || end > len(header) || b[11+nameLength-1] != 0 || bytes.IndexByte(b[11:11+nameLength-1], 0) >= 0 {
			return bad("invalid attribute name")
		}
		if offset+length > total || (offset < start && (offset != 0 || length != 0)) {
			return bad("attribute outside data")
		}
		v, err := value(offset, length)
		if err != nil {
			return record, err
		}
		record.Attributes = append(record.Attributes, AppleDoubleAttribute{string(b[11 : 11+nameLength-1]), be.Uint16(b[8:]), v})
		if length > 0 {
			spans = append(spans, [2]int64{offset, offset + length})
		}
		cursor = (end + 3) &^ 3
		if cursor > len(header) {
			return bad("attribute padding outside header")
		}
	}
	slices.SortFunc(spans, func(a, b [2]int64) int {
		if a[0] < b[0] {
			return -1
		}
		if a[0] > b[0] {
			return 1
		}
		return 0
	})
	for i := 1; i < len(spans); i++ {
		if spans[i][0] < spans[i-1][1] {
			return bad("overlapping attributes")
		}
	}
	return record, nil
}

// ReadAppleDoubleFile reads a retained control or returned portable output.
func ReadAppleDoubleFile(filename string) (AppleDoubleRecord, error) {
	f, err := os.Open(filename)
	if err != nil {
		return AppleDoubleRecord{}, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return AppleDoubleRecord{}, err
	}
	return ReadAppleDouble(f, info.Size())
}

// CompareAppleDouble compares semantics, allowing Apple's padding/layout to
// differ from canonical output. Attribute ordering and serialized flags matter.
func CompareAppleDouble(got, want AppleDoubleRecord) []Difference {
	var differences []Difference
	for _, field := range []struct {
		name      string
		got, want any
	}{
		{"finderInfo", got.FinderInfo, want.FinderInfo},
		{"resourceFork", got.Resource, want.Resource},
		{"flags", got.Flags, want.Flags},
		{"debugTag", got.DebugTag, want.DebugTag},
		{"attributes", got.Attributes, want.Attributes},
	} {
		if !reflect.DeepEqual(field.got, field.want) {
			differences = append(differences, Difference{Field: field.name, Got: fmt.Sprint(field.got), Want: fmt.Sprint(field.want)})
		}
	}
	return differences
}

func appleDoubleControl(view schema.View, name string) (schema.AppleDoubleExport, error) {
	var found []schema.AppleDoubleExport
	for _, e := range view.AppleDouble {
		if e.Path == name {
			found = append(found, e)
		}
	}
	if len(found) != 1 {
		return schema.AppleDoubleExport{}, fmt.Errorf("no unique native AppleDouble export for %q", name)
	}
	return found[0], nil
}
