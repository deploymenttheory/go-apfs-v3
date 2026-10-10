package diskimage

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// Reading files can ignore unrelated DMG resources. Repacking cannot: this
// admission parser rejects unknown keys, duplicate keys and unsupported scalar
// types rather than dropping data that belongs to the original envelope.
type repackValue struct {
	kind, text string
	dict       map[string]repackValue
	array      []repackValue
}

func (v repackValue) keys(names ...string) error {
	if v.kind != "dict" {
		return corrupt("UDIF dictionary expected")
	}
	for k := range v.dict {
		found := false
		for _, n := range names {
			found = found || k == n
		}
		if !found {
			return fmt.Errorf("UDIF resource/key %q: %w", k, filesystem.ErrUnsupported)
		}
	}
	return nil
}
func parseRepackPlist(data []byte) (repackValue, error) {
	d := xml.NewDecoder(bytes.NewReader(data))
	nodes := 0
	var read func(xml.StartElement, int) (repackValue, error)
	read = func(start xml.StartElement, depth int) (repackValue, error) {
		v := repackValue{kind: start.Name.Local}
		nodes++
		if depth > 16 || nodes > 100000 {
			return v, filesystem.ErrLimit
		}
		if start.Name.Space != "" || len(start.Attr) != 0 {
			return v, filesystem.ErrUnsupported
		}
		switch v.kind {
		case "string", "data", "key":
			var text strings.Builder
			for {
				token, err := d.Token()
				if err != nil {
					return v, corrupt("UDIF plist scalar")
				}
				switch t := token.(type) {
				case xml.CharData:
					text.Write(t)
				case xml.Comment:
				case xml.EndElement:
					v.text = text.String()
					return v, nil
				default:
					return v, corrupt("nested UDIF plist scalar")
				}
			}
		case "dict":
			v.dict = map[string]repackValue{}
		case "array":
			v.array = []repackValue{}
		default:
			return v, fmt.Errorf("UDIF plist type %q: %w", v.kind, filesystem.ErrUnsupported)
		}
		key, hasKey := "", false
		for {
			token, err := d.Token()
			if err != nil {
				return v, corrupt("UDIF plist nesting")
			}
			switch t := token.(type) {
			case xml.StartElement:
				child, err := read(t, depth+1)
				if err != nil {
					return v, err
				}
				if v.kind == "array" {
					if child.kind == "key" {
						return v, corrupt("UDIF key in array")
					}
					v.array = append(v.array, child)
				} else if !hasKey {
					if child.kind != "key" {
						return v, corrupt("UDIF dictionary key")
					}
					key, hasKey = child.text, true
					if _, exists := v.dict[key]; exists {
						return v, corrupt("duplicate UDIF plist key")
					}
				} else {
					if child.kind == "key" {
						return v, corrupt("UDIF dictionary value")
					}
					v.dict[key], hasKey = child, false
				}
			case xml.EndElement:
				if hasKey {
					return v, corrupt("UDIF dictionary missing value")
				}
				return v, nil
			case xml.CharData:
				if strings.TrimSpace(string(t)) != "" {
					return v, corrupt("UDIF plist text")
				}
			case xml.Comment:
			default:
				return v, filesystem.ErrUnsupported
			}
		}
	}
	var result repackValue
	opened, valueRead, closed := false, false, false
	for {
		token, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return result, corrupt("UDIF XML")
		}
		switch t := token.(type) {
		case xml.StartElement:
			if !opened {
				if t.Name.Local != "plist" || t.Name.Space != "" || len(t.Attr) != 1 || t.Attr[0].Name.Local != "version" || t.Attr[0].Value != "1.0" {
					return result, filesystem.ErrUnsupported
				}
				opened = true
			} else {
				if valueRead || closed {
					return result, corrupt("multiple UDIF plist roots")
				}
				result, err = read(t, 0)
				if err != nil {
					return result, err
				}
				valueRead = true
			}
		case xml.EndElement:
			closed = true
		case xml.CharData:
			if strings.TrimSpace(string(t)) != "" {
				return result, corrupt("UDIF XML text")
			}
		case xml.Comment, xml.ProcInst, xml.Directive: // XML declarations do not add resource values.
		default:
			return result, filesystem.ErrUnsupported
		}
	}
	if !valueRead || !closed {
		return result, corrupt("incomplete UDIF plist")
	}
	return result, nil
}

func readRepackLayout(source block.Source, size int64) (encodingLayout, error) {
	var layout encodingLayout
	footer := make([]byte, 512)
	if err := block.ReadFull(source, footer, source.Size()-512); err != nil {
		return layout, err
	}
	be := binary.BigEndian
	// These reserved fields include code-signature offsets. Every byte outside
	// the admitted data/plist/footer layout must be accounted for, never stripped.
	if be.Uint32(footer[12:]) != 1 || !allZero(footer[16:32]) || !allZero(footer[40:56]) ||
		be.Uint32(footer[56:]) != 1 || be.Uint32(footer[60:]) != 1 || !allZero(footer[232:352]) || !allZero(footer[500:]) {
		return layout, fmt.Errorf("signed, segmented or extended UDIF envelope: %w", filesystem.ErrUnsupported)
	}
	layout.variant = be.Uint32(footer[488:])
	if layout.variant != 1 && layout.variant != 2 {
		return layout, filesystem.ErrUnsupported
	}
	offset, length := be.Uint64(footer[216:]), be.Uint64(footer[224:])
	limit := uint64(source.Size() - 512)
	if length == 0 || length > 16<<20 || offset > limit || length > limit-offset || be.Uint64(footer[492:]) != uint64(size/512) {
		return layout, corrupt("UDIF repack metadata range or changed geometry")
	}
	if offset != be.Uint64(footer[32:]) || offset+length != limit {
		return layout, fmt.Errorf("unaccounted UDIF container bytes: %w", filesystem.ErrUnsupported)
	}
	metadata := make([]byte, int(length))
	if err := block.ReadFull(source, metadata, int64(offset)); err != nil {
		return layout, err
	}
	root, err := parseRepackPlist(metadata)
	if err != nil {
		return layout, err
	}
	if err = root.keys("resource-fork"); err != nil {
		return layout, err
	}
	resources := root.dict["resource-fork"]
	if err = resources.keys("blkx", "plst"); err != nil {
		return layout, err
	}
	blocks := resources.dict["blkx"]
	if blocks.kind != "array" || len(blocks.array) == 0 {
		return layout, corrupt("UDIF block array")
	}
	if len(blocks.array) > 4096 {
		return layout, filesystem.ErrLimit
	}
	end, storedEnd := uint64(0), uint64(0)
	ids := map[string]bool{}
	for _, v := range blocks.array {
		if err = v.keys("Attributes", "CFName", "ID", "Name", "Data"); err != nil {
			return layout, err
		}
		for _, k := range []string{"Attributes", "ID", "Name"} {
			if v.dict[k].kind != "string" {
				return layout, corrupt("UDIF block label")
			}
		}
		if c, ok := v.dict["CFName"]; ok && c.kind != "string" {
			return layout, corrupt("UDIF block CFName")
		}
		id := v.dict["ID"].text
		if _, err = strconv.ParseInt(id, 10, 32); err != nil || ids[id] {
			return layout, corrupt("UDIF block identifier")
		}
		ids[id] = true
		if v.dict["Attributes"].text != "0x0050" {
			return layout, filesystem.ErrUnsupported
		}
		table, err := plistData(v.dict["Data"])
		if err != nil {
			return layout, err
		}
		if len(table) < 244 || string(table[:4]) != "mish" || be.Uint32(table[4:]) != 1 || !allZero(table[40:64]) {
			return layout, corrupt("UDIF block header")
		}
		start, count, base := be.Uint64(table[8:]), be.Uint64(table[16:]), be.Uint64(table[24:])
		if start != end || count == 0 || count > uint64(size/512)-end {
			return layout, corrupt("UDIF disk coverage")
		}
		n := uint64(be.Uint32(table[200:]))
		if n != uint64((len(table)-204)/40) || len(table) != 204+int(n)*40 {
			return layout, corrupt("UDIF chunk table length")
		}
		cursor := uint64(0)
		for j := uint64(0); j < n; j++ {
			c := table[204+j*40 : 244+j*40]
			kind, rel, sectors := be.Uint32(c), be.Uint64(c[8:]), be.Uint64(c[16:])
			stored, length := be.Uint64(c[24:]), be.Uint64(c[32:])
			if kind == 0x7ffffffe {
				if sectors != 0 || length != 0 {
					return layout, filesystem.ErrUnsupported
				}
				continue
			}
			if rel != cursor || sectors > count-cursor {
				return layout, corrupt("UDIF chunk coverage")
			}
			if kind == 0xffffffff {
				if j != n-1 || sectors != 0 || length != 0 || cursor != count {
					return layout, corrupt("UDIF terminator")
				}
				continue
			}
			if j == n-1 || sectors == 0 {
				return layout, corrupt("UDIF missing terminator or empty run")
			}
			if kind == 0 || kind == 2 {
				if length != 0 {
					return layout, corrupt("UDIF zero run contains payload")
				}
			} else {
				// Bounds and codec admission are shared with openUDIF. Reject stored gaps
				// and aliases here because those could hide unsupported envelope content.
				if base > offset || stored > offset-base || base+stored != storedEnd || length > offset-storedEnd {
					return layout, corrupt("UDIF stored coverage")
				}
				storedEnd += length
			}
			cursor += sectors
		}
		layout.blocks = append(layout.blocks, encodingBlock{start: int64(start) * 512, size: int64(count) * 512, name: v.dict["Name"].text, cfName: v.dict["CFName"].text, id: id, attributes: v.dict["Attributes"].text, table: table, descriptor: be.Uint32(table[36:])})
		end += count
	}
	if end != uint64(size/512) || storedEnd != offset {
		return layout, corrupt("incomplete UDIF coverage")
	}
	if value, ok := resources.dict["plst"]; ok {
		if value.kind != "array" || len(value.array) != 1 {
			return layout, filesystem.ErrUnsupported
		}
		p := value.array[0]
		if err = p.keys("Attributes", "ID", "Name", "Data"); err != nil {
			return layout, err
		}
		if p.dict["Attributes"].kind != "string" || p.dict["Attributes"].text != "0x0050" || p.dict["ID"].kind != "string" || p.dict["ID"].text != "0" || p.dict["Name"].kind != "string" || p.dict["Name"].text != "" {
			return layout, filesystem.ErrUnsupported
		}
		data, err := plistData(p.dict["Data"])
		if err != nil {
			return layout, err
		}
		placeholder := make([]byte, 1032)
		placeholder[517], placeholder[519] = 1, 1
		if !bytes.Equal(data, placeholder) {
			return layout, fmt.Errorf("unrecognized UDIF plst resource: %w", filesystem.ErrUnsupported)
		}
		layout.plst = data
	}
	return layout, nil
}
func plistData(v repackValue) ([]byte, error) {
	if v.kind != "data" {
		return nil, corrupt("UDIF data expected")
	}
	data, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(v.text), ""))
	if err != nil {
		return nil, corrupt("UDIF base64")
	}
	return data, nil
}
