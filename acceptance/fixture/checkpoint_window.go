package fixture

// These bounded measurements locate acquisition windows and explicit damage.
// They neither open filesystem trees nor select the expected recovery state:
// Apple's fsck and read-only mount remain the only recovery oracle.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

const checkpointBlockBytes = 4096

type checkpointWindow struct {
	BlockZero uint64              `json:"blockZeroXID"`
	Base      uint64              `json:"descriptorBase"`
	Count     uint32              `json:"descriptorBlocks"`
	DataBase  uint64              `json:"dataBase"`
	DataCount uint32              `json:"dataBlocks"`
	Latest    checkpointCandidate `json:"latest"`
	Future    map[string]uint64   `json:"future"`
}

type checkpointCandidate struct {
	XID              uint64 `json:"xid"`
	Address          uint64 `json:"address"`
	DescriptorIndex  uint32 `json:"descriptorIndex"`
	DescriptorLength uint32 `json:"descriptorLength"`
	DataIndex        uint32 `json:"dataIndex"`
	DataLength       uint32 `json:"dataLength"`
	NextDescriptor   uint32 `json:"nextDescriptor"`
	NextData         uint32 `json:"nextData"`
}

func checkpointChecksumValid(data []byte) bool {
	if len(data) < 32 || len(data)%4 != 0 {
		return false
	}
	var a, b uint64
	const modulus = uint64(0xffffffff)
	for i := 8; i < len(data); i += 4 {
		a = (a + uint64(binary.LittleEndian.Uint32(data[i:]))) % modulus
		b = (b + a) % modulus
	}
	x := modulus - (a+b)%modulus
	y := modulus - (a+x)%modulus
	return binary.LittleEndian.Uint64(data) == y<<32|x
}

func measureCheckpoints(path string) (*checkpointWindow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() != 128<<20 {
		return nil, errors.New("checkpoint capture requires a 128 MiB regular raw file")
	}
	read := func(address uint64) ([]byte, error) {
		if address >= uint64(info.Size()/checkpointBlockBytes) {
			return nil, errors.New("checkpoint acquisition address outside image")
		}
		b := make([]byte, checkpointBlockBytes)
		_, err := f.ReadAt(b, int64(address)*checkpointBlockBytes)
		return b, err
	}
	zero, err := read(0)
	if err != nil {
		return nil, err
	}
	if string(zero[32:36]) != "NXSB" || !checkpointChecksumValid(zero) {
		return nil, errors.New("invalid native block-zero acquisition geometry")
	}
	le := binary.LittleEndian
	s := &checkpointWindow{BlockZero: le.Uint64(zero[16:]), Base: le.Uint64(zero[112:]), Count: le.Uint32(zero[104:]), DataBase: le.Uint64(zero[120:]), DataCount: le.Uint32(zero[108:]), Future: map[string]uint64{}}
	blocks := uint64(info.Size() / checkpointBlockBytes)
	if s.Count == 0 || s.Count > 256 || s.DataCount == 0 || s.DataCount > 4096 || s.Base >= blocks || uint64(s.Count) > blocks-s.Base || s.DataBase >= blocks || uint64(s.DataCount) > blocks-s.DataBase {
		return nil, errors.New("unbounded native checkpoint acquisition rings")
	}
	for i := uint32(0); i < s.Count; i++ {
		b, err := read(s.Base + uint64(i))
		if err != nil {
			return nil, err
		}
		if string(b[32:36]) != "NXSB" || !checkpointChecksumValid(b) {
			continue
		}
		xid := le.Uint64(b[16:])
		if xid <= s.Latest.XID {
			continue
		}
		candidate := checkpointCandidate{XID: xid, Address: s.Base + uint64(i), NextDescriptor: le.Uint32(b[128:]), NextData: le.Uint32(b[132:]), DescriptorIndex: le.Uint32(b[136:]), DescriptorLength: le.Uint32(b[140:]), DataIndex: le.Uint32(b[144:]), DataLength: le.Uint32(b[148:])}
		if candidate.DescriptorIndex >= s.Count || candidate.NextDescriptor >= s.Count || candidate.DescriptorLength == 0 || candidate.DescriptorLength > s.Count || candidate.DataIndex >= s.DataCount || candidate.NextData >= s.DataCount || candidate.DataLength == 0 || candidate.DataLength > s.DataCount {
			return nil, errors.New("invalid native checkpoint ring cursor")
		}
		s.Latest = candidate
	}
	if s.Latest.XID == 0 {
		return nil, errors.New("no native descriptor superblock")
	}
	for label, address := range map[string]uint64{"mapping": s.Base + uint64(s.Latest.NextDescriptor), "data": s.DataBase + uint64(s.Latest.NextData)} {
		b, err := read(address)
		if err != nil {
			return nil, err
		}
		if checkpointChecksumValid(b) && le.Uint64(b[16:]) > s.Latest.XID {
			s.Future[label] = address
		}
	}
	return s, nil
}

func checkpointDamageOffset(path, kind string, state *checkpointWindow) (int64, int, error) {
	if kind == "disabled-latest" {
		return int64(state.Latest.Address) * checkpointBlockBytes, checkpointBlockBytes, nil
	}
	mapping := state.Base + uint64(state.Latest.DescriptorIndex)
	if kind == "bad-mapping" {
		return int64(mapping) * checkpointBlockBytes, 1, nil
	}
	if kind != "bad-object" {
		return 0, 0, fmt.Errorf("unknown checkpoint damage %q", kind)
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = f.Close() }()
	b := make([]byte, checkpointBlockBytes)
	if _, err := f.ReadAt(b, int64(mapping)*checkpointBlockBytes); err != nil {
		return 0, 0, err
	}
	le := binary.LittleEndian
	if !checkpointChecksumValid(b) || le.Uint32(b[24:])&0xffff != 12 || le.Uint32(b[36:]) == 0 {
		return 0, 0, errors.New("missing native checkpoint mapping for damage control")
	}
	address := le.Uint64(b[72:])
	if address == 0 || address >= 128<<20/checkpointBlockBytes {
		return 0, 0, io.ErrUnexpectedEOF
	}
	return int64(address) * checkpointBlockBytes, 1, nil
}
