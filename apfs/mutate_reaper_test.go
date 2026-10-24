package apfs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

type reaperMutationDisk struct {
	*bytes.Reader
	data   []byte
	writes int
}

func newReaperMutationDisk(data []byte) *reaperMutationDisk {
	b := bytes.Clone(data)
	return &reaperMutationDisk{Reader: bytes.NewReader(b), data: b}
}

func (d *reaperMutationDisk) WriteAt(data []byte, offset int64) (int, error) {
	d.writes++
	if offset < 0 || offset > int64(len(d.data)) || int64(len(data)) > int64(len(d.data))-offset {
		return 0, fs.ErrInvalid
	}
	return copy(d.data[offset:], data), nil
}

// This small Go-built image adds the published reaper-list layout, with the
// idle empty indices independently observed in Apple's selected checkpoint:
// flags=0, maximum=100, occupied=0, first/last=-1 and free=1. It does not copy
// native disk bytes or claim to reproduce native active reaping. Free entries
// retain nonzero completed-work payloads; only the linked occupied list is work.
func idleReaperImage(t *testing.T, pages int) []byte {
	t.Helper()
	data := builtContainer(t, stageFixture(t))
	nx := data[:4096]
	base := le.Uint64(nx[120:])
	length := le.Uint32(nx[148:])
	nextOID := le.Uint64(nx[88:])
	reaper := data[base*4096 : (base+1)*4096]
	le.PutUint64(reaper[32:], 2)
	le.PutUint64(reaper[40:], 1)
	le.PutUint64(reaper[48:], nextOID+uint64(pages-1))
	le.PutUint64(reaper[56:], nextOID)
	le.PutUint32(reaper[68:], uint32(pages))
	le.PutUint32(reaper[72:], 13)
	le.PutUint32(reaper[76:], 4096)
	seal(reaper)
	mapping := data[4096:8192]
	for i := range pages {
		// Descending OIDs distinguish link order from sorting or map iteration.
		oid := nextOID + uint64(pages-1-i)
		address := base + uint64(length) + uint64(i)
		page := data[address*4096 : (address+1)*4096]
		le.PutUint64(page[8:], oid)
		le.PutUint64(page[16:], 1)
		le.PutUint32(page[24:], 0x80000012)
		if i+1 < pages {
			le.PutUint64(page[32:], oid-1)
		}
		le.PutUint32(page[44:], 100)
		le.PutUint32(page[52:], math.MaxUint32)
		le.PutUint32(page[56:], math.MaxUint32)
		le.PutUint32(page[60:], 1)
		for j := range 100 {
			entry := page[64+j*40:]
			next := uint32(j + 1)
			switch j {
			case 0:
				next = 2
			case 1:
				next = 0
			case 99:
				next = math.MaxUint32
			}
			le.PutUint32(entry, next)
			if j < 3 {
				le.PutUint32(entry[8:], 13)
				le.PutUint32(entry[12:], 4096)
				le.PutUint64(entry[16:], 1026)
				le.PutUint64(entry[24:], uint64(1852-j))
				le.PutUint64(entry[32:], 4)
			}
		}
		seal(page)
		r := mapping[40+(4+i)*40:]
		le.PutUint32(r, 0x80000012)
		le.PutUint32(r[8:], 4096)
		le.PutUint64(r[24:], oid)
		le.PutUint64(r[32:], address)
	}
	le.PutUint32(mapping[36:], uint32(4+pages))
	seal(mapping)
	for _, address := range []uint64{0, 2} {
		nx := data[address*4096 : (address+1)*4096]
		le.PutUint64(nx[88:], nextOID+uint64(pages))
		le.PutUint32(nx[132:], length+uint32(pages))
		le.PutUint32(nx[148:], length+uint32(pages))
		seal(nx)
	}
	return data
}

func reaperCheckpointObjects(t *testing.T, data []byte) (*Container, []checkpointObject) {
	t.Helper()
	c, err := Open(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	nx := data[uint64(c.Checkpoint)*4096 : (uint64(c.Checkpoint)+1)*4096]
	objects, err := c.checkpointObjects(context.Background(), nx)
	if err != nil {
		t.Fatal(err)
	}
	return c, objects
}

func TestAPFSMutationCarriesIdleEmptyReaperPagesThroughCheckpointWrap(t *testing.T) {
	ctx := context.Background()
	for _, pages := range []int{1, 2} {
		t.Run(fmt.Sprintf("%d-linked-pages", pages), func(t *testing.T) {
			source := idleReaperImage(t, pages)
			digest := sha256.Sum256(source)
			if err := ValidateMutation(ctx, bytes.NewReader(source)); err != nil {
				t.Fatal("idle empty list was not admitted", err)
			}
			original, before := reaperCheckpointObjects(t, source)
			disks := []*reaperMutationDisk{newReaperMutationDisk(source), newReaperMutationDisk(source)}
			var want []byte
			steps := int(le.Uint32(source[108:])/le.Uint32(source[148:])) + 2
			wrapped := false
			previous := uint32(0)
			for i := range steps {
				want = fmt.Appendf(nil, "ordinary continuation %d", i)
				for _, disk := range disks {
					if _, err := Modify(ctx, disk, []Change{{Path: "/continued", Data: bytes.NewReader(want)}}, builtClock); err != nil {
						t.Fatal("ordinary write with idle list", i, err)
					}
				}
				c, objects := reaperCheckpointObjects(t, disks[0].data)
				if c.UUID != original.UUID || c.Volumes[0].UUID != original.Volumes[0].UUID || c.XID != original.XID+XID(i+1) {
					t.Fatal("continuation changed identity or transaction", c)
				}
				nx := disks[0].data[uint64(c.Checkpoint)*4096:]
				index := le.Uint32(nx[144:])
				wrapped = wrapped || index < previous
				previous = index
				var carried []checkpointObject
				for _, object := range objects {
					if object.kind == 0x80000011 || object.kind == 0x80000012 {
						carried = append(carried, object)
					}
				}
				at := 0
				for _, object := range before {
					if object.kind != 0x80000011 && object.kind != 0x80000012 {
						continue
					}
					if at >= len(carried) || carried[at].oid != object.oid {
						t.Fatal("linked page order or identity changed", before, carried)
					}
					expected := bytes.Clone(object.data)
					le.PutUint64(expected[16:], uint64(c.XID))
					seal(expected)
					if !bytes.Equal(carried[at].data, expected) {
						t.Fatal("idle object bytes changed beyond transaction/checksum", object.oid)
					}
					at++
				}
				if at != len(carried) {
					t.Fatal("unexpected carried reaper object", carried)
				}
			}
			if !wrapped || !bytes.Equal(disks[0].data, disks[1].data) {
				t.Fatal("checkpoint wrap or deterministic serialization failed", wrapped)
			}
			if err := ValidateMutation(ctx, disks[0]); err != nil {
				t.Fatal("continued image is not editable", err)
			}
			c, err := Open(disks[0])
			if err != nil {
				t.Fatal(err)
			}
			for path, expected := range map[string][]byte{
				"/continued":     want,
				"/Fixture/data":  []byte("built fixture payload\n"),
				"/Fixture/alias": []byte("built fixture payload\n"),
			} {
				id, err := filesystem.LookupExact(ctx, &c.Volumes[0], path)
				if err != nil {
					t.Fatal(path, err)
				}
				value, err := c.Volumes[0].OpenData(ctx, id)
				if err != nil {
					t.Fatal(err)
				}
				got := make([]byte, value.Size())
				_, err = value.ReadAt(got, 0)
				closeErr := value.Close()
				if err != nil && !errors.Is(err, io.EOF) || closeErr != nil || !bytes.Equal(got, expected) {
					t.Fatal("continued or untouched file changed", path, err, closeErr)
				}
			}
			if sha256.Sum256(source) != digest {
				t.Fatal("immutable input changed")
			}
		})
	}
}

func TestAPFSMutationRejectsUnsupportedReaperStateBeforeWriting(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(reaper, first, last, mapping []byte)
		want error
	}{
		{"active reaper", func(r, _, _, _ []byte) { le.PutUint32(r[64:], 0) }, filesystem.ErrUnsupported},
		{"occupied later page", func(_, _, p, _ []byte) { le.PutUint32(p[48:], 1) }, filesystem.ErrUnsupported},
		{"unknown list flags", func(_, p, _, _ []byte) { le.PutUint32(p[40:], 1) }, filesystem.ErrUnsupported},
		{"unknown list layout", func(_, p, _, _ []byte) { le.PutUint32(p[44:], 101) }, filesystem.ErrUnsupported},
		{"occupied index on empty page", func(_, p, _, _ []byte) { le.PutUint32(p[52:], 0) }, filesystem.ErrCorrupt},
		{"invalid free index", func(_, p, _, _ []byte) { le.PutUint32(p[60:], 100) }, filesystem.ErrCorrupt},
		{"cycle", func(_, p, _, _ []byte) { le.PutUint64(p[32:], le.Uint64(p[8:])) }, filesystem.ErrCorrupt},
		{"missing page", func(_, p, _, _ []byte) { le.PutUint64(p[32:], 9000) }, filesystem.ErrCorrupt},
		{"wrong page count", func(r, _, _, _ []byte) { le.PutUint32(r[68:], 1) }, filesystem.ErrCorrupt},
		{"wrong tail", func(r, p, _, _ []byte) { le.PutUint64(r[56:], le.Uint64(p[8:])) }, filesystem.ErrCorrupt},
		{"headless inventory", func(r, _, _, _ []byte) { le.PutUint64(r[48:], 0) }, filesystem.ErrCorrupt},
		{"unlinked ephemeral page", func(r, _, _, _ []byte) { clear(r[48:64]); le.PutUint32(r[68:], 0) }, filesystem.ErrUnsupported},
		{"unknown linked object", func(_, p, _, m []byte) {
			le.PutUint32(p[24:], 0x80000013)
			le.PutUint32(m[40+4*40:], 0x80000013)
		}, filesystem.ErrCorrupt},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := idleReaperImage(t, 2)
			base := le.Uint64(data[120:])
			r := data[base*4096 : (base+1)*4096]
			first := data[(base+4)*4096 : (base+5)*4096]
			last := data[(base+5)*4096 : (base+6)*4096]
			mapping := data[4096:8192]
			tc.edit(r, first, last, mapping)
			for _, b := range [][]byte{r, first, last, mapping} {
				seal(b)
			}
			digest := sha256.Sum256(data)
			disk := newReaperMutationDisk(data)
			if err := ValidateMutation(context.Background(), bytes.NewReader(data)); !errors.Is(err, tc.want) {
				t.Fatal("validation refusal changed", err)
			}
			_, err := Modify(context.Background(), disk, []Change{{Path: "/continued", Data: bytes.NewReader([]byte("must not write"))}}, builtClock)
			if !errors.Is(err, tc.want) || disk.writes != 0 || sha256.Sum256(disk.data) != digest || sha256.Sum256(data) != digest {
				t.Fatal("unsupported reaper state reached a write or changed source", err, disk.writes)
			}
		})
	}
}
