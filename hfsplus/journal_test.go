package hfsplus

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/session"
)

// Synthetic safety controls complement the independent Apple acceptance corpus.
// They do not supply native expected filesystem outcomes.
func journalMutationFixture(t *testing.T, order binary.ByteOrder) ([]byte, int, int) {
	t.Helper()
	ctx := context.Background()
	s, err := session.Create(ctx, filepath.Join(t.TempDir(), "session"), session.Options{Names: filesystem.NameRules{Format: "HFS+", NormalizationInsensitive: true}, Time: &mutationTime})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, name := range []string{".journal", ".journal_info_block", "file"} {
		size := 4096
		if name == ".journal" {
			size = 256 << 10
		}
		path := filepath.Join(t.TempDir(), "host")
		if err = os.WriteFile(path, make([]byte, size), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = s.Copy(ctx, []string{path}, "/"+name, session.CopyOptions{FromHost: true}); err != nil {
			t.Fatal(err)
		}
	}
	p, err := Plan(ctx, s, BuildOptions{Name: "Journal safety", Time: mutationTime, Capacity: 16 << 20})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err = p.Write(ctx, &out); err != nil {
		t.Fatal(err)
	}
	b := out.Bytes()
	v, err := Open(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	location := func(name string) int {
		t.Helper()
		id, e := filesystem.Lookup(ctx, v, "/"+name)
		if e != nil {
			t.Fatal(e)
		}
		r, e := v.catalogRecord(ctx, id)
		if e != nil {
			t.Fatal(e)
		}
		return int(be.Uint32(r[104:])) * int(v.BlockSize)
	}
	info, journal := location(".journal_info_block"), location(".journal")
	be.PutUint32(b[info:], 1)
	be.PutUint64(b[info+36:], uint64(journal))
	be.PutUint64(b[info+44:], 256<<10)
	h := b[journal : journal+48]
	order.PutUint32(h, journalHeaderMagic)
	order.PutUint32(h[4:], journalEndianMagic)
	order.PutUint64(h[8:], 512)
	order.PutUint64(h[16:], 512)
	order.PutUint64(h[24:], 256<<10)
	order.PutUint32(h[32:], 8192)
	order.PutUint32(h[40:], 512)
	order.PutUint32(h[44:], 73)
	order.PutUint32(h[36:], journalChecksum(h[:44]))
	for _, off := range []int{1024, len(b) - 1024} {
		be.PutUint32(b[off+4:], be.Uint32(b[off+4:])|0x2000)
		copy(b[off+8:], "HFSJ")
		be.PutUint32(b[off+12:], uint32(info/int(v.BlockSize)))
	}
	return b, info, journal
}

func TestJournaledMutationPreservesStorageAndRefusesBackingFiles(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		t.Run(order.String(), func(t *testing.T) {
			b, info, journal := journalMutationFixture(t, order)
			ctx := context.Background()
			disk := &memoryMutation{bytes.Clone(b)}
			// All retained Apple clean journaled detaches leave the alternate's
			// unmounted bit clear; this does not mean journal replay is needed.
			be.PutUint32(disk.data[len(b)-1020:], be.Uint32(disk.data[len(b)-1020:]) & ^uint32(0x100))
			for _, change := range []Change{{Path: "/file", Data: bytes.NewReader(bytes.Repeat([]byte("grow"), 4000))}, {Path: "/file", Data: bytes.NewReader(nil)}, {Path: "/file", Mode: "0755"}} {
				if _, e := Modify(ctx, disk, []Change{change}, mutationTime); e != nil {
					t.Fatal(e)
				}
				if e := ValidateMutation(ctx, disk); e != nil {
					t.Fatal(e)
				}
				if !bytes.Equal(disk.data[info:info+4096], b[info:info+4096]) || !bytes.Equal(disk.data[journal:journal+256<<10], b[journal:journal+256<<10]) {
					t.Fatal("journal storage changed")
				}
			}
			for _, name := range []string{".journal", ".journal_info_block", ".JOURNAL"} {
				for _, change := range []Change{{Path: "/" + name, Mode: "0755"}, {Path: "/" + name, Data: bytes.NewReader(nil)}, {Path: "/" + name, Data: bytes.NewReader([]byte("fork")), ResourceFork: true}} {
					before := bytes.Clone(disk.data)
					if _, e := Modify(ctx, disk, []Change{change}, mutationTime); !errors.Is(e, filesystem.ErrUnsupported) {
						t.Fatal("journal backing edit admitted", e)
					}
					if !bytes.Equal(before, disk.data) {
						t.Fatal("refused journal edit wrote bytes")
					}
				}
			}
			if _, e := Modify(ctx, shortMutation{disk}, []Change{{Path: "/file", Data: bytes.NewReader([]byte("failure"))}}, mutationTime); !errors.Is(e, io.ErrShortWrite) {
				t.Fatal(e)
			}
		})
	}
}

func TestJournalAdmissionRejectsUnsafeStateBeforeWriting(t *testing.T) {
	b, info, journal := journalMutationFixture(t, binary.LittleEndian)
	for _, kind := range []string{"external", "need-init", "unknown-flags", "info-range", "journal-range", "overlap", "checksum", "magic", "old-header", "endian", "size", "header-size", "list-size", "cursor-range", "cursor-alignment", "pending", "alternate"} {
		t.Run(kind, func(t *testing.T) {
			badDisk := bytes.Clone(b)
			h := badDisk[journal : journal+48]
			le := binary.LittleEndian
			switch kind {
			case "external":
				be.PutUint32(badDisk[info:], 2)
			case "need-init":
				be.PutUint32(badDisk[info:], 5)
			case "unknown-flags":
				be.PutUint32(badDisk[info:], 9)
			case "info-range":
				be.PutUint32(badDisk[1036:], 1<<31)
				be.PutUint32(badDisk[len(badDisk)-1012:], 1<<31)
			case "journal-range":
				be.PutUint64(badDisk[info+36:], 1<<63)
			case "overlap":
				be.PutUint64(badDisk[info+36:], uint64(info))
			case "checksum":
				h[36] ^= 1
			case "magic":
				h[0] ^= 1
			case "old-header":
				le.PutUint32(h, 0x4a484452)
			case "endian":
				h[4] ^= 1
			case "size":
				le.PutUint64(h[24:], 512<<10)
			case "header-size":
				le.PutUint32(h[40:], 0)
			case "list-size":
				le.PutUint32(h[32:], 1<<31)
			case "cursor-range":
				le.PutUint64(h[8:], 0)
				le.PutUint64(h[16:], 0)
			case "cursor-alignment":
				le.PutUint64(h[8:], 513)
				le.PutUint64(h[16:], 513)
			case "pending":
				le.PutUint64(h[16:], 1024)
			case "alternate":
				be.PutUint32(badDisk[len(badDisk)-1012:], 1)
			}
			if kind != "checksum" {
				clear(h[36:40])
				le.PutUint32(h[36:], journalChecksum(h[:44]))
			}
			disk := &memoryMutation{badDisk}
			before := bytes.Clone(badDisk)
			_, e := Modify(context.Background(), disk, []Change{{Path: "/file", Data: bytes.NewReader([]byte("new"))}}, mutationTime)
			if e == nil {
				t.Fatal("unsafe journal admitted")
			}
			if (kind == "pending" || kind == "old-header") && !errors.Is(e, filesystem.ErrUnsupported) {
				t.Fatal("unsupported journal classification", e)
			}
			if (kind == "magic" || kind == "checksum") && !errors.Is(e, filesystem.ErrCorrupt) {
				t.Fatal("corrupt journal classification", e)
			}
			if !bytes.Equal(before, badDisk) {
				t.Fatal("journal admission changed bytes")
			}
		})
	}
}
