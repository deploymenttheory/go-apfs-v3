package hfsplus

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

type journalTestBlock struct {
	number uint64
	data   []byte
}

func journalTestList(order binary.ByteOrder, sequence uint32, blocks ...journalTestBlock) []byte {
	data := make([]byte, 8192)
	order.PutUint16(data, 511)
	order.PutUint16(data[2:], uint16(1+len(blocks)))
	order.PutUint32(data[12:], 3)
	order.PutUint32(data[28:], sequence)
	for i, block := range blocks {
		info := data[32+i*16 : 48+i*16]
		order.PutUint64(info, block.number)
		order.PutUint32(info[8:], uint32(len(block.data)))
		order.PutUint32(info[12:], journalChecksum(block.data))
		data = append(data, block.data...)
	}
	order.PutUint32(data[4:], uint32(len(data)))
	order.PutUint32(data[8:], journalChecksum(data[:32]))
	return data
}

func journalTestRing(data []byte, base int, order binary.ByteOrder, start uint64, declared int, lists ...[]byte) uint64 {
	header := data[base : base+48]
	size := order.Uint64(header[24:])
	position, end := start, start
	for i, list := range lists {
		first := min(uint64(len(list)), size-position)
		copy(data[uint64(base)+position:], list[:first])
		copy(data[base+512:], list[first:])
		position = 512 + (position+uint64(len(list))-512)%(size-512)
		if i+1 == declared {
			end = position
		}
	}
	order.PutUint64(header[8:], start)
	order.PutUint64(header[16:], end)
	clear(header[36:40])
	order.PutUint32(header[36:], journalChecksum(header[:44]))
	return position
}

// Synthetic failure/ordering controls complement Apple-created recovery
// acceptance. They do not supply expected native filesystem states.
func TestJournalReplayOrdersOverlapsWrapsAndQualifiedTail(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, wrapped := range []bool{false, true} {
			t.Run(order.String()+map[bool]string{false: "/linear", true: "/wrapped"}[wrapped], func(t *testing.T) {
				data, _, base := journalMutationFixture(t, order)
				start := uint64(512)
				if wrapped {
					start = 256<<10 - 4096
				}
				first := journalTestList(order, 101, journalTestBlock{0, bytes.Repeat([]byte("a"), 1024)})
				second := journalTestList(order, 102, journalTestBlock{1, bytes.Repeat([]byte("b"), 1024)}, journalTestBlock{^uint64(0), bytes.Repeat([]byte("k"), 512)})
				tail := journalTestList(order, 103, journalTestBlock{2, bytes.Repeat([]byte("c"), 512)})
				end := journalTestRing(data, base, order, start, 2, first, second, tail)
				disk := &memoryMutation{bytes.Clone(data)}
				report, err := ReplayJournal(context.Background(), disk)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(disk.data[:512], bytes.Repeat([]byte("a"), 512)) || !bytes.Equal(disk.data[512:1024], bytes.Repeat([]byte("b"), 512)) || !bytes.Equal(disk.data[1024:1536], bytes.Repeat([]byte("c"), 512)) {
					t.Fatal("last-write partial overlap")
				}
				if report.RecoveredEnd != end || report.BlockLists != 3 || report.ExtraBlockLists != 1 || report.Transactions != 3 || report.Sectors != 3 {
					t.Fatal(report)
				}
				if order.Uint64(disk.data[base+8:]) != end || order.Uint64(disk.data[base+16:]) != end {
					t.Fatal("journal cursors")
				}
				if !bytes.Equal(disk.data[base+48:base+256<<10], data[base+48:base+256<<10]) {
					t.Fatal("history changed")
				}
			})
		}
	}
}

func TestJournalReplayRejectsCommittedCorruptionBeforeWriting(t *testing.T) {
	for _, problem := range []string{"header-checksum", "data-checksum", "sequence", "outside", "log-target", "info-target", "short-data", "header-count", "unknown-flags", "byte-accounting"} {
		t.Run(problem, func(t *testing.T) {
			order := binary.LittleEndian
			data, info, base := journalMutationFixture(t, order)
			first := journalTestList(order, 100, journalTestBlock{0, bytes.Repeat([]byte("a"), 512)})
			second := journalTestList(order, 101, journalTestBlock{1, bytes.Repeat([]byte("b"), 512)})
			switch problem {
			case "header-checksum":
				second[8] ^= 1
			case "data-checksum":
				second[8192] ^= 1
			case "sequence":
				order.PutUint32(second[28:], 900)
			case "outside":
				order.PutUint64(second[32:], uint64(len(data)/512))
			case "log-target":
				order.PutUint64(second[32:], uint64(base/512))
			case "info-target":
				order.PutUint64(second[32:], uint64(info/512))
			case "short-data":
				order.PutUint32(second[40:], 4096)
			case "header-count":
				order.PutUint16(second[2:], 512)
			case "unknown-flags":
				order.PutUint32(second[12:], 7)
			case "byte-accounting":
				order.PutUint16(second[2:], 1)
			}
			if problem != "header-checksum" {
				clear(second[8:12])
				order.PutUint32(second[8:], journalChecksum(second[:32]))
			}
			journalTestRing(data, base, order, 512, 2, first, second)
			disk := &memoryMutation{bytes.Clone(data)}
			if _, err := ReplayJournal(context.Background(), disk); err == nil {
				t.Fatal("corruption accepted")
			}
			if !bytes.Equal(disk.data, data) {
				t.Fatal("invalid committed log changed home blocks")
			}
		})
	}
}

func TestJournalReplayDropsIncompleteTailAndPropagatesCancellationAndWriteFailure(t *testing.T) {
	order := binary.LittleEndian
	data, _, base := journalMutationFixture(t, order)
	first := journalTestList(order, 100, journalTestBlock{0, bytes.Repeat([]byte("a"), 512)})
	tail := journalTestList(order, 101, journalTestBlock{1, bytes.Repeat([]byte("b"), 512)})
	tail[8192] ^= 1
	journalTestRing(data, base, order, 512, 1, first, tail)
	disk := &memoryMutation{bytes.Clone(data)}
	report, err := ReplayJournal(context.Background(), disk)
	if err != nil || report.RecoveredEnd != 512+uint64(len(first)) || report.BlockLists != 1 || !bytes.Equal(disk.data[512:1024], data[512:1024]) {
		t.Fatal(report, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	disk = &memoryMutation{bytes.Clone(data)}
	if _, err = ReplayJournal(ctx, disk); !errors.Is(err, context.Canceled) || !bytes.Equal(disk.data, data) {
		t.Fatal(err)
	}
	if _, err = ReplayJournal(context.Background(), shortMutation{disk}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	if !bytes.Equal(disk.data[base:base+48], data[base:base+48]) {
		t.Fatal("failed home writes advanced journal")
	}
	broken := bytes.Clone(data)
	order.PutUint64(broken[base+8:], 0)
	if _, err = ReplayJournal(context.Background(), &memoryMutation{broken}); !errors.Is(err, filesystem.ErrCorrupt) {
		t.Fatal(err)
	}
}

func TestJournalReplayContinuationAndIncompleteWholeTailTransaction(t *testing.T) {
	order := binary.LittleEndian
	data, _, base := journalMutationFixture(t, order)
	committed := journalTestList(order, 100, journalTestBlock{0, bytes.Repeat([]byte("a"), 512)})
	first := journalTestList(order, 101, journalTestBlock{1, bytes.Repeat([]byte("b"), 512)})
	continuation := journalTestList(order, 101, journalTestBlock{2, bytes.Repeat([]byte("c"), 512)})
	order.PutUint32(continuation[12:], 1)
	clear(continuation[8:12])
	order.PutUint32(continuation[8:], journalChecksum(continuation[:32]))
	end := journalTestRing(data, base, order, 512, 1, committed, first, continuation)
	disk := &memoryMutation{bytes.Clone(data)}
	report, err := ReplayJournal(context.Background(), disk)
	if err != nil || report.Transactions != 2 || report.BlockLists != 3 || report.ExtraBlockLists != 2 || report.RecoveredEnd != end {
		t.Fatal(report, err)
	}
	continuation[8192] ^= 1
	journalTestRing(data, base, order, 512, 1, committed, first, continuation)
	disk = &memoryMutation{bytes.Clone(data)}
	report, err = ReplayJournal(context.Background(), disk)
	if err != nil || report.Transactions != 1 || report.BlockLists != 1 || report.ExtraBlockLists != 0 || report.RecoveredEnd != 512+uint64(len(committed)) || !bytes.Equal(disk.data[512:1536], data[512:1536]) {
		t.Fatal("incomplete continuation did not drop the whole tentative transaction", report, err)
	}
}

func TestJournalReaderRefusesPendingRecordsDespiteUnmountedBit(t *testing.T) {
	order := binary.LittleEndian
	data, _, base := journalMutationFixture(t, order)
	journalTestRing(data, base, order, 512, 1, journalTestList(order, 100, journalTestBlock{0, make([]byte, 512)}))
	volume, err := Open(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if !volume.Clean || volume.Journal == nil || !volume.Journal.Pending {
		t.Fatal("actual header flags and journal state must stay distinct")
	}
	if _, err = volume.Stat(context.Background(), 2); !errors.Is(err, filesystem.ErrUnsupported) {
		t.Fatal("pending journal was hidden by the primary unmounted bit", err)
	}
}
