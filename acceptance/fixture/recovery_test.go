package fixture

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func TestImageHelperRequiresTheExactOwnedWritableAttachment(t *testing.T) {
	image := filepath.Join(t.TempDir(), "owned.raw")
	if err := os.WriteFile(image, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "unrelated.raw")
	if err := os.WriteFile(other, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"owned", "another image", "another device", "readonly", "another owner", "missing owner", "pid one", "fractional pid", "duplicate attachment"} {
		t.Run(scenario, func(t *testing.T) {
			m := map[string]any{"image-path": image, "writeable": true, "owner-uid": float64(501), "hdid-pid": float64(123), "system-entities": []any{map[string]any{"dev-entry": "/dev/disk42"}}}
			switch scenario {
			case "another image":
				m["image-path"] = other
			case "another device":
				m["system-entities"] = []any{map[string]any{"dev-entry": "/dev/disk43"}}
			case "readonly":
				m["writeable"] = false
			case "another owner":
				m["owner-uid"] = float64(0)
			case "missing owner":
				delete(m, "owner-uid")
			case "pid one":
				m["hdid-pid"] = float64(1)
			case "fractional pid":
				m["hdid-pid"] = 123.5
			}
			images := []any{m}
			if scenario == "duplicate attachment" {
				images = append(images, m)
			}
			pid, err := imageHelperOwner(map[string]any{"images": images}, image, "/dev/disk42", 501)
			if scenario == "owned" {
				if err != nil || pid != 123 {
					t.Fatal(pid, err)
				}
			} else if err == nil {
				t.Fatal("unsafe helper admitted", pid)
			}
		})
	}
}

func sealAcquisitionCheckpoint(b []byte) {
	var a, c uint64
	const modulus = uint64(0xffffffff)
	for i := 8; i < len(b); i += 4 {
		a = (a + uint64(binary.LittleEndian.Uint32(b[i:]))) % modulus
		c = (c + a) % modulus
	}
	x := modulus - (a+c)%modulus
	y := modulus - (a+x)%modulus
	binary.LittleEndian.PutUint64(b, y<<32|x)
}

func checkpointAcquisitionFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "checkpoint.raw")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(128 << 20); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4096)
	le := binary.LittleEndian
	copy(b[32:], "NXSB")
	le.PutUint64(b[16:], 1)
	le.PutUint32(b[104:], 4)
	le.PutUint32(b[108:], 8)
	le.PutUint64(b[112:], 1)
	le.PutUint64(b[120:], 8)
	le.PutUint32(b[128:], 2)
	le.PutUint32(b[132:], 1)
	le.PutUint32(b[136:], 0)
	le.PutUint32(b[140:], 2)
	le.PutUint32(b[144:], 0)
	le.PutUint32(b[148:], 1)
	sealAcquisitionCheckpoint(b)
	if _, err := f.WriteAt(b, 0); err != nil {
		t.Fatal(err)
	}
	le.PutUint64(b[16:], 2)
	sealAcquisitionCheckpoint(b)
	if _, err := f.WriteAt(b, 2*4096); err != nil {
		t.Fatal(err)
	}
	// One mapping names a bounded physical object for deliberate checksum damage.
	clear(b)
	le.PutUint32(b[24:], 12)
	le.PutUint64(b[16:], 2)
	le.PutUint32(b[36:], 1)
	le.PutUint64(b[72:], 20)
	sealAcquisitionCheckpoint(b)
	if _, err := f.WriteAt(b, 4096); err != nil {
		t.Fatal(err)
	}
	clear(b)
	le.PutUint64(b[16:], 3)
	sealAcquisitionCheckpoint(b)
	if _, err := f.WriteAt(b, 9*4096); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCheckpointAcquisitionMeasuresFutureWritesAndBoundsDamage(t *testing.T) {
	p := checkpointAcquisitionFile(t)
	s, err := measureCheckpoints(p)
	if err != nil {
		t.Fatal(err)
	}
	if s.BlockZero != 1 || s.Latest.XID != 2 || s.Latest.Address != 2 || s.Future["data"] != 9 {
		t.Fatalf("wrong acquisition state: %+v", s)
	}
	for kind, want := range map[string]int64{"bad-mapping": 4096, "bad-object": 20 * 4096, "disabled-latest": 2 * 4096} {
		offset, count, err := checkpointDamageOffset(p, kind, s)
		if err != nil || offset != want || count != map[bool]int{true: 4096, false: 1}[kind == "disabled-latest"] {
			t.Fatal(kind, offset, count, err)
		}
	}
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteAt([]byte{0xff}, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := measureCheckpoints(p); err == nil {
		t.Fatal("damaged acquisition geometry admitted")
	}
}

func TestCheckpointAcquisitionRejectsUnboundedRingsAndInvalidCursors(t *testing.T) {
	for _, fault := range []string{"descriptor count", "data range", "cursor", "no descriptor"} {
		t.Run(fault, func(t *testing.T) {
			p := checkpointAcquisitionFile(t)
			f, err := os.OpenFile(p, os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			b := make([]byte, 4096)
			if _, err := f.ReadAt(b, 0); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "descriptor count":
				binary.LittleEndian.PutUint32(b[104:], 257)
			case "data range":
				binary.LittleEndian.PutUint64(b[120:], 1<<50)
			case "cursor":
				binary.LittleEndian.PutUint32(b[128:], 4)
			case "no descriptor":
				if _, err := f.WriteAt(make([]byte, 4096), 2*4096); err != nil {
					t.Fatal(err)
				}
			}
			sealAcquisitionCheckpoint(b)
			if _, err := f.WriteAt(b, 0); err != nil {
				t.Fatal(err)
			}
			if fault == "cursor" {
				if _, err := f.WriteAt(b, 2*4096); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := measureCheckpoints(p); err == nil {
				t.Fatal("invalid checkpoint acquisition accepted")
			}
		})
	}
}

func journalAcquisitionFile(t *testing.T) (string, *journalWindow) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "journal.raw")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(64 << 20); err != nil {
		t.Fatal(err)
	}
	be, le := binary.BigEndian, binary.LittleEndian
	volume := make([]byte, 512)
	copy(volume, "H+")
	be.PutUint32(volume[40:], 4096)
	be.PutUint32(volume[12:], 1)
	if _, err := f.WriteAt(volume, 1024); err != nil {
		t.Fatal(err)
	}
	info := make([]byte, 180)
	be.PutUint32(info, 1)
	be.PutUint64(info[36:], 8192)
	be.PutUint64(info[44:], 1<<20)
	if _, err := f.WriteAt(info, 4096); err != nil {
		t.Fatal(err)
	}
	h := make([]byte, 48)
	copy(h, "xLNJ")
	le.PutUint32(h[4:], 0x12345678)
	le.PutUint64(h[8:], 512)
	le.PutUint64(h[16:], 1536)
	le.PutUint64(h[24:], 1<<20)
	le.PutUint32(h[32:], 512)
	le.PutUint32(h[40:], 512)
	le.PutUint32(h[44:], 7)
	le.PutUint32(h[36:], acquisitionJournalChecksum(h[:44]))
	if _, err := f.WriteAt(h, 8192); err != nil {
		t.Fatal(err)
	}
	list := make([]byte, 512)
	le.PutUint16(list, 31)
	le.PutUint16(list[2:], 2)
	le.PutUint32(list[4:], 1024)
	le.PutUint32(list[12:], 3)
	le.PutUint32(list[28:], 7)
	le.PutUint64(list[32:], 80)
	le.PutUint32(list[40:], 512)
	payload := make([]byte, 512)
	copy(payload, "native committed metadata")
	le.PutUint32(list[44:], acquisitionJournalChecksum(payload))
	le.PutUint32(list[8:], acquisitionJournalChecksum(list[:32]))
	if _, err := f.WriteAt(list, 8192+512); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(payload, 8192+1024); err != nil {
		t.Fatal(err)
	}
	s, err := measureJournal(p)
	if err != nil {
		t.Fatal(err)
	}
	return p, s
}

func TestJournalAcquisitionDistinguishesUnappliedMetadataAndTailCompleteness(t *testing.T) {
	for _, tail := range []string{"absent", "complete", "incomplete"} {
		t.Run(tail, func(t *testing.T) {
			p, s := journalAcquisitionFile(t)
			f, err := os.OpenFile(p, os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if tail != "absent" {
				b := make([]byte, 1024)
				if _, err := f.ReadAt(b, 8192+512); err != nil {
					t.Fatal(err)
				}
				if tail == "incomplete" {
					b[512] ^= 1
				}
				if _, err := f.WriteAt(b, 8192+1536); err != nil {
					t.Fatal(err)
				}
			}
			changes, kind, err := measureJournalChanges(p, s)
			if err != nil || changes != 1 {
				t.Fatal(changes, kind, err)
			}
			want := ""
			if tail != "absent" {
				want = tail + "-tail"
			}
			if kind != want {
				t.Fatal(kind, want)
			}
			payload := make([]byte, 512)
			if _, err := f.ReadAt(payload, 8192+1024); err != nil {
				t.Fatal(err)
			}
			if _, err := f.WriteAt(payload, 80*512); err != nil {
				t.Fatal(err)
			}
			changes, _, err = measureJournalChanges(p, s)
			if err != nil || changes != 0 {
				t.Fatal("completed home writes mistaken for interruption", changes, err)
			}
			if tail != "absent" && !journalWindowMatches(s, want, s.End, changes, want) {
				t.Fatal("valid native tail rejected after committed home writes completed")
			}
			if journalWindowMatches(s, "linear", s.End, changes, "") {
				t.Fatal("completed home writes mistaken for a pending linear commit")
			}
		})
	}
}

func TestJournalAcquisitionRejectsCommittedChecksumDamage(t *testing.T) {
	p, s := journalAcquisitionFile(t)
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteAt([]byte{0xff}, 8192+1024); err != nil {
		t.Fatal(err)
	}
	if _, _, err := measureJournalChanges(p, s); !errors.Is(err, errJournalAcquisition) {
		t.Fatal("damaged committed payload was not classified as an unusable acquisition", err)
	}
}

func TestRejectedAcquisitionPreservesItsFirstSnapshotAndDoesNotRetryIOFailures(t *testing.T) {
	profile, _ := schema.LookupProfile("hfsx-j")
	c := &Capture{Profile: profile, Out: t.TempDir(), t: &Transcript{}}
	first, _ := journalAcquisitionFile(t)
	before, err := schema.FileDigest(first)
	if err != nil {
		t.Fatal(err)
	}
	stage := "interrupted-incomplete-tail"
	if err := c.rejectAcquisition(first, stage, map[string]any{"attempt": 0}, rejectJournalAcquisition("partially written committed list")); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(c.Out, c.prefix()+"."+stage+".rejected.raw.gz")
	digest, err := schema.FileDigest(archive)
	if err != nil {
		t.Fatal(err)
	}
	expanded := filepath.Join(t.TempDir(), "original.raw")
	if err := gunzipCopy(archive, expanded); err != nil {
		t.Fatal(err)
	}
	if after, err := schema.FileDigest(expanded); err != nil || after != before {
		t.Fatal("rejected evidence changed", err)
	}
	second, _ := journalAcquisitionFile(t)
	if err := c.rejectAcquisition(second, stage, map[string]any{"attempt": 1}, rejectJournalAcquisition("another partial list")); err != nil {
		t.Fatal(err)
	}
	if after, err := schema.FileDigest(archive); err != nil || after != digest {
		t.Fatal("later rejection overwrote original evidence", err)
	}
	third, _ := journalAcquisitionFile(t)
	if err := c.rejectAcquisition(third, stage, map[string]any{}, os.ErrPermission); !errors.Is(err, os.ErrPermission) {
		t.Fatal("I/O error entered the acquisition retry path", err)
	}
	if _, err := os.Stat(third); err != nil {
		t.Fatal("I/O failure discarded its input", err)
	}
	if len(c.t.Commands) != 2 {
		t.Fatal("acquisition rejections were not recorded", len(c.t.Commands))
	}
}
