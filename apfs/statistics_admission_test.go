package apfs

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"math"
	"os"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// The original Apple disk supplies a real nested statistics graph. Faults below
// are explicit corruption/overflow controls, not expected native edit outcomes.
func nativeStatisticsMutation(t *testing.T) *mutation {
	t.Helper()
	f, err := os.Open("../acceptance/testdata/apfs-directory-statistics/macos-15/apfs-directory-statistics-source.raw.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	disk, err := io.ReadAll(io.LimitReader(z, (128<<20)+1))
	if err != nil || len(disk) != 128<<20 {
		t.Fatal("native statistics disk bound", err)
	}
	m, err := openMutation(context.Background(), readOnlyMutation{bytes.NewReader(disk)})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestDirectoryStatisticsCorruptionRefused(t *testing.T) {
	for _, fault := range []string{"missing group", "orphan group", "wrong count", "chain cycle", "missing reference"} {
		t.Run(fault, func(t *testing.T) {
			m := nativeStatisticsMutation(t)
			entry, err := m.lookupEntry("/Fixture")
			if err != nil {
				t.Fatal(err)
			}
			key, err := m.statisticsKey(entry.id)
			if err != nil {
				t.Fatal(err)
			}
			r, _ := m.fs.get(buildKey(key, 10, 0))
			value := bytes.Clone(r.value)
			switch fault {
			case "missing group":
				err = m.fs.put(r.key, nil)
			case "orphan group":
				err = m.fs.put(buildKey(objectMask-1, 10, 0), make([]byte, 32))
			case "wrong count":
				le.PutUint64(value, le.Uint64(value)+1)
				err = m.fs.put(r.key, value)
			case "chain cycle":
				le.PutUint64(value[16:], key)
				err = m.fs.put(r.key, value)
			case "missing reference":
				inode, _ := m.inodeRecord(entry.id)
				value, err = removeInodeField(inode.value, 10)
				if err == nil {
					err = m.fs.put(inode.key, value)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = m.updateStatistics(true); !errors.Is(err, filesystem.ErrCorrupt) {
				t.Fatal("corrupt statistics admitted", err)
			}
		})
	}
}

func TestDirectoryStatisticsGenerationNeverWraps(t *testing.T) {
	m := nativeStatisticsMutation(t)
	entry, err := m.lookupEntry("/Fixture")
	if err != nil {
		t.Fatal(err)
	}
	key, err := m.statisticsKey(entry.id)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := m.fs.get(buildKey(key, 10, 0))
	value := bytes.Clone(r.value)
	le.PutUint64(value[24:], math.MaxUint64)
	if err = m.fs.put(r.key, value); err != nil {
		t.Fatal(err)
	}
	if err = m.bumpStatistics(key, 1); !errors.Is(err, filesystem.ErrLimit) {
		t.Fatal("generation overflow admitted", err)
	}
	r, _ = m.fs.get(r.key)
	if le.Uint64(r.value[24:]) != math.MaxUint64 {
		t.Fatal("overflow changed the record")
	}
}
