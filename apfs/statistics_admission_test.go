package apfs

import (
	"bytes"
	"context"
	"errors"
	"math"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// Apple-populated statistics graphs belong to the acceptance tier. Here the
// product's own record primitives attach one origin group to a Go-built
// directory in memory; the faults below are corruption/overflow controls on
// that graph, never expected native edit outcomes.
func syntheticStatisticsMutation(t *testing.T) (*mutation, *mutationEntry, uint64) {
	t.Helper()
	data := builtContainer(t, stageFixture(t))
	m, err := openMutation(context.Background(), readOnlyMutation{bytes.NewReader(data)})
	if err != nil {
		t.Fatal(err)
	}
	entry, err := m.lookupEntry("/Fixture")
	if err != nil {
		t.Fatal(err)
	}
	key, err := m.nextFileID()
	if err != nil {
		t.Fatal(err)
	}
	group := make([]byte, 32)
	le.PutUint64(group[24:], 1)
	if err = m.fs.put(buildKey(key, 10, 0), group); err != nil {
		t.Fatal(err)
	}
	if err = m.setStatisticsReference(entry.id, key, true); err != nil {
		t.Fatal(err)
	}
	for _, child := range m.children(entry.id) {
		if child != m.primaryEntry(child.id) {
			continue
		}
		if err = m.setStatisticsReference(child.id, key, false); err != nil {
			t.Fatal(err)
		}
	}
	if err = m.updateStatistics(false); err != nil {
		t.Fatal(err)
	}
	if err = m.updateStatistics(true); err != nil {
		t.Fatal("synthetic statistics graph is not self-consistent", err)
	}
	r, ok := m.fs.get(buildKey(key, 10, 0))
	if !ok || le.Uint64(r.value) != 1 || le.Uint64(r.value[8:]) == 0 {
		t.Fatal("origin totals were not recomputed", r)
	}
	got, err := m.statisticsKey(entry.id)
	if err != nil || got != key {
		t.Fatal("origin reference", got, err)
	}
	return m, entry, key
}

func TestDirectoryStatisticsCorruptionRefused(t *testing.T) {
	for _, fault := range []string{"missing group", "orphan group", "wrong count", "chain cycle", "missing reference"} {
		t.Run(fault, func(t *testing.T) {
			m, entry, key := syntheticStatisticsMutation(t)
			r, _ := m.fs.get(buildKey(key, 10, 0))
			value := bytes.Clone(r.value)
			var err error
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
	m, _, key := syntheticStatisticsMutation(t)
	r, _ := m.fs.get(buildKey(key, 10, 0))
	value := bytes.Clone(r.value)
	le.PutUint64(value[24:], math.MaxUint64)
	if err := m.fs.put(r.key, value); err != nil {
		t.Fatal(err)
	}
	if err := m.bumpStatistics(key, 1); !errors.Is(err, filesystem.ErrLimit) {
		t.Fatal("generation overflow admitted", err)
	}
	r, _ = m.fs.get(r.key)
	if le.Uint64(r.value[24:]) != math.MaxUint64 {
		t.Fatal("overflow changed the record")
	}
	if err := m.bumpStatistics(key, 0); err != nil {
		t.Fatal("zero delta at the limit refused", err)
	}
}
