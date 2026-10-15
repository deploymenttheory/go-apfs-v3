package apfs

import (
	"context"
	"errors"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

func TestReclamationWaitsForCheckpointRetirementAndFinalOwner(t *testing.T) {
	storage, _ := nativeStorage(t, "apfs-clone-final-owner")
	space := storage.reader.space
	space.protected, space.protectedPool = storage.protected, storage.pool
	// One eligible deferred range stands in for a final owner released in a
	// prior transaction. Its allocation must survive while a retained checkpoint
	// can still refer to it; a current owner must always forbid reclamation.
	var target buildRecord
	for _, r := range space.queues[1].all() {
		if le.Uint64(r.key) < uint64(space.owner.c.XID) && le.Uint64(r.key) >= uint64(space.checkpointFloor) {
			target = r
			break
		}
	}
	if target.key == nil {
		t.Fatal("native retained-checkpoint queue window missing")
	}
	address := le.Uint64(target.key[8:])
	if err := space.reclaim(); err != nil {
		t.Fatal(err)
	}
	if !space.used(address) {
		t.Fatal("retained checkpoint allocation freed early")
	}
	// Reclamation must not trust an old queue entry when a live/historical
	// storage root still protects its block, even after checkpoint retirement.
	setLittleBit(space.protected, address, true)
	space.owner.reusePrepared = true
	if err := space.reclaim(); !errors.Is(err, filesystem.ErrCorrupt) {
		t.Fatal("protected root was reclaimed", err)
	}
	if !space.used(address) {
		t.Fatal("protected root's allocation was lost")
	}
	setLittleBit(space.protected, address, false)
	before := space.free
	if err := space.reclaim(); err != nil {
		t.Fatal(err)
	}
	if space.used(address) || space.free <= before {
		t.Fatal("final retired reference leaked allocation")
	}
}

func TestIdleReaperListsDoNotTreatStaleFreeEntriesAsOwners(t *testing.T) {
	for _, fault := range []string{"idle", "active entry", "cycle", "bad tail", "bad empty index", "unmapped list"} {
		t.Run(fault, func(t *testing.T) {
			storage, _ := nativeStorage(t, "snapshot-apfs-retained")
			m := storage.reader
			reaper := m.ephemeral[le.Uint64(m.nx[168:])].data
			head := le.Uint64(reaper[48:])
			page := m.ephemeral[head].data
			if head == 0 {
				t.Fatal("native empty reaper list missing")
			}
			want := filesystem.ErrCorrupt
			switch fault {
			case "idle":
				want = nil
			case "active entry":
				le.PutUint32(page[48:], 1)
				want = filesystem.ErrUnsupported
			case "cycle":
				le.PutUint64(page[32:], head)
			case "bad tail":
				le.PutUint64(reaper[56:], head+1)
			case "bad empty index":
				le.PutUint32(page[52:], 0)
			case "unmapped list":
				delete(m.ephemeral, head)
			}
			_, err := m.emptyReaperLists(reaper, true)
			if !errors.Is(err, want) {
				t.Fatal("reaper list admission differs", fault, err)
			}
		})
	}
}

func TestStorageCancellationPrecedesDiskAccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := InspectStorage(ctx, &storageFaultSource{})
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled inspection accessed source", err)
	}
}
