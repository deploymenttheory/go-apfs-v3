package apfs

import "testing"

func TestBuildCheckpointGeometryCoversDeclaredEphemeralGrowth(t *testing.T) {
	for _, tc := range []struct {
		capacityMiB       uint64
		data, descriptors uint64
	}{
		{8, 52, 8},
		{64, 160, 8},
		{128, 304, 8},
		{1024, 992, 16},
		{1536, 1480, 20},
		{1600, 1764, 24},
	} {
		g := buildGeometryFor(tc.capacityMiB * 256)
		if g.dataBlocks != tc.data || g.descriptorBlocks != tc.descriptors {
			t.Fatalf("%d MiB: data %d, descriptors %d; require %d/%d", tc.capacityMiB, g.dataBlocks, g.descriptorBlocks, tc.data, tc.descriptors)
		}
		if g.dataBase != 1+g.descriptorBlocks || g.containerMap != g.dataBase+g.dataBlocks {
			t.Fatal("checkpoint areas overlap following container metadata", g)
		}
	}
	// Queue declarations and the space manager grow independently of volume
	// count. The second geometry exercises a multi-block space manager beyond
	// the current public capacity limit, without allocating a multi-TiB image.
	for _, blocks := range []uint64{1 << 28, 1 << 31} {
		g := buildGeometryFor(blocks)
		if blocks == 1<<31 && g.spacemanBlocks <= 1 {
			t.Fatal("geometry does not exercise a multi-block space manager")
		}
		if buildIPQueueLimit(g.chunks) <= 1 {
			t.Fatal("geometry does not exercise internal-pool queue growth")
		}
		perCheckpoint := g.dataBlocks / 4
		queues := uint64(buildIPQueueLimit(g.chunks)) + uint64(buildMainQueueLimit(blocks))
		if perCheckpoint < g.spacemanBlocks+queues+2+4*buildMaximumVolumes(blocks)*buildEphemeralMinimum(blocks) {
			t.Fatal("checkpoint budget omits declared structures", g)
		}
		if g.descriptorBlocks/4 < (perCheckpoint+100)/101+1 {
			t.Fatal("descriptor ring cannot map a grown checkpoint", g)
		}
		if perCheckpoint*4096 > checkpointByteLimit || g.dataBlocks > 65536 || g.descriptorBlocks*4096 > checkpointByteLimit {
			t.Fatal("builder geometry exceeds reader limits", g)
		}
	}
}
