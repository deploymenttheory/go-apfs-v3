package apfs

const (
	// Apple File System Reference, nx_ephemeral_info: four checkpoints must
	// fit the data area; up to four ephemeral structures belong to each volume.
	buildCheckpointCount               = uint64(4)
	buildFilesystemEphemeralStructures = uint64(4)
	buildFilesystemEphemeralHeadroom   = uint64(2)
	buildReaperListBlocks              = uint64(1)
	buildCheckpointMapEntries          = uint64(101)
)

func buildMaximumVolumes(blocks uint64) uint64 {
	return min(uint64(100), (blocks+131071)/131072)
}

func buildEphemeralMinimum(blocks uint64) uint64 {
	if blocks < 32768 {
		return uint64(buildMainQueueLimit(blocks))
	}
	return 8
}

func (g *buildGeometry) sizeCheckpoints() {
	// The static four-object payload is insufficient once either free queue
	// grows. Budget their declared maximum nodes, the complete space manager,
	// the reaper and its first list page, plus per-volume ephemeral structures.
	// The doubled per-volume allowance is conservative builder policy,
	// corroborated by retained Apple-created geometries, not an Apple sizing
	// formula or a bound on arbitrary future native workloads.
	volumeBlocks := buildFilesystemEphemeralHeadroom * buildFilesystemEphemeralStructures *
		buildMaximumVolumes(g.blocks) * buildEphemeralMinimum(g.blocks)
	blocks := g.spacemanBlocks + 1 + buildReaperListBlocks +
		uint64(buildIPQueueLimit(g.chunks)) + uint64(buildMainQueueLimit(g.blocks)) + volumeBlocks
	g.dataBlocks = buildCheckpointCount * blocks
	// A checkpoint map has 101 entries. Treat every budgeted block as a
	// possible separate object, including multi-block space-manager overhead,
	// and reserve one additional descriptor for the container superblock.
	g.descriptorBlocks = buildCheckpointCount * ((blocks+buildCheckpointMapEntries-1)/buildCheckpointMapEntries + 1)
	g.dataBase = 1 + g.descriptorBlocks
}
