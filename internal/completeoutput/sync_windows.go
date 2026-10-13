package completeoutput

// Windows File.Sync uses FlushFileBuffers for the completed file. Windows does
// not provide an unprivileged directory flush through this API. Successful
// publication therefore promises atomic visibility and flushed file contents,
// without a separate power-loss guarantee for the new directory entry.
func syncDirectory(string) error { return nil }
