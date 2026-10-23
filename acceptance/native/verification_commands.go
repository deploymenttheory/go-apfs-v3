package native

// recordVerificationCommands also covers sector-preserving container checks
// and encrypted device hashes, which can fail before an observer is installed.
func (v *Verifier) recordVerificationCommands(work string) func(*error) {
	return v.recordNativeCommands(work, "verification-commands.json", "retain complete verification commands", true)
}
