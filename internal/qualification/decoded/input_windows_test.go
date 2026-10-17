package decoded

import "testing"

func TestDecodedWindowsResolvedPathsAllowSeparateDrivesAndRejectOverlap(t *testing.T) {
	for _, control := range []struct {
		name, source, scratch string
		overlap               bool
	}{
		{"checkout-and-test-scratch", `D:\a\repo\acceptance\testdata`, `C:\Users\runneradmin\AppData\Local\Temp\test`, false},
		{"checkout-and-job-cache", `D:\a\repo\acceptance\testdata`, `D:\a\_temp\apfs-decoded-inputs`, false},
		{"same-directory", `D:\a\repo\testdata`, `D:\a\repo\testdata`, true},
		{"scratch-inside-source", `D:\a\repo\testdata`, `D:\a\repo\testdata\scratch`, true},
		{"source-inside-scratch", `D:\a\repo\testdata`, `D:\a\repo`, true},
		{"drive-letter-case", `D:\a\repo\testdata`, `d:\a\repo\testdata\scratch`, true},
		{"similar-sibling-name", `D:\a\repo\testdata`, `D:\a\repo\testdata-other`, false},
		{"unresolved-relative-source", `testdata`, `C:\scratch`, true},
		{"drive-relative-source", `D:testdata`, `C:\scratch`, true},
	} {
		t.Run(control.name, func(t *testing.T) {
			err := separate(control.source, control.scratch)
			if (err != nil) != control.overlap {
				t.Fatalf("source/scratch separation: %v; want rejection %v", err, control.overlap)
			}
		})
	}
}
