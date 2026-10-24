package schema

import "fmt"

// Profile identifies one filesystem variant a recipe is captured in. The ID
// is used in fixture file names and in test names; HdiutilFS is the exact
// value passed to `hdiutil create -fs`.
type Profile struct {
	ID            string
	Family        string // "apfs" or "hfs"
	HdiutilFS     string
	CaseSensitive bool
	Journaled     bool
}

// Profiles lists every supported profile in canonical order.
var Profiles = []Profile{
	{ID: "apfs", Family: "apfs", HdiutilFS: "APFS"},
	{ID: "apfsx", Family: "apfs", HdiutilFS: "Case-sensitive APFS", CaseSensitive: true},
	{ID: "hfsplus", Family: "hfs", HdiutilFS: "HFS+"},
	{ID: "hfsx", Family: "hfs", HdiutilFS: "Case-sensitive HFS+", CaseSensitive: true},
	{ID: "hfsplus-j", Family: "hfs", HdiutilFS: "Journaled HFS+", Journaled: true},
	{ID: "hfsx-j", Family: "hfs", HdiutilFS: "Case-sensitive Journaled HFS+", CaseSensitive: true, Journaled: true},
}

// LookupProfile returns the profile with the given ID.
func LookupProfile(id string) (Profile, error) {
	for _, p := range Profiles {
		if p.ID == id {
			return p, nil
		}
	}
	return Profile{}, fmt.Errorf("unknown profile %q", id)
}

// Producers lists the supported macOS major versions required by active
// acceptance, in canonical order. Archived captures remain historical evidence.
var Producers = []int{26, 27}

// IsSupportedProducer reports whether major participates in active acceptance.
func IsSupportedProducer(major int) bool {
	for _, supported := range Producers {
		if major == supported {
			return true
		}
	}
	return false
}
