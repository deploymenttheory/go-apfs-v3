package filesystem

import (
	"errors"
	"testing"
)

func TestHostMetadataOmissionsRejectAmbiguousOrUnboundedProvenance(t *testing.T) {
	good := MetadataOmission{Field: "acl", SourceFormat: "linux-posix-acl", Status: MetadataUnsupported, Reason: "captured ACL conversion unsupported"}
	if err := ValidateMetadataOmissions([]MetadataOmission{good}); err != nil {
		t.Fatal(err)
	}
	for name, modify := range map[string]func(*MetadataOmission){
		"unknown field":      func(v *MetadataOmission) { v.Field = "unknown" },
		"wrong field format": func(v *MetadataOmission) { v.SourceFormat = "windows-file-attributes" },
		"unknown status":     func(v *MetadataOmission) { v.Status = "absent" },
		"empty reason":       func(v *MetadataOmission) { v.Reason = "" },
		"control byte":       func(v *MetadataOmission) { v.Reason = "untrusted\nrecord" },
	} {
		t.Run(name, func(t *testing.T) {
			v := good
			modify(&v)
			if !errors.Is(ValidateMetadataOmissions([]MetadataOmission{v}), ErrCorrupt) {
				t.Fatal("invalid provenance admitted", v)
			}
		})
	}
	if !errors.Is(ValidateMetadataOmissions([]MetadataOmission{good, good}), ErrCorrupt) {
		t.Fatal("duplicate field admitted")
	}
}
