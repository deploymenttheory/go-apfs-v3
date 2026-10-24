package copyfile

import (
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"slices"
)

// copiedOmissions changes provenance only for fields this copy supplies.
// Unsupported host conversions retain an existing destination's uncertainty;
// a new destination still records the untransferred source field.
func copiedOmissions(prior, incoming []filesystem.MetadataOmission, newObject, preserve, noAttributes, retainAttributes, retainACL bool) []filesystem.MetadataOmission {
	values := map[string]filesystem.MetadataOmission{}
	for _, v := range prior {
		values[v.Field] = v
	}
	source := map[string]filesystem.MetadataOmission{}
	for _, v := range incoming {
		source[v.Field] = v
	}
	replace := func(field string, retain bool) {
		if retain {
			if _, ok := values[field]; ok {
				return
			}
		}
		delete(values, field)
		if v, ok := source[field]; ok {
			values[field] = v
		}
	}
	if newObject || preserve {
		for _, field := range []string{"mode", "uid", "gid", "bsdFlags"} {
			replace(field, false)
		}
	}
	if preserve {
		replace("acl", retainACL)
	}
	if !noAttributes {
		replace("attributes", retainAttributes)
	}
	var result []filesystem.MetadataOmission
	for _, v := range values {
		result = append(result, v)
	}
	slices.SortFunc(result, func(a, b filesystem.MetadataOmission) int {
		if a.Field < b.Field {
			return -1
		}
		if a.Field > b.Field {
			return 1
		}
		return 0
	})
	return result
}
