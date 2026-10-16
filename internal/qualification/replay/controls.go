package replay

import (
	"fmt"
	"slices"
	"strings"
)

func RequiredControls(value string) (map[string]bool, error) {
	known := []string{"compression-boundaries", "copy-truncation", "copy-setid", "metadata-collapse-reuse"}
	result := map[string]bool{}
	if value == "" {
		return result, nil
	}
	for _, name := range strings.Split(value, ",") {
		if !slices.Contains(known, name) || result[name] {
			return nil, fmt.Errorf("unknown/duplicate required native control: %s", name)
		}
		result[name] = true
	}
	return result, nil
}
