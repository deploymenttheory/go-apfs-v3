package fixture

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Vars resolves the references a recipe argument may contain. Plain names
// ($STAGE, $MOUNT, $DEV) come from the values map; keyed names
// ($MOUNT:Primary, $VOLUME:Data, $SNAPSHOT:before) from the keyed map;
// $PASSWORD:ref from passwords; $HEX:name and $FILE:name from the payload
// directory.
type Vars struct {
	Values    map[string]string
	Keyed     map[string]map[string]string
	Passwords map[string]string
	Payloads  string
}

var reference = regexp.MustCompile(`\$([A-Z]+)(?::([^\s/"'$]+))?`)

// Expand substitutes every reference in arg. Unknown references are errors:
// a recipe must not silently pass a literal "$MOUNT" to a program.
func (v *Vars) Expand(arg string) (string, error) {
	var firstErr error
	out := reference.ReplaceAllStringFunc(arg, func(match string) string {
		if firstErr != nil {
			return match
		}
		parts := reference.FindStringSubmatch(match)
		name, key := parts[1], parts[2]
		value, err := v.resolve(name, key)
		if err != nil {
			firstErr = err
			return match
		}
		return value
	})
	if firstErr != nil {
		return "", firstErr
	}
	return out, nil
}

// ExpandAll expands a slice of arguments.
func (v *Vars) ExpandAll(args []string) ([]string, error) {
	out := make([]string, 0, len(args))
	for _, arg := range args {
		expanded, err := v.Expand(arg)
		if err != nil {
			return nil, err
		}
		out = append(out, expanded)
	}
	return out, nil
}

func (v *Vars) resolve(name, key string) (string, error) {
	switch name {
	case "PASSWORD":
		value, ok := v.Passwords[key]
		if !ok {
			return "", fmt.Errorf("unknown password reference %q", key)
		}
		return value, nil
	case "HEX":
		data, err := v.Payload(key)
		if err != nil {
			return "", err
		}
		return hex.EncodeToString(data), nil
	case "FILE":
		if key == "" {
			return "", fmt.Errorf("$FILE needs a payload name")
		}
		path := filepath.Join(v.Payloads, key)
		if _, err := os.Stat(path); err != nil {
			return "", fmt.Errorf("payload %q: %w", key, err)
		}
		return path, nil
	}
	if key != "" {
		values, ok := v.Keyed[name]
		if !ok {
			return "", fmt.Errorf("unknown keyed reference $%s:%s", name, key)
		}
		value, ok := values[key]
		if !ok {
			return "", fmt.Errorf("unknown %s %q", strings.ToLower(name), key)
		}
		return value, nil
	}
	value, ok := v.Values[name]
	if !ok {
		return "", fmt.Errorf("unknown reference $%s", name)
	}
	return value, nil
}

// Payload reads a payload file by name.
func (v *Vars) Payload(name string) ([]byte, error) {
	if name == "" || strings.ContainsAny(name, "/\\") {
		return nil, fmt.Errorf("invalid payload name %q", name)
	}
	data, err := os.ReadFile(filepath.Join(v.Payloads, name))
	if err != nil {
		return nil, fmt.Errorf("payload %q: %w", name, err)
	}
	return data, nil
}

// Set assigns a plain value.
func (v *Vars) Set(name, value string) {
	if v.Values == nil {
		v.Values = map[string]string{}
	}
	v.Values[name] = value
}

// SetKeyed assigns a keyed value.
func (v *Vars) SetKeyed(name, key, value string) {
	if v.Keyed == nil {
		v.Keyed = map[string]map[string]string{}
	}
	if v.Keyed[name] == nil {
		v.Keyed[name] = map[string]string{}
	}
	v.Keyed[name][key] = value
}
