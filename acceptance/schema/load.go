package schema

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// LoadRecipes decodes and validates every recipe in dir. The file name must
// equal the recipe name, every payload a recipe references must exist under
// dir/payloads, and names must be unique. Recipes are returned sorted by
// name so consumers iterate deterministically.
func LoadRecipes(dir string) ([]Recipe, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var recipes []Recipe
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var recipe Recipe
		if err := DecodeStrict(data, &recipe); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if err := recipe.Validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if want := recipe.Name + ".json"; entry.Name() != want {
			return nil, fmt.Errorf("%s: recipe %q must live in %s", path, recipe.Name, want)
		}
		for _, payload := range recipe.payloads() {
			if _, err := os.Stat(filepath.Join(dir, "payloads", payload)); err != nil {
				return nil, fmt.Errorf("%s: payload %q: %w", path, payload, err)
			}
		}
		recipes = append(recipes, recipe)
	}
	if len(recipes) == 0 {
		return nil, fmt.Errorf("%s: no recipes", dir)
	}
	sort.Slice(recipes, func(i, j int) bool { return recipes[i].Name < recipes[j].Name })
	return recipes, nil
}

// payloads lists every payload file a recipe references.
func (r *Recipe) payloads() []string {
	seen := map[string]bool{}
	var out []string
	add := func(name string) {
		if name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	scanTool := func(t *ToolStep) {
		add(t.StdinBytes)
		for _, arg := range t.Args {
			for _, ref := range payloadRefs(arg) {
				add(ref)
			}
		}
	}
	for _, stage := range r.Stages {
		for _, step := range stage.Steps {
			switch {
			case step.Host != nil:
				add(step.Host.Payload)
			case step.Tool != nil:
				scanTool(step.Tool)
			case step.FS != nil:
				add(step.FS.Payload)
			}
		}
	}
	for _, d := range r.Derive {
		for i := range d.Steps {
			scanTool(&d.Steps[i])
		}
	}
	sort.Strings(out)
	return out
}

// payloadRefs extracts $HEX:<name> and $FILE:<name> references from an
// argument.
func payloadRefs(arg string) []string {
	var refs []string
	for _, prefix := range []string{"$HEX:", "$FILE:"} {
		rest := arg
		for {
			i := strings.Index(rest, prefix)
			if i < 0 {
				break
			}
			rest = rest[i+len(prefix):]
			end := strings.IndexAny(rest, " /\"")
			if end < 0 {
				end = len(rest)
			}
			refs = append(refs, rest[:end])
			rest = rest[end:]
		}
	}
	return refs
}
