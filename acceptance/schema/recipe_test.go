package schema

import (
	"strings"
	"testing"
)

func minimalRecipe() Recipe {
	return Recipe{
		Schema:   RecipeSchema,
		Name:     "file-corpus",
		Purpose:  "read parity",
		Profiles: []string{"apfs", "hfsx-j"},
		Image:    ImageSpec{Create: "hdiutil", Size: "64m", Layout: "GPTSPUD", Output: "UDZO"},
		Stages: []Stage{{
			Name: "final",
			Steps: []Step{
				{Host: &HostStep{Path: "tree/a", Pattern: "text", Content: "x"}},
				{Tool: &ToolStep{Program: "ditto", Args: []string{"$STAGE/tree", "$MOUNT/Fixture"}, Expect: "0"}},
			},
		}},
	}
}

func TestRecipeValidateAcceptsMinimalRecipe(t *testing.T) {
	r := minimalRecipe()
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRecipeValidateRejectsStructuralMistakes(t *testing.T) {
	cases := map[string]func(*Recipe){
		"ordering number in name": func(r *Recipe) { r.Name = "01-file-corpus" },
		"unknown profile":         func(r *Recipe) { r.Profiles = []string{"ntfs"} },
		"duplicate profile":       func(r *Recipe) { r.Profiles = []string{"apfs", "apfs"} },
		"unknown layout":          func(r *Recipe) { r.Image.Layout = "MBR" },
		"unknown output":          func(r *Recipe) { r.Image.Output = "ISO" },
		"missing purpose":         func(r *Recipe) { r.Purpose = "" },
		"no stages":               func(r *Recipe) { r.Stages = nil },
		"two step kinds":          func(r *Recipe) { r.Stages[0].Steps[0].Tool = &ToolStep{Program: "cp", Expect: "0"} },
		"no step kind":            func(r *Recipe) { r.Stages[0].Steps[0] = Step{} },
		"non-apple program":       func(r *Recipe) { r.Stages[0].Steps[1].Tool.Program = "python3" },
		"product binary":          func(r *Recipe) { r.Stages[0].Steps[1].Tool.Program = "apfs" },
		"bad expect":              func(r *Recipe) { r.Stages[0].Steps[1].Tool.Expect = "ok" },
		"unknown password":        func(r *Recipe) { r.Stages[0].Steps[1].Tool.Stdin = []string{"pw"} },
		"escaping host path":      func(r *Recipe) { r.Stages[0].Steps[0].Host.Path = "../etc" },
		"unknown fs op":           func(r *Recipe) { r.Stages[0].Steps[0] = Step{FS: &FSStep{Op: "mmap", Path: "x"}} },
		"fs op without path":      func(r *Recipe) { r.Stages[0].Steps[0] = Step{FS: &FSStep{Op: "write"}} },
		"raw-newfs without args":  func(r *Recipe) { r.Image.Create = "raw-newfs" },
		"unknown create":          func(r *Recipe) { r.Image.Create = "dd" },
		"unknown control":         func(r *Recipe) { r.Stages[0].Steps[0] = Step{Control: &ControlStep{Action: "kill"}} },
		"bad lookup expectation":  func(r *Recipe) { r.Stages[0].Observe.Lookups = []Lookup{{Dir: "d", Query: "q", Expect: "maybe"}} },
		"derivation from nowhere": func(r *Recipe) { r.Derive = []Derivation{{Name: "aes", From: "before"}} },
		"derivation name clash":   func(r *Recipe) { r.Derive = []Derivation{{Name: "final", From: "final"}} },
		"derivation password":     func(r *Recipe) { r.Derive = []Derivation{{Name: "aes", From: "final", Password: "nope"}} },
		"step profile unknown":    func(r *Recipe) { r.Stages[0].Steps[0].Only = []string{"zfs"} },
		"stage from unknown":      func(r *Recipe) { r.Stages[0].From = "before" },
		"bad xattr option": func(r *Recipe) {
			r.Stages[0].Steps[0] = Step{FS: &FSStep{Op: "setxattr", Path: "x", Name: "n", Option: "upsert"}}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := minimalRecipe()
			mutate(&r)
			if err := r.Validate(); err == nil {
				t.Fatalf("%s was accepted", name)
			}
		})
	}
}

func TestStrictDecodingRejectsUnknownRecipeFields(t *testing.T) {
	var r Recipe
	err := DecodeStrict([]byte(`{"schema":1,"name":"x","purpose":"p","profiles":["apfs"],"requires":{"sudo":false},"image":{"create":"hdiutil","size":"64m","layout":"GPTSPUD","output":"UDZO"},"stages":[],"skipOnFailure":true}`), &r)
	if err == nil || !strings.Contains(err.Error(), "skipOnFailure") {
		t.Fatalf("unknown field accepted: %v", err)
	}
}
