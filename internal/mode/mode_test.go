package mode

import (
	"encoding/json"
	"os"
	"testing"
)

// The vectors were produced by Apple's own setmode(3)/getmode(3); see the
// source object in the fixture. The grammar must agree on validity and result.
func TestModeGrammarMatchesNativeSetmodeVectors(t *testing.T) {
	b, err := os.ReadFile("testdata/setmode_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Source struct {
			System, Version string
		}
		Vectors []struct {
			Expression   string
			Input, Umask uint32
			Valid        bool
			Output       uint32
		}
	}
	if err := json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Source.System != "macOS" || fixture.Source.Version == "" || len(fixture.Vectors) != 390 {
		t.Fatal("incomplete native mode vectors", fixture.Source, len(fixture.Vectors))
	}
	invalid := 0
	for _, v := range fixture.Vectors {
		program, err := Parse(v.Expression, v.Umask)
		if (err == nil) != v.Valid {
			t.Fatalf("mode %q validity: %v (native %t)", v.Expression, err, v.Valid)
		}
		if err != nil {
			invalid++
			continue
		}
		if got := program.Apply(v.Input); got != v.Output {
			t.Fatalf("mode %q on %#o mask %#o: got %#o want %#o", v.Expression, v.Input, v.Umask, got, v.Output)
		}
	}
	if invalid == 0 {
		t.Fatal("vectors include no rejected expressions")
	}
}

func TestModeParseBounds(t *testing.T) {
	for _, tc := range []struct {
		expression string
		mask       uint32
	}{{"", 0}, {"755", 01000}, {"u+r,", 0}, {"z+x", 0}, {"7777777", 0}} {
		if _, err := Parse(tc.expression, tc.mask); err == nil {
			t.Fatal("accepted", tc.expression, tc.mask)
		}
	}
}
