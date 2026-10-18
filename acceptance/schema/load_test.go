package schema

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRecipesRequiresMatchingNamesAndPayloads(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "payloads"), 0o755); err != nil {
		t.Fatal(err)
	}
	good := `{"schema":1,"name":"file-corpus","purpose":"p","profiles":["apfs"],"requires":{"sudo":false},"image":{"create":"hdiutil","size":"64m","layout":"GPTSPUD","output":"UDZO"},"stages":[{"name":"final","steps":[{"tool":{"program":"xattr","args":["-wx","com.apple.decmpfs","$HEX:zlib-attr","$MOUNT/f"],"expect":"0"}}],"observe":{}}]}`
	if err := os.WriteFile(filepath.Join(dir, "file-corpus.json"), []byte(good), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRecipes(dir); err == nil {
		t.Fatal("missing payload accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "payloads", "zlib-attr"), []byte{0}, 0o644); err != nil {
		t.Fatal(err)
	}
	recipes, err := LoadRecipes(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(recipes) != 1 || recipes[0].Name != "file-corpus" {
		t.Fatalf("unexpected recipes %+v", recipes)
	}
	if err := os.Rename(filepath.Join(dir, "file-corpus.json"), filepath.Join(dir, "corpus.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRecipes(dir); err == nil {
		t.Fatal("file name differing from recipe name accepted")
	}
}
