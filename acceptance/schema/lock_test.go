package schema

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeLock(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixtures.lock.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

const digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestReadLockAcceptsRecipesOnlyAndCompleteBundles(t *testing.T) {
	lock, err := ReadLock(writeLock(t, `{"schema":1,"release":"","recipesSHA256":"`+digest+`","bundles":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(lock.Bundles) != 0 {
		t.Fatal("expected no bundles")
	}
	lock, err = ReadLock(writeLock(t, `{"schema":1,"release":"fixtures/2026.10.18","recipesSHA256":"`+digest+`","bundles":{"macos-27":{"asset":"a.tar.gz","sha256":"`+digest+`","bytes":10,"build":"26A434","captureRun":"https://example"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if lock.Bundles["macos-27"].Bytes != 10 {
		t.Fatal("bundle not decoded")
	}
}

func TestReadLockRejectsWeakenedFiles(t *testing.T) {
	cases := map[string]string{
		"unknown field":           `{"schema":1,"release":"","recipesSHA256":"` + digest + `","bundles":{},"skip":true}`,
		"wrong schema":            `{"schema":2,"release":"","recipesSHA256":"` + digest + `","bundles":{}}`,
		"bad recipes digest":      `{"schema":1,"release":"","recipesSHA256":"abc","bundles":{}}`,
		"bundle without digest":   `{"schema":1,"release":"r","recipesSHA256":"` + digest + `","bundles":{"macos-27":{"asset":"a","sha256":"","bytes":1,"build":"b","captureRun":"c"}}}`,
		"bundle without bytes":    `{"schema":1,"release":"r","recipesSHA256":"` + digest + `","bundles":{"macos-27":{"asset":"a","sha256":"` + digest + `","bytes":0,"build":"b","captureRun":"c"}}}`,
		"bundles without release": `{"schema":1,"release":"","recipesSHA256":"` + digest + `","bundles":{"macos-27":{"asset":"a","sha256":"` + digest + `","bytes":1,"build":"b","captureRun":"c"}}}`,
		"trailing data":           `{"schema":1,"release":"","recipesSHA256":"` + digest + `","bundles":{}} {}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ReadLock(writeLock(t, body)); err == nil {
				t.Fatalf("%s was accepted", name)
			} else if !strings.Contains(err.Error(), "fixtures.lock.json") {
				t.Fatalf("error does not name the file: %v", err)
			}
		})
	}
}
