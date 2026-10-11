package hfsplus

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/filecompression"
	"github.com/deploymenttheory/go-apfs-v3/session"
)

// Inspect stored catalog records independently of logical link resolution.
// Apple's cat_lookup marks resolved hard-link inodes as having link chains;
// subsequent native writes must not persist that flag onto an incomplete chain.
func TestBuiltHardLinksHaveCompleteNativeChains(t *testing.T) {
	for _, sensitive := range []bool{false, true} {
		for _, policy := range []string{"preserve", "zlib"} {
			name := policy
			if sensitive {
				name = "HFSX/" + name
			}
			t.Run(name, func(t *testing.T) {
				ctx := context.Background()
				clock := time.Date(2025, 6, 7, 8, 9, 10, 0, time.UTC)
				s, err := session.Create(ctx, filepath.Join(t.TempDir(), "session"), session.Options{
					Names: filesystem.NameRules{Format: "HFS+", CaseSensitive: sensitive, NormalizationInsensitive: true}, Time: &clock,
				})
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				host := filepath.Join(t.TempDir(), "input")
				if err = os.WriteFile(host, bytes.Repeat([]byte("hard-linked compression"), 100), 0600); err != nil {
					t.Fatal(err)
				}
				if _, err = s.Copy(ctx, []string{host}, "/file", session.CopyOptions{FromHost: true}); err != nil {
					t.Fatal(err)
				}
				for _, path := range []string{"/alias-a", "/alias-b"} {
					if _, err = s.Link(ctx, "/file", path, session.LinkOptions{}); err != nil {
						t.Fatal(err)
					}
				}
				var budget int64
				prepared, err := filecompression.Prepare(ctx, s, policy, t.TempDir(), &budget)
				if err != nil {
					t.Fatal(err)
				}
				defer prepared.Close()
				layout, err := Plan(ctx, prepared, BuildOptions{Name: "Test", Time: clock, CaseSensitive: sensitive})
				if err != nil {
					t.Fatal(err)
				}
				var image bytes.Buffer
				if err = layout.Write(ctx, &image); err != nil {
					t.Fatal(err)
				}
				volume, err := Open(bytes.NewReader(image.Bytes()))
				if err != nil {
					t.Fatal(err)
				}
				id, err := filesystem.Lookup(ctx, volume, "/file")
				if err != nil {
					t.Fatal(err)
				}
				for _, path := range []string{"/alias-a", "/alias-b"} {
					alias, err := filesystem.Lookup(ctx, volume, path)
					if err != nil || alias != id {
						t.Fatal("hard-link identity", alias, id, err)
					}
				}
				var inode []byte
				if err = volume.catalog.records(ctx, volume.privateID, func(r treeRecord) error {
					if len(r.value) == 248 && be.Uint32(r.value[8:]) == uint32(id) {
						inode = append([]byte(nil), r.value...)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if len(inode) != 248 || be.Uint16(inode[2:])&0x20 == 0 || be.Uint32(inode[44:]) != 3 {
					t.Fatal("inode lacks native link-chain flag or count")
				}
				links := map[uint32][]byte{}
				if err = volume.catalog.records(ctx, 2, func(r treeRecord) error {
					if len(r.value) == 248 && string(r.value[48:56]) == "hlnkhfs+" {
						links[be.Uint32(r.value[8:])] = append([]byte(nil), r.value...)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				seen := map[uint32]bool{}
				var previous uint32
				for link := be.Uint32(inode[4:]); link != 0; {
					r := links[link]
					if len(r) != 248 || seen[link] || be.Uint16(r[2:])&0x20 == 0 || be.Uint32(r[32:]) != previous || be.Uint32(r[44:]) != uint32(id) {
						t.Fatal("invalid native hard-link chain", link, previous)
					}
					seen[link] = true
					previous, link = link, be.Uint32(r[36:])
				}
				if len(seen) != 3 || len(links) != 3 {
					t.Fatal("native chain omits an alias", len(seen), len(links))
				}
			})
		}
	}
}
