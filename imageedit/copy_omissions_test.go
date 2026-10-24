package imageedit

import (
	"context"
	"errors"
	"io/fs"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/edit"
)

func TestCopyOmissionReportReadsOnlyAffectedObjectsAndDeduplicatesAliases(t *testing.T) {
	ctx := context.Background()
	omission := filesystem.MetadataOmission{Field: "acl", SourceFormat: "linux-posix-acl", Status: filesystem.MetadataUnsupported, Reason: "captured foreign ACL cannot be converted"}
	source := &copyOmissionSource{omissions: []filesystem.MetadataOmission{omission}}
	tree, err := edit.NewLazy(ctx, source, edit.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := copyMetadataOmissions(ctx, tree, map[string]bool{"/z-alias": true, "/a-alias": true})
	if err != nil {
		t.Fatal(err)
	}
	if source.largeListings != 0 || source.largeStats != 0 {
		t.Fatal("COPY outcome reporting visited unrelated peers", source.largeListings, source.largeStats)
	}
	if len(got) != 1 || got[0].Object != 4 || got[0].Path != "/a-alias" || got[0].MetadataOmission != omission || got[0].Command != 0 || got[0].ClockNS != 0 {
		t.Fatal("wrong scoped alias/provenance report", got)
	}
	// A known supported replacement has no stale omission, irrespective of an
	// unrelated earlier import or the directory metadata that COPY updated.
	source.omissions = nil
	fresh, err := edit.NewLazy(ctx, source, edit.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	got, err = copyMetadataOmissions(ctx, fresh, map[string]bool{"/z-alias": true})
	if err != nil || len(got) != 0 {
		t.Fatal("report restored unrelated or resolved provenance", got, err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := copyMetadataOmissions(cancelled, fresh, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("empty cancelled report ignored cancellation", err)
	}
	if _, err := copyMetadataOmissions(cancelled, fresh, map[string]bool{"/a-alias": true}); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled report ignored cancellation", err)
	}
}

func TestCopyOmissionReportDoesNotIgnoreAffectedObjectErrors(t *testing.T) {
	source := &copyOmissionSource{omissions: []filesystem.MetadataOmission{{Field: "acl", SourceFormat: "unknown", Status: filesystem.MetadataUnsupported, Reason: "invalid"}}}
	if _, err := copyMetadataOmissions(context.Background(), source, map[string]bool{"/a-alias": true}); !errors.Is(err, filesystem.ErrCorrupt) {
		t.Fatal("malformed affected provenance accepted", err)
	}
	if _, err := copyMetadataOmissions(context.Background(), source, map[string]bool{"/absent": true}); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("missing affected destination silently dropped", err)
	}
}

type copyOmissionSource struct {
	filesystem.Reader
	omissions                 []filesystem.MetadataOmission
	largeListings, largeStats int
}

func (*copyOmissionSource) Root() uint64 { return 2 }
func (*copyOmissionSource) NameRules() filesystem.NameRules {
	return filesystem.NameRules{Format: "HFS+", NormalizationInsensitive: true}
}
func (r *copyOmissionSource) Stat(_ context.Context, id uint64) (filesystem.Node, error) {
	if id == 3 || id >= 100 {
		r.largeStats++
	}
	mode := uint32(0100644)
	if id == 2 || id == 3 {
		mode = 0040755
	}
	n := filesystem.Node{Identity: filesystem.Identity{Object: id}, Metadata: filesystem.Metadata{Mode: filesystem.Observed(mode)}, Links: filesystem.Observed(uint32(2)), Compression: filesystem.Observation[filesystem.Compression]{State: filesystem.Absent}}
	if id == 4 {
		n.MetadataOmissions = r.omissions
	}
	if id == 2 {
		n.MetadataOmissions = []filesystem.MetadataOmission{{Field: "attributes", SourceFormat: "linux-xattrs", Status: filesystem.MetadataUnavailable, Reason: "unrelated earlier observation"}}
	}
	return n, nil
}
func (r *copyOmissionSource) ReadDir(_ context.Context, id uint64, yield func(filesystem.DirEntry) error) error {
	if id == 3 {
		r.largeListings++
		return filesystem.ErrLimit
	} // 120,000 unrelated peers are intentionally unavailable to this report.
	if id != 2 {
		return fs.ErrInvalid
	}
	for _, e := range []filesystem.DirEntry{{Name: "Unrelated", Object: 3}, {Name: "z-alias", Object: 4}, {Name: "a-alias", Object: 4}} {
		if err := yield(e); err != nil {
			return err
		}
	}
	return nil
}
func (*copyOmissionSource) Lookup(_ context.Context, id uint64, name string) (filesystem.DirEntry, error) {
	if id != 2 {
		return filesystem.DirEntry{}, fs.ErrInvalid
	}
	switch name {
	case "Unrelated":
		return filesystem.DirEntry{Name: name, Object: 3}, nil
	case "a-alias", "z-alias":
		return filesystem.DirEntry{Name: name, Object: 4}, nil
	}
	return filesystem.DirEntry{}, fs.ErrNotExist
}
