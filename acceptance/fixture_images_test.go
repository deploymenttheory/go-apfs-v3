package acceptance_test

import (
	"context"
	"errors"
	"io"
	"reflect"
	"sync"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
)

type fixtureImageScope struct {
	mu      sync.Mutex
	images  map[string]*corpus.ImageLease
	readers map[io.Closer]*corpus.ImageLease
	cleanup map[*corpus.ImageLease]error
}

var fixtureScopes = struct {
	sync.Mutex
	byTest map[*testing.T]*fixtureImageScope
}{byTest: map[*testing.T]*fixtureImageScope{}}

// fixtureImage leases one source for this leaf test's synchronous operations.
// Reader defers finish before the leaf cleanup releases its raw backing. Parallel
// leaves share a corpus entry only while each still holds an explicit lease.
func fixtureImage(t *testing.T, k corpus.Case) string {
	t.Helper()
	fixtureScopes.Lock()
	scope := fixtureScopes.byTest[t]
	if scope == nil {
		scope = &fixtureImageScope{images: map[string]*corpus.ImageLease{}}
		fixtureScopes.byTest[t] = scope
		t.Cleanup(func() {
			if err := scope.release(); err != nil {
				t.Error(err)
			}
			fixtureScopes.Lock()
			delete(fixtureScopes.byTest, t)
			fixtureScopes.Unlock()
		})
	}
	fixtureScopes.Unlock()
	scope.mu.Lock()
	defer scope.mu.Unlock()
	key := k.Dir + "\x00" + k.Observation.Image.File
	if lease := scope.images[key]; lease != nil {
		return lease.Path()
	}
	_, c := loadCorpus(t)
	lease, err := c.AcquireImage(context.Background(), k)
	if err != nil {
		t.Fatalf("fixture image: %v", err)
	}
	scope.images[key] = lease
	return lease.Path()
}

// closeFixture reports close errors separately from assertions/operation errors.
// An uncertain reader release pins this leaf's backing files, even on platforms
// where unlinking a still-open file would otherwise appear to succeed.
func closeFixture(t *testing.T, closer io.Closer) {
	t.Helper()
	if err := closer.Close(); err != nil {
		fixtureScopes.Lock()
		scope := fixtureScopes.byTest[t]
		fixtureScopes.Unlock()
		if scope != nil {
			scope.recordCleanup(closer, err)
		}
		t.Errorf("close fixture reader: %v", err)
	}
}

func (s *fixtureImageScope) recordCleanup(closer io.Closer, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if closer == nil || !reflect.TypeOf(closer).Comparable() {
		return
	}
	lease := s.readers[closer]
	if lease == nil {
		return
	} // OUTPUT/scratch cleanup cannot pin healthy inputs.
	if s.cleanup == nil {
		s.cleanup = map[*corpus.ImageLease]error{}
	}
	s.cleanup[lease] = errors.Join(s.cleanup[lease], err)
}

func (s *fixtureImageScope) release() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	for _, lease := range s.images {
		err = errors.Join(err, lease.Release(s.cleanup[lease]))
	}
	return err
}

func trackFixturePath(t *testing.T, closer io.Closer, path string) {
	t.Helper()
	if closer == nil || !reflect.TypeOf(closer).Comparable() {
		return
	}
	fixtureScopes.Lock()
	scope := fixtureScopes.byTest[t]
	fixtureScopes.Unlock()
	if scope == nil {
		return
	}
	scope.mu.Lock()
	defer scope.mu.Unlock()
	for _, lease := range scope.images {
		if lease.Path() == path {
			if scope.readers == nil {
				scope.readers = map[io.Closer]*corpus.ImageLease{}
			}
			scope.readers[closer] = lease
			return
		}
	}
}

func trackFixtureBorrower(t *testing.T, borrower, parent io.Closer) {
	t.Helper()
	if borrower == nil || parent == nil || !reflect.TypeOf(borrower).Comparable() || !reflect.TypeOf(parent).Comparable() {
		return
	}
	fixtureScopes.Lock()
	scope := fixtureScopes.byTest[t]
	fixtureScopes.Unlock()
	if scope == nil {
		return
	}
	scope.mu.Lock()
	defer scope.mu.Unlock()
	if lease := scope.readers[parent]; lease != nil {
		scope.readers[borrower] = lease
	}
}
