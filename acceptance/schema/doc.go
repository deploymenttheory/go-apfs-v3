// Package schema holds the JSON contracts shared by the fixture capture tool,
// the portable conformance tests and the native verifier: recipes, captured
// observations, bundle manifests and the lock file that pins the corpus.
//
// This package must not import any product package. The capture tool and
// the native verifier depend on it and must stay independent of the code
// under test; acceptance/boundary_test.go enforces that.
package schema
