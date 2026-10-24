// Package native verifies Go-produced images with Apple tools on macOS 26
// and 27: cross-host equality, hdiutil verify, fsck, diskutil
// verification, codesign, mounted readback against the fixture
// observation, native continuation writes followed by a further product
// edit through the product's command-line binary, and cross-version
// parity of the fixtures themselves. Preservation exports receive independent
// manifest, graph, metadata and blob verification against the Apple observations
// on every host's copy, without using the product's workspace reader.
// AppleDouble receives independent serialized-value checks and Apple's public
// COPYFILE_UNPACK verdict against a retained native control on the same kernel.
//
// The package never imports the product: the product is exercised only as
// a built binary named by APFS_PRODUCT_CLI. Everything that is not a system
// call or an Apple program is portable and tested on every host; the test
// entry point itself carries the native build tag.
package native
