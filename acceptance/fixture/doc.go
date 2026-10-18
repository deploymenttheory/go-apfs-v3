// Package fixture executes recipes with Apple tools and system calls and
// records what macOS reports. It never imports the product packages; the
// boundary test in the acceptance package enforces that.
//
// The package is layered so that almost all of it is portable and testable
// with fakes:
//
//   - Vars expands the $NAME and $NAME:key references recipes use.
//   - Commander runs programs with deadlines and records a transcript.
//   - Disk drives hdiutil and diskutil through a Commander and plutil.
//   - Volume is the POSIX surface recipes touch on a mounted volume; its
//     darwin implementation (build tag fixture) is the only platform code.
//   - Interpreter walks a recipe's stages and steps over those interfaces.
//   - Observer records the kernel's view through Volume and Disk.
package fixture
