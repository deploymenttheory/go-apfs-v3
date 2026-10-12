package filesystem

import "github.com/deploymenttheory/go-apfs-v3/block"

// Change describes an ordinary operation on an unpublished filesystem copy.
// Paths never follow symlinks. Data is borrowed for the call; Mode uses Apple's
// setmode grammar. Individual filesystem engines admit their supported verbs.
type Change struct {
	Name                                 string
	Operation                            string
	Destination                          string
	Parents, Recursive, Force, NoClobber bool
	Path                                 string
	Data                                 block.Source
	ResourceFork                         bool
	Mode                                 string
	// Metadata is a partial ownership/time patch. Flags uses the ordinary
	// chflags expression; attributes borrow a complete value just like a fork.
	Metadata                            *Metadata
	Flags, Attribute, AttributeMode     string
	DeleteAttribute, NoCreate, NoFollow bool
	Reference                           string
	Access, Modify                      bool
}
