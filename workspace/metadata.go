package workspace

import (
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/edit"
)

type AttributeMode = edit.AttributeMode

const (
	AttributeUpsert  = edit.AttributeUpsert
	AttributeCreate  = edit.AttributeCreate
	AttributeReplace = edit.AttributeReplace
)

func copyNode(n filesystem.Node) filesystem.Node { return edit.CopyNode(n) }
