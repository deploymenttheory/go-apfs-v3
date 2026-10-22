package native

import (
	"fmt"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func historicalWorkspaceIdentity(source corpus.Case, view schema.View, expect schema.Expectation) (*workspaceSourceIdentity, error) {
	identity := &workspaceSourceIdentity{}
	for _, volume := range source.Observation.Volumes {
		if volume.Index == view.Volume && volume.APFS != nil {
			identity.Volume = strings.ToUpper(volume.APFS.VolumeUUID)
			for _, snapshot := range volume.APFS.Snapshots {
				if snapshot.Name == expect.Snapshot {
					if identity.View != 0 {
						return nil, fmt.Errorf("duplicate native snapshot identity")
					}
					identity.View = snapshot.XID
				}
			}
		}
	}
	for _, entry := range view.Entries {
		if entry.Path == expect.Subtree {
			identity.Object = entry.ID
		}
	}
	if identity.Volume == "" || identity.View == 0 || identity.Object == 0 {
		return nil, fmt.Errorf("historical workspace lacks an independent native source identity")
	}
	return identity, nil
}

// Require preservation-source coverage even if all portable hosts omit it.
func requirePreservationSourceOutputs(pairs []Paired, cases map[string]corpus.Case, major int) error {
	packed, snapshots := map[string]int{}, map[string]int{}
	for _, pair := range pairs {
		o := pair.Output
		if strings.HasSuffix(o.Name, ".build.session.UDZO.dmg") {
			if o.Operation != "build" || o.Format != "UDZO" || o.Encrypted || o.Expect.Subtree != "Fixture" || o.Expect.Continuation {
				return fmt.Errorf("invalid reopened-session build %q", o.Name)
			}
			packed[CaseKey(o.Source)]++
		}
		if o.Operation != "workspace-snapshot" && o.Expect.Snapshot == "" {
			continue
		}
		if o.Operation != "workspace-snapshot" || o.Expect.Snapshot == "" || o.Expect.Workspace == nil || o.Expect.Workspace.Policy != "preserve" || o.Expect.Subtree != "Fixture" || o.Expect.View != "" || o.Expect.Continuation || o.Encrypted || o.Format != "workspace" || o.Expect.Container != nil || o.Expect.AppleDouble != nil {
			return fmt.Errorf("invalid historical preservation output %q", o.Name)
		}
		snapshots[CaseKey(o.Source)+"/"+o.Expect.Snapshot]++
	}
	for _, profile := range []string{"apfs", "apfsx", "hfsplus", "hfsx"} {
		ref := schema.CaseRef{Producer: major, Recipe: "file-corpus", Profile: profile, Stage: "final"}
		if _, ok := cases[CaseKey(ref)]; !ok || packed[CaseKey(ref)] != 1 {
			return fmt.Errorf("missing unique reopened-source build %s", CaseKey(ref))
		}
	}
	for _, profile := range []string{"apfs", "apfsx"} {
		ref := schema.CaseRef{Producer: major, Recipe: "snapshot-history", Profile: profile, Stage: "live"}
		k, ok := cases[CaseKey(ref)]
		if !ok || k.Observation == nil {
			return fmt.Errorf("missing historical preservation control %s", CaseKey(ref))
		}
		count := 0
		for _, view := range k.Observation.Views {
			if view.Snapshot == "" {
				continue
			}
			count++
			key := CaseKey(ref) + "/" + view.Snapshot
			if snapshots[key] != 1 {
				return fmt.Errorf("historical preservation %s: got %d outputs, want one", key, snapshots[key])
			}
		}
		if count != 2 {
			return fmt.Errorf("historical preservation %s: got %d native controls, want two", CaseKey(ref), count)
		}
	}
	return nil
}
