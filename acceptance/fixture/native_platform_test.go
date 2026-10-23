package fixture

import (
	"context"
	"fmt"
	"path"
	"slices"
	"strings"
	"testing"
)

func TestNativePlatformOriginalsRetainCompleteIndependentScopesAndAdapterFailures(t *testing.T) {
	for _, capture := range retainedNativePlatformCaptures(t) {
		t.Run(fmt.Sprint(capture.Major), func(t *testing.T) {
			if len(capture.Phases) != 6 || len(capture.OriginalClaims) != 7 || capture.Original.ContractError == "" || path.Base(capture.First.Image) != path.Base(capture.Second.Image) {
				t.Fatal("original complete collection or distinct same-basename cases changed")
			}
			for _, claim := range capture.OriginalClaims {
				if claim.Owned || claim.Error != "kernel registry archive size outside bounds" {
					t.Fatal("original failed adapter boolean/error was rewritten", claim.Kind)
				}
			}
			for phase, scopes := range capture.Phases {
				if len(scopes) != 4 {
					t.Fatal("phase did not retain every independent scope", phase)
				}
				commander := capture.commander(t, phase)
				for _, scope := range scopes {
					result := commander.Run(context.Background(), Command{Argv: scope.Argv})
					if result.Err != nil || result.Status != 0 {
						t.Fatal("native collection command did not succeed", phase, scope.Argv)
					}
					if slices.Equal(scope.Argv, imageRegistryArgs) && len(result.Stdout) != 0 {
						t.Fatal("actual successful modern class miss changed")
					}
				}
				if result := commander.Run(context.Background(), Command{Argv: []string{"hdiutil", "detach", capture.First.Dev}}); result.Err == nil {
					t.Fatal("file-only scope replay admitted an unrecorded native action")
				}
			}
		})
	}
}

func TestNativePlatformReplayBindsOriginalPathsAliasesForeignImagesAndPostDetachFacts(t *testing.T) {
	for _, capture := range retainedNativePlatformCaptures(t) {
		t.Run(fmt.Sprint(capture.Major), func(t *testing.T) {
			if len(capture.Relations) != 10 {
				t.Fatal("declared native relation inventory changed")
			}
			for _, relation := range capture.Relations {
				commander := capture.commander(t, relation.Phase)
				result := commander.Run(context.Background(), Command{Argv: legacyRegistryArgs})
				roots, err := decodeRegistryOwnership(result.Stdout)
				if err != nil {
					t.Fatal("original legacy archive cannot be projected", err)
				}
				images := map[string]string{"first": capture.First.Image, "second": capture.Second.Image, "alias": capture.Alias}
				devices := map[string]string{"first": capture.First.Dev, "second": capture.Second.Dev}
				image, imageOK := images[relation.Image]
				device, deviceOK := devices[relation.Device]
				if !imageOK || !deviceOK {
					t.Fatal("invalid declared replay identity")
				}
				var owners []map[string]any
				for _, root := range roots {
					if err := walkRegistry(root, nil, strings.TrimPrefix(device, "/dev/"), true, 0, &owners); err != nil {
						t.Fatal(err)
					}
				}
				if relation.Relation == "post-detach" {
					if len(owners) != 0 {
						t.Fatal("detached private target remains in original legacy scope")
					}
					media := commander.Run(context.Background(), Command{Argv: mediaRegistryArgs})
					nodes, err := decodeRegistryOwnership(media.Stdout)
					if err != nil || len(nodes) == 0 {
						t.Fatal("post-detach complete root-media archive unavailable", err)
					}
					for _, node := range nodes {
						if node["BSD Name"] == strings.TrimPrefix(device, "/dev/") {
							t.Fatal("detached private target remains in original full-media scope")
						}
					}
					continue // These are observed membership facts, not a lifecycle-policy verdict.
				}
				if len(owners) != 1 {
					t.Fatal("original legacy target lacks one exact owner", relation)
				}
				native, err := registryOwnerPath(owners[0], true)
				if err != nil {
					t.Fatal(err)
				}
				disk := &HostDisk{imagePathResolver: capture.resolveImage}
				same, err := disk.imagePathsMatch(native, image)
				if err != nil || same != (relation.Relation == "owned") {
					t.Fatal("original full-path relation changed", relation, err)
				}
			}
		})
	}
}
