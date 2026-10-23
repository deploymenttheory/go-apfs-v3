package fixture

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestRegistryOwnershipProjectsTheOpaqueDataArchiveRejectedByNativeJSONConversion(t *testing.T) {
	const dir = "testdata/registry-opaque-properties/"
	receipt, err := os.ReadFile(dir + "conversion-receipt.json")
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(receipt)) != "5a5c3d31f68d8892ef3df006142d78186cde28842d1f21610337354172d82dcb" {
		t.Fatalf("original file-only conversion receipt changed: %v", err)
	}
	var evidence struct {
		Results []struct {
			Case     string
			ExitCode int
			Files    map[string]struct {
				Bytes  int
				SHA256 string
			}
		}
	}
	if err := json.Unmarshal(receipt, &evidence); err != nil {
		t.Fatal(err)
	}
	for _, result := range evidence.Results {
		t.Run(result.Case, func(t *testing.T) {
			files := map[string][]byte{}
			for name, binding := range result.Files {
				raw, err := os.ReadFile(dir + name)
				if err != nil || len(raw) != binding.Bytes || fmt.Sprintf("%x", sha256.Sum256(raw)) != binding.SHA256 {
					t.Fatalf("original conversion bytes changed for %s: %v", name, err)
				}
				files[name] = raw
			}
			if result.Case == "opaque-data" && (result.ExitCode != 1 || string(files[result.Case+".stderr"]) != "<stdin>: Invalid object in plist for JSON format\n") {
				t.Fatal("the actual opaque-data conversion refusal changed")
			}
			c := &kernelOwnershipCommander{
				images: files[result.Case+".plist"],
				registryConversionFailure: &Result{
					Status: result.ExitCode,
					Stdout: files[result.Case+".stdout"],
					Stderr: files[result.Case+".stderr"],
				},
			}
			disk := imageTestDisk(c)
			roots, err := disk.registryInventory(context.Background(), "ioreg-image-ownership", imageRegistryArgs)
			if err != nil || len(roots) != 1 || len(roots[0]) != 1 || roots[0]["IOObjectClass"] != "AppleDiskImageDevice" {
				t.Fatalf("opaque native properties blocked the ownership projection: %v %v", roots, err)
			}
			if c.count("plutil") != 0 || len(disk.T.Commands) != 1 || disk.T.Commands[0].StdoutText != string(c.images) {
				t.Fatal("registry ownership depended on lossy conversion or lost original archive text")
			}
		})
	}
}

func TestKernelOwnershipSkipsOpaqueDataRealDateAndNestedProperties(t *testing.T) {
	for _, opaque := range []string{
		`<data>AAEC</data>`,
		`<real>1.5</real>`,
		`<date>2026-10-23T00:00:00Z</date>`,
		`<integer>0xffffffffffffffff</integer>`,
		`<dict><key>DiskImageURL</key><data>AAEC</data><key>IOObjectClass</key><integer>1</integer><key>IORegistryEntryChildren</key><string>opaque</string></dict>`,
	} {
		t.Run(opaque, func(t *testing.T) {
			image := detachImage(t, t.TempDir())
			owner := registryImage(imageFileURL(image), registryMedia("disk17"))
			owner = strings.TrimSuffix(owner, "</dict>") + "<key>unused-driver-property</key>" + opaque + "</dict>"
			c := &kernelOwnershipCommander{
				global: []byte(`<plist><dict><key>images</key><array/></dict></plist>`),
				images: registryArchive(owner),
			}
			disk := imageTestDisk(c)
			if err := disk.Detach(context.Background(), &Attachment{Image: image, Dev: "/dev/disk17"}); err != nil || c.count("detach") != 1 || c.count("plutil") != 1 {
				t.Fatalf("an opaque property changed exact ownership or caused registry conversion: %v", err)
			}
		})
	}
}

func TestRegistryOwnershipRejectsMalformedProjectedKeysAndArchiveStructure(t *testing.T) {
	for name, raw := range map[string][]byte{
		"typed class":          registryArchive(`<dict><key>IOObjectClass</key><integer>1</integer></dict>`),
		"typed BSD name":       registryArchive(`<dict><key>BSD Name</key><data>AAEC</data></dict>`),
		"typed URL":            registryArchive(`<dict><key>DiskImageURL</key><data>AAEC</data></dict>`),
		"nested string":        registryArchive(`<dict><key>DiskImageURL</key><string><string>file:///tmp/a</string></string></dict>`),
		"duplicate class":      registryArchive(`<dict><key>IOObjectClass</key><string>IOMedia</string><key>IOObjectClass</key><string>Unknown</string></dict>`),
		"duplicate URL":        registryArchive(`<dict><key>DiskImageURL</key><string>file:///tmp/a</string><key>DiskImageURL</key><string>file:///tmp/b</string></dict>`),
		"duplicate children":   registryArchive(`<dict><key>IORegistryEntryChildren</key><array/><key>IORegistryEntryChildren</key><array/></dict>`),
		"scalar children":      registryArchive(`<dict><key>IORegistryEntryChildren</key><string>opaque</string></dict>`),
		"non-dictionary child": registryArchive(`<dict><key>IORegistryEntryChildren</key><array><string>child</string></array></dict>`),
		"missing value":        registryArchive(`<dict><key>unused</key></dict>`),
		"opaque XML mismatch":  registryArchive(`<dict><key>unused</key><data>AAEC</string></dict>`),
		"non-array root":       []byte(`<plist><dict/></plist>`),
		"trailing root":        append(registryArchive(), []byte(`<plist><array/></plist>`)...),
		"unclosed plist":       []byte(`<plist><array/>`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeRegistryOwnership(raw); err == nil {
				t.Fatal("malformed projected ownership was admitted")
			}
		})
	}
}

func TestRegistryOwnershipBoundsOpaquePropertiesAsWellAsProjectedNodes(t *testing.T) {
	for _, test := range []struct {
		name, value, cause string
	}{
		{"depth", strings.Repeat("<array>", 70) + strings.Repeat("</array>", 70), "depth limit"},
		{"tokens", "<array>" + strings.Repeat("<string/>", 50001) + "</array>", "token limit"},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := registryArchive("<dict><key>unused</key>" + test.value + "</dict>")
			if _, err := decodeRegistryOwnership(raw); err == nil || !strings.Contains(err.Error(), test.cause) {
				t.Fatalf("opaque content escaped its independent %s bound: %v", test.name, err)
			}
		})
	}
}
