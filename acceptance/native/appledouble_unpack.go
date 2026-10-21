package native

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

type unpackedAppleDouble struct {
	Data       AppleDoubleValue
	Attributes []schema.Xattr
	ACL        string
}

func (v *Verifier) observeUnpackedAppleDouble(filename string) (unpackedAppleDouble, error) {
	var result unpackedAppleDouble
	sum, size, err := v.Vol.Hash(filename)
	if err != nil {
		return result, err
	}
	result.Data = AppleDoubleValue{size, sum}
	names, err := v.Vol.Listxattr(filename, true)
	if err != nil {
		return result, err
	}
	slices.Sort(names)
	for _, name := range names {
		data, err := v.Vol.Getxattr(filename, name, true)
		if err != nil {
			return result, err
		}
		sum := sha256.Sum256(data)
		result.Attributes = append(result.Attributes, schema.Xattr{Name: name, Bytes: int64(len(data)), SHA256: hex.EncodeToString(sum[:])})
	}
	acl, err := v.Vol.ACL(filename)
	if err != nil {
		return result, err
	}
	result.ACL = hex.EncodeToString(acl)
	return result, nil
}

// verifyAppleDouble uses a native control on the same kernel and destination
// filesystem. Serialized ACL text and unpack omission policy stay Apple's own;
// every serialized value is checked separately before either native invocation.
func (v *Verifier) verifyAppleDouble(ctx context.Context, p Paired, k corpus.Case, view schema.View) ([]Difference, error) {
	if v.AppleDoubleUnpack == "" {
		return nil, fmt.Errorf("missing guarded AppleDouble unpack adapter")
	}
	control, err := appleDoubleControl(view, p.Output.Expect.AppleDouble.Path)
	if err != nil {
		return nil, err
	}
	original := filepath.Join(k.Dir, filepath.FromSlash(control.File))
	if sum, err := schema.FileDigest(original); err != nil || sum != control.SHA256 {
		return nil, fmt.Errorf("native AppleDouble control digest changed: %v", err)
	}
	want, err := ReadAppleDoubleFile(original)
	if err != nil {
		return nil, err
	}
	var hosts []string
	for host := range p.ByHost {
		hosts = append(hosts, host)
	}
	slices.Sort(hosts)
	for _, host := range hosts {
		o := p.ByHost[host]
		filename := filepath.Join(p.Dirs[host], o.File)
		if sum, err := schema.FileDigest(filename); err != nil || sum != o.SHA256 {
			return nil, fmt.Errorf("%s: AppleDouble output digest mismatch: %v", host, err)
		}
		got, err := ReadAppleDoubleFile(filename)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", host, err)
		}
		if diffs := CompareAppleDouble(got, want); len(diffs) != 0 {
			for i := range diffs {
				diffs[i].Path = host + ":" + control.Path
			}
			return diffs, nil
		}
	}
	work := filepath.Join(v.Work, "appledouble", sanitize(p.Name))
	if err := os.MkdirAll(work, 0755); err != nil {
		return nil, err
	}
	transcript := &fixture.Transcript{}
	unpack := func(label, source string) (unpackedAppleDouble, error) {
		destination := filepath.Join(work, label)
		if err := v.Vol.WriteFile(destination, []byte("AppleDouble metadata must preserve this data fork.\n"), true); err != nil {
			return unpackedAppleDouble{}, err
		}
		cmd := fixture.Command{Label: label, Argv: []string{v.AppleDoubleUnpack, source, destination}, Expected: "0"}
		runErr := transcript.Record(cmd, v.C.Run(ctx, cmd))
		commands, err := json.MarshalIndent(transcript.Commands, "", "  ")
		if err != nil {
			return unpackedAppleDouble{}, err
		}
		if err := os.WriteFile(filepath.Join(work, "commands.json"), commands, 0644); err != nil {
			return unpackedAppleDouble{}, err
		}
		if runErr != nil {
			return unpackedAppleDouble{}, runErr
		}
		return v.observeUnpackedAppleDouble(destination)
	}
	// Pair already requires byte-identical canonical output on all hosts.
	// Check every host's bytes above, then ask Apple to unpack one copy.
	reference, err := unpack("native-control", original)
	if err != nil {
		return nil, fmt.Errorf("native AppleDouble positive control: %w", err)
	}
	if err := checkAppleDoubleUnpackControl(reference, want); err != nil {
		return nil, err
	}
	actual, err := unpack("portable-output", filepath.Join(p.Dirs[p.Primary], p.ByHost[p.Primary].File))
	if err != nil {
		return nil, fmt.Errorf("portable AppleDouble native unpack: %w", err)
	}
	for _, source := range []struct{ filename, sum string }{
		{original, control.SHA256},
		{filepath.Join(p.Dirs[p.Primary], p.ByHost[p.Primary].File), p.ByHost[p.Primary].SHA256},
	} {
		if sum, err := schema.FileDigest(source.filename); err != nil || sum != source.sum {
			return nil, fmt.Errorf("AppleDouble unpack changed its input: %s (%v)", source.filename, err)
		}
	}
	report := struct {
		Commands         []schema.Command
		Native, Portable unpackedAppleDouble
	}{transcript.Commands, reference, actual}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(work, "unpack-verdict.json"), data, 0644); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(actual, reference) {
		return []Difference{{Path: control.Path, Field: "nativeUnpack", Got: fmt.Sprint(actual), Want: fmt.Sprint(reference)}}, nil
	}
	return nil, nil
}

func checkAppleDoubleUnpackControl(got unpackedAppleDouble, want AppleDoubleRecord) error {
	payload := []byte("AppleDouble metadata must preserve this data fork.\n")
	sum := sha256.Sum256(payload)
	if got.Data != (AppleDoubleValue{int64(len(payload)), hex.EncodeToString(sum[:])}) {
		return fmt.Errorf("AppleDouble unpack changed the data fork")
	}
	attrs := map[string]AppleDoubleValue{}
	for _, a := range got.Attributes {
		attrs[a.Name] = AppleDoubleValue{a.Bytes, a.SHA256}
	}
	values := map[string]AppleDoubleValue{"com.apple.ResourceFork": want.Resource}
	if want.FinderInfo != [32]byte{} {
		sum := sha256.Sum256(want.FinderInfo[:])
		values["com.apple.FinderInfo"] = AppleDoubleValue{32, hex.EncodeToString(sum[:])}
	}
	for _, a := range want.Attributes {
		if a.Name == "com.apple.acl.text" {
			if a.Bytes > 0 && got.ACL == "" {
				return fmt.Errorf("native AppleDouble control did not restore its ACL")
			}
			continue
		}
		values[a.Name] = a.AppleDoubleValue
	}
	for name, value := range values {
		// Apple's unpack policy may omit empty native attributes. Their
		// serialized presence/order/flags remain exact in the separate verdict.
		if value.Bytes > 0 && attrs[name] != value {
			return fmt.Errorf("native AppleDouble control did not restore %s", name)
		}
	}
	return nil
}
