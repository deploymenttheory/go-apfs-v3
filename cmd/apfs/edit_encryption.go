package main

import (
	"flag"
	"fmt"
	"io"
	"io/fs"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

func addEditEncryptionFlags(f *flag.FlagSet) {
	f.String("image-password-file", "", "source DMG password bytes in FILE; - reads stdin to EOF")
	f.String("password-file", "", "selected APFS volume password bytes; - reads stdin to EOF")
	var additional volumePasswordFiles
	f.Var(&additional, "volume-password-file", "additional APFS credential UUID=FILE; repeat for independently encrypted peers")
	f.String("output-password-file", "", "replacement DMG password bytes; retain source AES strength unless --encryption is set")
	f.String("encryption", "", "output DMG encryption: AES-128, AES-256 or none; default preserves source encryption")
}

type volumePasswordFiles []string

func (v *volumePasswordFiles) String() string { return strings.Join(*v, ",") }
func (v *volumePasswordFiles) Set(value string) error {
	id, path, ok := strings.Cut(value, "=")
	if !ok || id == "" || path == "" {
		return fs.ErrInvalid
	}
	*v = append(*v, value)
	return nil
}

func editEncryptionOptions(f *flag.FlagSet, input io.Reader, o imageedit.Options) (_ imageedit.Options, err error) {
	policy := f.Lookup("encryption").Value.String()
	output := f.Lookup("output-password-file").Value.String()
	switch policy {
	case "":
	case "none":
		if output != "" {
			return o, fmt.Errorf("--output-password-file conflicts with --encryption none")
		}
		o.Decrypt = true
	case "AES-128", "AES-256":
		if output == "" {
			return o, fmt.Errorf("encrypted output requires --output-password-file")
		}
	default:
		return o, fmt.Errorf("--encryption must be AES-128, AES-256 or none")
	}
	stdin := 0
	for _, name := range []string{"image-password-file", "password-file", "output-password-file", "new-password-file"} {
		if option := f.Lookup(name); option != nil && option.Value.String() == "-" {
			stdin++
		}
	}
	additional := f.Lookup("volume-password-file").Value.(*volumePasswordFiles)
	for _, item := range *additional {
		_, path, _ := strings.Cut(item, "=")
		if path == "-" {
			stdin++
		}
	}
	if stdin > 1 {
		return o, fmt.Errorf("only one image, volume or output password file may consume stdin")
	}
	defer func() {
		if err != nil {
			clearEditPasswords(o)
		}
	}()
	for _, credential := range []struct {
		name string
		into *[]byte
	}{{"image-password-file", &o.ImagePassword}, {"password-file", &o.VolumePassword}} {
		if path := f.Lookup(credential.name).Value.String(); path != "" {
			*credential.into, err = readPassword(path, input)
			if err != nil {
				return o, err
			}
		}
	}
	for _, item := range *additional {
		id, path, _ := strings.Cut(item, "=")
		password, err := readPassword(path, input)
		if err != nil {
			return o, err
		}
		o.VolumeCredentials = append(o.VolumeCredentials, apfs.VolumeCredential{VolumeUUID: id, Password: password})
	}
	if output != "" {
		password, e := readPassword(output, input)
		if e != nil {
			return o, e
		}
		bits := uint32(0)
		switch policy {
		case "AES-128":
			bits = 128
		case "AES-256":
			bits = 256
		}
		o.Encryption = &diskimage.EncryptionOptions{KeyBits: bits, Password: password}
	}
	return o, nil
}

func clearEditPasswords(o imageedit.Options) {
	clear(o.ImagePassword)
	clear(o.VolumePassword)
	for _, credential := range o.VolumeCredentials {
		clear(credential.Password)
	}
	if o.Encryption != nil {
		clear(o.Encryption.Password)
	}
}
