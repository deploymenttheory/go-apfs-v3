package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

func addEditEncryptionFlags(f *flag.FlagSet) {
	f.String("image-password-file", "", "source DMG password bytes in FILE; - reads stdin to EOF")
	f.String("password-file", "", "independent APFS volume password bytes; encrypted APFS writes remain unsupported")
	f.String("output-password-file", "", "replacement DMG password bytes; retain source AES strength unless --encryption is set")
	f.String("encryption", "", "output DMG encryption: AES-128, AES-256 or none; default preserves source encryption")
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
	for _, name := range []string{"image-password-file", "password-file", "output-password-file"} {
		if f.Lookup(name).Value.String() == "-" {
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
	if o.Encryption != nil {
		clear(o.Encryption.Password)
	}
}
