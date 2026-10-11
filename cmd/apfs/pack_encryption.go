package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/deploymenttheory/go-apfs-v3/diskimage"
)

type packEncryptionFlags struct {
	policy, sourcePassword, outputPassword string
}

func addPackEncryptionFlags(f *flag.FlagSet, source bool) *packEncryptionFlags {
	o := &packEncryptionFlags{}
	f.StringVar(&o.policy, "encryption", "", "output DMG encryption: AES-128, AES-256 or none; required for encrypted image input")
	f.StringVar(&o.outputPassword, "output-password-file", "", "new DMG password bytes in FILE; - reads stdin to EOF")
	if source {
		f.StringVar(&o.sourcePassword, "image-password-file", "", "source DMG password bytes in FILE; - reads stdin to EOF")
	}
	return o
}

func (f *packEncryptionFlags) options(input io.Reader, imageSource bool) (o diskimage.RepackOptions, err error) {
	if f.sourcePassword != "" && !imageSource {
		return o, fmt.Errorf("--image-password-file applies only to image repacking")
	}
	switch f.policy {
	case "", "none":
		if f.outputPassword != "" {
			return o, fmt.Errorf("--output-password-file requires --encryption AES-128 or AES-256")
		}
		o.Decrypt = f.policy == "none"
	case "AES-128", "AES-256":
		if f.outputPassword == "" {
			return o, fmt.Errorf("encrypted output requires --output-password-file")
		}
	default:
		return o, fmt.Errorf("--encryption must be AES-128, AES-256 or none")
	}
	if f.sourcePassword != "" && f.policy == "" {
		return o, fmt.Errorf("encrypted image repacking requires an explicit --encryption AES-128, AES-256 or none")
	}
	if f.sourcePassword == "-" && f.outputPassword == "-" {
		return o, fmt.Errorf("source and output passwords cannot both read stdin")
	}
	defer func() {
		if err != nil {
			clearPackPasswords(o)
		}
	}()
	if f.sourcePassword != "" {
		o.SourcePassword, err = readPassword(f.sourcePassword, input)
		if err != nil {
			return o, err
		}
	}
	if f.outputPassword != "" {
		var password []byte
		password, err = readPassword(f.outputPassword, input)
		if err != nil {
			return o, err
		}
		bits := uint32(128)
		if f.policy == "AES-256" {
			bits = 256
		}
		o.Encryption = &diskimage.EncryptionOptions{KeyBits: bits, Password: password}
		err = o.Encryption.Validate()
	}
	return o, err
}

func clearPackPasswords(o diskimage.RepackOptions) {
	clear(o.SourcePassword)
	if o.Encryption != nil {
		clear(o.Encryption.Password)
	}
}

func packEncryptionLabel(e *diskimage.Encryption) string {
	if e == nil {
		return "none"
	}
	return fmt.Sprintf("AES-%d", e.KeyBits)
}
