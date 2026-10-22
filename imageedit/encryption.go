package imageedit

import (
	"fmt"
	"io/fs"

	"github.com/deploymenttheory/go-apfs-v3/diskimage"
)

func (o Options) outputEncryption(source *diskimage.Encryption) (*diskimage.EncryptionOptions, error) {
	if o.Decrypt && o.Encryption != nil {
		return nil, fmt.Errorf("output encryption and decryption are mutually exclusive: %w", fs.ErrInvalid)
	}
	if o.Decrypt {
		return nil, nil
	}
	var output diskimage.EncryptionOptions
	if o.Encryption != nil {
		output = *o.Encryption
		if output.KeyBits == 0 && source != nil {
			output.KeyBits = source.KeyBits
		}
	} else if source != nil {
		output = diskimage.EncryptionOptions{KeyBits: source.KeyBits, Password: o.ImagePassword}
	} else {
		return nil, nil
	}
	if err := output.Validate(); err != nil {
		return nil, err
	}
	return &output, nil
}
