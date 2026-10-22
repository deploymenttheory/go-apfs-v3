package session

import (
	"context"
	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/copyfile"
)

// CopyOptions shares Apple's ordinary copy policy with existing-image commands.
type CopyOptions = copyfile.Options
type CopyOmission = copyfile.Omission
type CopyCloneResult = copyfile.CloneResult

func (s *Session) Copy(ctx context.Context, sources []string, to string, options CopyOptions) (Report, error) {
	var omitted []copyfile.Omission
	var clones []CopyCloneResult
	report, err := s.mutate(ctx, func(c *command) error {
		backend := copyfile.Backend{Tree: c.tree, Time: c.now, ActorUID: filesystem.Observed(s.document.Config.UID), UID: s.document.Config.UID, GID: s.document.Config.GID, Umask: s.document.Config.Umask, Limits: s.document.Config.Limits, Apply: c.apply, CloneNamespace: s.digest, CloneResult: func(value CopyCloneResult) { clones = append(clones, value) }, Omitted: func(value copyfile.Omission) { omitted = append(omitted, value) },
			Own: func(ctx context.Context, v filesystem.Value, total *int64) (block.Source, error) {
				b, err := s.store(ctx, v, total)
				if err != nil {
					return nil, err
				}
				return &blobValue{owner: s, ctx: ctx, ref: b}, nil
			},
		}
		if err := copyfile.Run(ctx, backend, sources, to, options); err != nil {
			return err
		}
		c.changed = true
		return nil
	})
	report.OmittedAttributes = omitted
	report.Clones = clones
	return report, err
}
