package fixture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// Capture executes one recipe for one profile and writes the retained
// images and observations into Out.
type Capture struct {
	Recipe   *schema.Recipe
	Profile  schema.Profile
	Disk     Disk
	Vol      Volume
	C        Commander
	Work     string
	Out      string
	Payloads string
	Helpers  map[string]string // helper name -> built binary path
	Producer schema.Producer

	captureCredentials
	vars      *Vars
	t         *Transcript
	scratch   string
	att       *Attachment
	baselines map[string]string // stage -> writable scratch copy
	retained  map[string]string // stage -> retained image path
	snapshots map[string]string
}

// Run performs every stage and derivation.
func (c *Capture) Run(ctx context.Context) (err error) {
	c.baselines, c.retained, c.snapshots = map[string]string{}, map[string]string{}, map[string]string{}
	if err := os.MkdirAll(c.Out, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(c.Work, 0o755); err != nil {
		return err
	}
	defer func() {
		if c.att != nil {
			if derr := c.Disk.Detach(context.Background(), c.att); err == nil {
				err = derr
			}
			c.att = nil
		}
	}()
	c.t = &Transcript{}
	if err := c.format(ctx); err != nil {
		return fmt.Errorf("%s/%s: format: %w", c.Recipe.Name, c.Profile.ID, err)
	}
	for i := range c.Recipe.Stages {
		stage := &c.Recipe.Stages[i]
		if err := c.runStage(ctx, stage); err != nil {
			return fmt.Errorf("%s/%s/%s: %w", c.Recipe.Name, c.Profile.ID, stage.Name, err)
		}
	}
	if c.att != nil {
		if err := c.detach(ctx); err != nil {
			return err
		}
	}
	for i := range c.Recipe.Derive {
		d := &c.Recipe.Derive[i]
		if !applies(d.Only, c.Profile.ID) {
			continue
		}
		if err := c.derive(ctx, d); err != nil {
			return fmt.Errorf("%s/%s/%s: %w", c.Recipe.Name, c.Profile.ID, d.Name, err)
		}
	}
	return nil
}

func applies(only []string, profile string) bool {
	if len(only) == 0 {
		return true
	}
	for _, id := range only {
		if id == profile {
			return true
		}
	}
	return false
}

func (c *Capture) prefix() string { return c.Profile.ID }

func (c *Capture) newVars() *Vars {
	v := &Vars{Payloads: c.Payloads, Passwords: c.Recipe.Passwords}
	u, _ := user.Current()
	if u != nil {
		v.Set("UID", u.Uid)
		v.Set("GID", u.Gid)
		v.Set("USER", u.Username)
	}
	v.Set("STAGE", filepath.Join(c.Work, "stage"))
	v.Set("IMAGE", c.scratch)
	if c.Profile.CaseSensitive {
		v.Set("FS", "APFSX")
	} else {
		v.Set("FS", "APFS")
	}
	for name, path := range c.snapshots {
		v.SetKeyed("SNAPSHOT", name, path)
	}
	return v
}

// refreshVars re-derives device and mount references after the volume
// inventory changed.
func (c *Capture) refreshVars(ctx context.Context) error {
	if err := c.Disk.Refresh(ctx, c.att); err != nil {
		return err
	}
	v := c.vars
	v.Set("DEV", c.att.Dev)
	v.Set("RDEV", c.att.RDev)
	if c.att.Container != "" {
		v.Set("CONTAINER", c.att.Container)
	}
	for i, vol := range c.att.Volumes {
		v.SetKeyed("VOLUME", vol.Name, vol.Dev)
		v.SetKeyed("MOUNTDIR", vol.Name, c.mountDir(vol.Name))
		if vol.Mount != "" {
			v.SetKeyed("MOUNT", vol.Name, vol.Mount)
		}
		if i == 0 {
			v.Set("VOLUME", vol.Dev)
			v.Set("MOUNTDIR", c.mountDir(vol.Name))
			if vol.Mount != "" {
				v.Set("MOUNT", vol.Mount)
			}
		}
	}
	return nil
}

func (c *Capture) mountDir(volume string) string {
	return filepath.Join(c.Work, "mnt", sanitize(volume))
}

// format creates and attaches the scratch image for the first stage.
func (c *Capture) format(ctx context.Context) error {
	size := c.Recipe.Image.Size
	if s, ok := c.Recipe.Image.SizeByProfile[c.Profile.ID]; ok {
		size = s
	}
	volname := c.Recipe.Image.VolumeName
	if volname == "" {
		volname = c.Recipe.Name
	}
	c.vars = c.newVars()
	switch c.Recipe.Image.Create {
	case "hdiutil":
		c.scratch = filepath.Join(c.Work, c.prefix()+".scratch.dmg")
		fsargs := c.Recipe.Image.FSArgs[c.Profile.ID]
		expanded, err := c.vars.Expand(fsargs)
		if err != nil {
			return err
		}
		if err := c.Disk.CreateImage(ctx, c.scratch, size, c.layout(), c.Profile.HdiutilFS, expanded, volname); err != nil {
			return err
		}
		att, err := c.Disk.Attach(ctx, c.scratch, AttachOptions{})
		if err != nil {
			return err
		}
		c.att = att
		if c.Profile.Family == "hfs" {
			// hdiutil's HFS+ defaults vary; make the journal state the
			// profile's, through diskutil, before anything is written.
			verb := "disableJournal"
			if c.Profile.Journaled {
				verb = "enableJournal"
			}
			for _, vol := range att.Volumes {
				if err := c.runTool(ctx, &schema.ToolStep{Program: "diskutil", Args: []string{verb, vol.Dev}, Expect: "0", Label: "journal-state"}); err != nil {
					return err
				}
			}
		}
	case "raw-newfs":
		c.scratch = filepath.Join(c.Work, c.prefix()+".scratch.raw")
		bytes, err := parseSize(size)
		if err != nil {
			return err
		}
		if err := c.Disk.CreateRaw(ctx, c.scratch, bytes); err != nil {
			return err
		}
		att, err := c.Disk.Attach(ctx, c.scratch, AttachOptions{Raw: true})
		if err != nil {
			return err
		}
		c.att = att
		c.vars.Set("RDEV", att.RDev)
		c.vars.Set("VOLNAME", volname)
		args, err := c.vars.ExpandAll(strings.Fields(c.Recipe.Image.Newfs[c.Profile.ID]))
		if err != nil {
			return err
		}
		program := "newfs_hfs"
		if c.Profile.Family == "apfs" {
			program = "newfs_apfs"
		}
		if helper, ok := c.Helpers["newfs_hfs_debug"]; ok && contains(c.Recipe.Requires.Helpers, "newfs_hfs_debug") {
			program = helper
		}
		if err := c.runTool(ctx, &schema.ToolStep{Program: program, Args: args, Sudo: true, Expect: "0", Label: "newfs"}); err != nil {
			return err
		}
	}
	c.vars.Set("IMAGE", c.scratch)
	if err := c.refreshVars(ctx); err != nil {
		return err
	}
	return c.autoMount(ctx)
}

func (c *Capture) layout() string {
	if l, ok := c.Recipe.Image.LayoutByProfile[c.Profile.ID]; ok {
		return l
	}
	return c.Recipe.Image.Layout
}

func (c *Capture) output() string {
	if o, ok := c.Recipe.Image.OutputByProfile[c.Profile.ID]; ok {
		return o
	}
	return c.Recipe.Image.Output
}

// autoMount mounts every unlocked, unmounted volume with the recipe's
// options. Locked volumes wait for the recipe's own unlock and mount steps.
func (c *Capture) autoMount(ctx context.Context) error {
	options := c.Recipe.Image.MountOptions
	if options == "" {
		options = "owners,noatime"
	}
	for _, vol := range c.att.Volumes {
		if vol.Locked || vol.Mount != "" {
			continue
		}
		if err := c.Disk.Mount(ctx, vol, options, c.mountDir(vol.Name), false); err != nil {
			return err
		}
	}
	return c.refreshVars(ctx)
}

func (c *Capture) runStage(ctx context.Context, stage *schema.Stage) error {
	c.t = &Transcript{}
	if stage.From != "" {
		if c.att != nil {
			if err := c.detach(ctx); err != nil {
				return err
			}
		}
		baseline, ok := c.baselines[stage.From]
		if !ok {
			return fmt.Errorf("no baseline for stage %s", stage.From)
		}
		if err := copyFile(baseline, c.scratch, true); err != nil {
			return err
		}
	}
	if c.att == nil {
		att, err := c.Disk.Attach(ctx, c.scratch, AttachOptions{Raw: c.Recipe.Image.Create == "raw-newfs"})
		if err != nil {
			return err
		}
		c.att = att
		c.vars = c.newVars()
		if err := c.refreshVars(ctx); err != nil {
			return err
		}
		if err := c.autoMount(ctx); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Join(c.Work, "stage"), 0o755); err != nil {
		return err
	}
	for i := range stage.Steps {
		step := &stage.Steps[i]
		if !applies(step.Only, c.Profile.ID) {
			continue
		}
		if err := c.runStep(ctx, step); err != nil {
			return fmt.Errorf("step %d: %w", i, err)
		}
	}
	if err := c.detach(ctx); err != nil {
		return err
	}
	baseline := filepath.Join(c.Work, "baseline", c.prefix()+"."+stage.Name)
	if err := os.MkdirAll(filepath.Dir(baseline), 0o755); err != nil {
		return err
	}
	if err := copyFile(c.scratch, baseline, true); err != nil {
		return err
	}
	c.baselines[stage.Name] = baseline
	retained, err := c.retain(ctx, stage)
	if err != nil {
		return err
	}
	if err := c.observe(ctx, stage.Name, stage.Observe, retained, c.output(), nil, c.prefix()+"."+stage.Name); err != nil {
		return err
	}
	if stage.Discard {
		if err := os.Remove(retained); err != nil {
			return err
		}
	} else {
		c.retained[stage.Name] = retained
	}
	return nil
}

func (c *Capture) detach(ctx context.Context) error {
	for _, vol := range c.att.Volumes {
		if vol.Mount != "" {
			if err := c.Disk.Unmount(ctx, vol); err != nil {
				return err
			}
		}
	}
	err := c.Disk.Detach(ctx, c.att)
	c.att = nil
	return err
}

// retain converts the detached scratch into the stage's retained image.
func (c *Capture) retain(ctx context.Context, stage *schema.Stage) (string, error) {
	dir := c.Out
	if stage.Discard {
		dir = filepath.Join(c.Work, "discard")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", err
		}
	}
	format := c.output()
	if format == "raw" {
		out := filepath.Join(dir, c.prefix()+"."+stage.Name+".raw.gz")
		if c.Recipe.Image.Create == "raw-newfs" {
			if err := gzipCopy(c.scratch, out); err != nil {
				return "", err
			}
			return out, nil
		}
		att, err := c.Disk.Attach(ctx, c.scratch, AttachOptions{ReadOnly: true})
		if err != nil {
			return "", err
		}
		info, err := c.Disk.Info(ctx, att.Dev)
		if err != nil {
			_ = c.Disk.Detach(ctx, att)
			return "", err
		}
		_, err = c.Disk.DeviceDigest(ctx, att.RDev, int64(number(info["TotalSize"])), out)
		if derr := c.Disk.Detach(ctx, att); err == nil {
			err = derr
		}
		if err != nil {
			return "", err
		}
		return out, nil
	}
	out := filepath.Join(dir, c.prefix()+"."+stage.Name+".dmg")
	if err := c.Disk.Convert(ctx, c.scratch, format, out, "", nil); err != nil {
		return "", err
	}
	return out, nil
}

// observe attaches a retained image read-only and records it.
func (c *Capture) observe(ctx context.Context, stage string, spec schema.ObserveSpec, image, format string, password []byte, prefix string) error {
	attachPath := image
	raw := false
	if strings.HasSuffix(image, ".raw.gz") {
		raw = true
		attachPath = filepath.Join(c.Work, "observe-"+filepath.Base(strings.TrimSuffix(image, ".gz")))
		if err := gunzipCopy(image, attachPath); err != nil {
			return err
		}
		defer func() { _ = os.Remove(attachPath) }()
	}
	att, err := c.Disk.Attach(ctx, attachPath, AttachOptions{ReadOnly: true, Raw: raw, Password: password})
	if err != nil {
		return err
	}
	work := filepath.Join(c.Work, "observe-work")
	_ = os.RemoveAll(work)
	obs, err := Observe(ctx, ObserveInput{Recipe: c.Recipe, Profile: c.Profile, Stage: stage, Spec: spec, Image: image, Format: format, Password: password, Att: att, Disk: c.Disk, Vol: c.Vol, Vars: c.vars, T: c.t, Work: work, Out: c.Out, Prefix: prefix, Producer: c.Producer})
	if derr := c.Disk.Detach(ctx, att); err == nil {
		err = derr
	}
	if err != nil {
		return err
	}
	after, err := schema.FileDigest(image)
	if err != nil {
		return err
	}
	if after != obs.Image.SHA256 {
		return fmt.Errorf("observation changed %s: %s -> %s", image, obs.Image.SHA256, after)
	}
	if len(c.sentinels) > 0 {
		obs.Image.Sentinels = c.sentinels
	}
	if password != nil {
		obs.Image.Encryption.Password = c.currentPasswordRef
		obs.Image.Encryption.Rejected = c.currentRejected
		if cipher := encryptionCipher(obs.Image.Imageinfo); cipher != "" {
			obs.Image.Encryption.Cipher = cipher
		}
	}
	data, err := json.MarshalIndent(obs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(c.Out, prefix+".observation.json"), append(data, '\n'), 0o644)
}

// encryptionCipher digs the cipher name out of imageinfo's backing store
// chain.
func encryptionCipher(info map[string]any) string {
	for m := info; m != nil; {
		if enc, ok := m["Encryption"].(string); ok {
			return enc
		}
		if props, ok := m["Properties"].(map[string]any); ok {
			if enc, ok := props["Encryption"].(string); ok {
				return enc
			}
		}
		next, _ := m["Backing Store Information"].(map[string]any)
		m = next
	}
	return ""
}

func (c *Capture) runStep(ctx context.Context, step *schema.Step) error {
	switch {
	case step.Host != nil:
		return c.runHost(step.Host)
	case step.Tool != nil:
		if err := c.runTool(ctx, step.Tool); err != nil {
			return err
		}
		if step.Tool.Program == "diskutil" || step.Tool.Program == "hdiutil" {
			return c.refreshVars(ctx)
		}
		return nil
	case step.FS != nil:
		return c.runFS(step.FS, step.Note)
	case step.Control != nil:
		return c.runControl(ctx, step.Control)
	}
	return errors.New("empty step")
}

func (c *Capture) runHost(h *schema.HostStep) error {
	path := filepath.Join(c.Work, "stage", filepath.FromSlash(h.Path))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	mode := os.FileMode(h.Mode)
	if mode == 0 {
		mode = 0o644
	}
	switch h.Pattern {
	case "tree":
		if err := os.MkdirAll(path, 0o755); err != nil {
			return err
		}
		for i := 0; i < h.Count; i++ {
			if err := os.WriteFile(filepath.Join(path, fmt.Sprintf("%s%05d", h.Prefix, i)), generate("zeros", "", h.Bytes), mode); err != nil {
				return err
			}
		}
		return nil
	case "payload":
		data, err := c.vars.Payload(h.Payload)
		if err != nil {
			return err
		}
		return os.WriteFile(path, data, mode)
	case "text":
		return os.WriteFile(path, []byte(h.Content), mode)
	default:
		return os.WriteFile(path, generate(h.Pattern, h.Label, h.Bytes), mode)
	}
}

// generate produces deterministic bytes for a pattern.
func generate(pattern, label string, n int64) []byte {
	if n <= 0 {
		return []byte{}
	}
	var cycle []byte
	switch pattern {
	case "zeros":
		return make([]byte, n)
	case "reverse":
		for i := 255; i >= 0; i-- {
			cycle = append(cycle, byte(i))
		}
	default:
		for i := 0; i < 256; i++ {
			cycle = append(cycle, byte(i))
		}
		if label != "" {
			cycle = append(append(cycle, label...), '\n')
		}
	}
	out := make([]byte, 0, n)
	for int64(len(out)) < n {
		out = append(out, cycle...)
	}
	return out[:n]
}

func (c *Capture) runTool(ctx context.Context, t *schema.ToolStep) error {
	args, err := c.vars.ExpandAll(t.Args)
	if err != nil {
		return err
	}
	program := t.Program
	if helper, ok := c.Helpers[program]; ok {
		program = helper
	}
	var stdin []byte
	for _, ref := range t.Stdin {
		password, ok := c.Recipe.Passwords[ref]
		if !ok {
			return fmt.Errorf("unknown password reference %q", ref)
		}
		stdin = append(append(stdin, password...), '\n')
	}
	if t.StdinBytes != "" {
		data, err := c.vars.Payload(t.StdinBytes)
		if err != nil {
			return err
		}
		stdin = data
	}
	if program == "hdiutil" && len(stdin) > 0 {
		// hdiutil reads NUL-terminated passwords.
		stdin = append(stdin[:len(stdin)-1], 0)
	}
	cmd := Command{Label: t.Label, Argv: append([]string{program}, args...), Stdin: stdin, Sudo: t.Sudo, Expected: t.Expect}
	if t.TimeoutSeconds > 0 {
		cmd.Timeout = secondsToDuration(t.TimeoutSeconds)
	}
	result := c.C.Run(ctx, cmd)
	return c.t.Record(cmd, result)
}

func (c *Capture) runFS(f *schema.FSStep, note string) error {
	p, err := c.vars.Expand(f.Path)
	if err != nil {
		return err
	}
	target := ""
	if f.Target != "" {
		if target, err = c.vars.Expand(f.Target); err != nil {
			return err
		}
	}
	data, err := c.bytesFor(f)
	if err != nil {
		return err
	}
	argv := []string{"fs:" + f.Op, p}
	if target != "" {
		argv = append(argv, target)
	}
	if f.Name != "" {
		argv = append(argv, f.Name)
	}
	var opErr error
	switch f.Op {
	case "write":
		opErr = c.Vol.WriteFile(p, data, f.Option == "create")
	case "append":
		opErr = c.Vol.AppendFile(p, data)
	case "pwrite":
		opErr = c.Vol.Pwrite(p, f.Offset, data)
	case "truncate":
		opErr = c.Vol.Truncate(p, f.Bytes)
	case "mkdir":
		mode := f.Mode
		if mode == 0 {
			mode = 0o755
		}
		opErr = c.Vol.Mkdir(p, mode)
	case "symlink":
		opErr = c.Vol.Symlink(f.Target, p)
	case "link":
		opErr = c.Vol.Link(p, target)
	case "rename":
		opErr = c.Vol.Rename(p, target)
	case "unlink":
		opErr = c.Vol.Remove(p)
	case "rmdir":
		opErr = c.Vol.Rmdir(p)
	case "chmod":
		opErr = c.Vol.Lchmod(p, f.Mode)
	case "chflags":
		opErr = c.Vol.Chflags(p, f.Flags)
	case "setxattr":
		opErr = c.Vol.Setxattr(p, f.Name, data, f.Option)
	case "removexattr":
		opErr = c.Vol.Removexattr(p, f.Name)
	case "settimes":
		if f.Times == nil {
			return errors.New("settimes needs times")
		}
		opErr = c.Vol.Settimes(p, f.Times.Birth, f.Times.Modify, f.Times.Access)
	case "fullfsync":
		opErr = c.Vol.Fullfsync(p)
	case "clone":
		opErr = c.Vol.Clone(p, target)
	case "fill":
		return c.fill(f, p, argv)
	case "thin":
		names, err := c.Vol.Readdir(p)
		if err != nil {
			return err
		}
		sort.Strings(names)
		for i, name := range names {
			if i%2 == 0 {
				if err := c.Vol.Remove(filepath.Join(p, name)); err != nil {
					return err
				}
			}
		}
		return c.t.RecordFS("thin", argv, nil, "0")
	default:
		return fmt.Errorf("unknown fs op %q", f.Op)
	}
	return c.t.RecordFS(f.Op, argv, opErr, f.Expect)
}

// fill writes files until ENOSPC/EDQUOT or Count, recording the outcome.
func (c *Capture) fill(f *schema.FSStep, dir string, argv []string) error {
	count := f.Count
	if count <= 0 {
		count = 1 << 20
	}
	data := generate("zeros", "", f.Bytes)
	written := 0
	var last error
	for i := 0; i < count; i++ {
		name := filepath.Join(dir, fmt.Sprintf("%05d%s", int(f.Offset)+i, f.Label))
		if err := c.Vol.WriteFile(name, data, true); err != nil {
			last = err
			_ = c.Vol.Remove(name)
			break
		}
		if f.Bytes > 0 {
			if err := c.Vol.Fullfsync(name); err != nil {
				last = err
				break
			}
		}
		written++
		if f.MinFree > 0 {
			if free, err := c.Vol.FreeBytes(dir); err == nil && free < f.MinFree {
				break
			}
		}
	}
	argv = append(argv, fmt.Sprintf("written=%d", written))
	if f.Expect == "ENOSPC" || f.Expect == "EDQUOT" {
		if last == nil {
			return fmt.Errorf("fill %s: wrote %d files without reaching %s", dir, written, f.Expect)
		}
		if written == 0 {
			return fmt.Errorf("fill %s: no file written before %v", dir, last)
		}
		var errno syscall.Errno
		if errors.As(last, &errno) && (errno == syscall.ENOSPC || errno == syscall.EDQUOT) {
			return c.t.RecordFS("fill", argv, last, errnoName(errno))
		}
		return fmt.Errorf("fill %s: %v", dir, last)
	}
	return c.t.RecordFS("fill", argv, last, "0")
}

func (c *Capture) bytesFor(f *schema.FSStep) ([]byte, error) {
	switch {
	case f.Payload != "":
		return c.vars.Payload(f.Payload)
	case f.Pattern != "":
		return generate(f.Pattern, f.Label, f.Bytes), nil
	case f.Repeat > 0:
		return []byte(strings.Repeat(f.Content, f.Repeat)), nil
	default:
		return []byte(f.Content), nil
	}
}

func (c *Capture) derive(ctx context.Context, d *schema.Derivation) error {
	c.t = &Transcript{}
	source, ok := c.retained[d.From]
	if !ok {
		return fmt.Errorf("stage %s has no retained image", d.From)
	}
	out := filepath.Join(c.Out, c.prefix()+"."+d.Name+".dmg")
	c.vars = c.newVars()
	c.vars.Set("IMAGE", source)
	c.vars.Set("OUT", out)
	for i := range d.Steps {
		if err := c.runTool(ctx, &d.Steps[i]); err != nil {
			return err
		}
	}
	if _, err := os.Stat(out); err != nil {
		return fmt.Errorf("derivation produced no %s: %w", out, err)
	}
	if !d.Observe {
		return nil
	}
	var password []byte
	if d.Password != "" {
		pw, ok := c.Recipe.Passwords[d.Password]
		if !ok {
			return fmt.Errorf("unknown password %q", d.Password)
		}
		password = []byte(pw)
		c.currentPasswordRef, c.currentRejected = d.Password, d.Rejected
		for _, ref := range d.Rejected {
			bad, ok := c.Recipe.Passwords[ref]
			if !ok {
				return fmt.Errorf("unknown password %q", ref)
			}
			if _, err := c.Disk.Imageinfo(ctx, out, []byte(bad)); err == nil {
				return fmt.Errorf("rejected password %q opened %s", ref, out)
			}
		}
	}
	format := "UDZO"
	for i := len(d.Steps) - 1; i >= 0; i-- {
		for j, arg := range d.Steps[i].Args {
			if arg == "-format" && j+1 < len(d.Steps[i].Args) {
				format = d.Steps[i].Args[j+1]
			}
		}
	}
	spec := c.Recipe.Stages[0].Observe
	for _, s := range c.Recipe.Stages {
		if s.Name == d.From {
			spec = s.Observe
		}
	}
	return c.observe(ctx, d.Name, spec, out, format, password, c.prefix()+"."+d.Name)
}

func contains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

func parseSize(s string) (int64, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "g"):
		mult, s = 1<<30, strings.TrimSuffix(s, "g")
	case strings.HasSuffix(s, "m"):
		mult, s = 1<<20, strings.TrimSuffix(s, "m")
	case strings.HasSuffix(s, "k"):
		mult, s = 1<<10, strings.TrimSuffix(s, "k")
	}
	var n int64
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return 0, fmt.Errorf("size %q", s)
	}
	return n * mult, nil
}

func copyFile(src, dst string, replace bool) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if !replace {
		flags |= os.O_EXCL
	}
	out, err := os.OpenFile(dst, flags, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func gzipCopy(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	w, err := newGzipFile(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, in); err != nil {
		_ = w.Close()
		return err
	}
	return w.Close()
}
