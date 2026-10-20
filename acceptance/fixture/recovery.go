package fixture

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func isRecoveryStage(s *schema.Stage) bool {
	for _, step := range s.Steps {
		if step.Control == nil {
			continue
		}
		switch step.Control.Action {
		case "journal-window", "replay-journal", "checkpoint-window", "damage":
			return true
		}
	}
	return false
}

// runRecoveryStage never reattaches original interrupted HFS or damaged APFS
// bytes for observation. Such inputs are retained with explicit expectations.
func (c *Capture) runRecoveryStage(ctx context.Context, stage *schema.Stage) error {
	if len(stage.Steps) != 1 || stage.Steps[0].Control == nil {
		return errors.New("a recovery stage must contain exactly one control")
	}
	ctl := stage.Steps[0].Control
	if err := c.retainRecoveryTools(stage.Name); err != nil {
		return err
	}
	if c.att != nil {
		if err := c.detach(ctx); err != nil {
			return err
		}
	}
	from := stage.From
	if ctl.Action == "replay-journal" {
		from = "interrupted-" + strings.TrimPrefix(stage.Name, "replayed-")
	}
	source, ok := c.retained[from]
	if !ok {
		return fmt.Errorf("recovery stage %s has no retained source %q", stage.Name, from)
	}
	live := filepath.Join(c.Work, c.prefix()+"."+stage.Name+".raw")
	if err := gunzipCopy(source, live); err != nil {
		return err
	}
	var recovery *schema.Recovery
	var replayOnly *schema.Image
	var disabledXID uint64
	switch ctl.Action {
	case "journal-window", "checkpoint-window":
		captured, evidence, err := c.captureWindow(ctx, live, stage.Name, ctl)
		if err != nil {
			return err
		}
		if err := os.Rename(captured, live); err != nil {
			return err
		}
		kind, expected := "checkpoint", stage.Name
		if ctl.Action == "journal-window" {
			kind, expected = "journal", "replayed-"+strings.TrimPrefix(stage.Name, "interrupted-")
		}
		recovery = &schema.Recovery{Kind: kind, ExpectedStage: expected, Acquisition: evidence}
	case "replay-journal":
		var err error
		replayOnly, err = c.replayJournal(ctx, live, stage.Name)
		if err != nil {
			return err
		}
	case "damage":
		state, err := measureCheckpoints(live)
		if err != nil {
			return err
		}
		kind := ctl.Params["kind"]
		if kind == "disabled-latest" {
			disabledXID = state.Latest.XID
		}
		offset, count, err := checkpointDamageOffset(live, kind, state)
		if err != nil {
			return err
		}
		parent, err := schema.FileDigest(live)
		if err != nil {
			return err
		}
		before := make([]byte, count)
		f, err := os.OpenFile(live, os.O_RDWR, 0)
		if err != nil {
			return err
		}
		_, err = f.ReadAt(before, offset)
		after := make([]byte, count)
		if count == 1 {
			after[0] = before[0] ^ 1
		}
		if err == nil {
			_, err = f.WriteAt(after, offset)
		}
		err = errors.Join(err, f.Close())
		if err != nil {
			return err
		}
		if kind != "disabled-latest" {
			recovery = &schema.Recovery{Kind: "checkpoint", ExpectedStage: "disabled-latest", RefuseOpen: true, Damage: &schema.Damage{ParentSHA256: parent, Offset: offset, Before: hex.EncodeToString(before), After: hex.EncodeToString(after)}}
		}
		derivation, _ := json.Marshal(schema.Damage{ParentSHA256: parent, Offset: offset, Before: hex.EncodeToString(before), After: hex.EncodeToString(after)})
		c.t.Commands = append(c.t.Commands, schema.Command{Label: "declared-checkpoint-damage", Argv: []string{"damage", kind}, Status: "0", Expected: "0", StdoutText: string(derivation)})
	default:
		return fmt.Errorf("unsupported recovery stage control %q", ctl.Action)
	}
	retained := filepath.Join(c.Out, c.prefix()+"."+stage.Name+".raw.gz")
	if err := gzipCopy(live, retained); err != nil {
		return err
	}
	c.baselines[stage.Name], c.retained[stage.Name] = live, retained
	prefix := c.prefix() + "." + stage.Name
	if recovery != nil && (recovery.Kind == "journal" || recovery.RefuseOpen) {
		image, err := rawImageEvidence(live, retained)
		if err != nil {
			return err
		}
		obs := &schema.Observation{Schema: schema.ObservationSchema, Recipe: c.Recipe.Name, Profile: c.Profile.ID, Stage: stage.Name, Producer: c.Producer, Image: *image, Recovery: recovery, Commands: c.t.Commands}
		return c.writeObservation(prefix, obs)
	}
	if err := c.observe(ctx, stage.Name, stage.Observe, retained, "raw", nil, prefix); err != nil {
		return err
	}
	// Observation is still being assembled; retain its acquisition binding and
	// replay-only reference before it becomes a published corpus member.
	data, err := os.ReadFile(filepath.Join(c.Out, prefix+".observation.json"))
	if err != nil {
		return err
	}
	var obs schema.Observation
	if err := schema.DecodeStrict(data, &obs); err != nil {
		return err
	}
	obs.Recovery, obs.ReplayOnly = recovery, replayOnly
	if obs.Checks.SelectedXID == 0 && c.Profile.Family == "apfs" {
		return errors.New("apple fsck did not identify the recovery checkpoint")
	}
	if disabledXID != 0 && obs.Checks.SelectedXID >= disabledXID {
		return errors.New("descriptor-disabled control did not select an earlier Apple checkpoint")
	}
	return c.writeObservation(prefix, &obs)
}

func (c *Capture) writeObservation(prefix string, obs *schema.Observation) error {
	data, err := json.MarshalIndent(obs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(c.Out, prefix+".observation.json"), append(data, '\n'), 0o644)
}

func rawImageEvidence(raw, archive string) (*schema.Image, error) {
	sum, err := schema.FileDigest(archive)
	if err != nil {
		return nil, err
	}
	disk, err := schema.FileDigest(raw)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(archive)
	if err != nil {
		return nil, err
	}
	rawInfo, err := os.Stat(raw)
	if err != nil {
		return nil, err
	}
	return &schema.Image{File: filepath.Base(archive), SHA256: sum, Bytes: info.Size(), Format: "raw", PartitionMap: "none", SectorSize: 512, DiskSHA256: disk, DiskBytes: rawInfo.Size()}, nil
}

// Each case keeps the bounded helper's source and binary digest alongside its
// command transcript. Historical sources and native evidence are never rewritten.
func (c *Capture) retainRecoveryTools(stage string) error {
	files := map[string][]string{
		"hfs-journal-capture":     {"hfs-journal", "hfs_journal_capture.c"},
		"hfs-journal-replay":      {"hfs-journal", "hfs_journal_replay.c"},
		"apfs-checkpoint-capture": {"apfs-checkpoint", "apfs_checkpoint_capture.c"},
	}
	type identity struct {
		Binary string `json:"binarySHA256"`
		Source string `json:"source"`
		SHA256 string `json:"sourceSHA256"`
	}
	receipt := map[string]identity{}
	for _, name := range c.Recipe.Requires.Helpers {
		parts, ok := files[name]
		if !ok {
			continue
		}
		bin, ok := c.Helpers[name]
		if !ok {
			return fmt.Errorf("missing recovery helper %s", name)
		}
		sum, err := schema.FileDigest(bin)
		if err != nil {
			return err
		}
		source := filepath.Join(filepath.Dir(c.Payloads), "helpers", parts[0], parts[1])
		retained := c.prefix() + "." + stage + "." + parts[1]
		if err := copyFile(source, filepath.Join(c.Out, retained), false); err != nil {
			return err
		}
		digest, err := schema.FileDigest(source)
		if err != nil {
			return err
		}
		receipt[name] = identity{sum, retained, digest}
	}
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(c.Out, c.prefix()+"."+stage+".helpers.json"), append(data, '\n'), 0o644)
}

func (c *Capture) captureWindow(ctx context.Context, live, stage string, ctl *schema.ControlStep) (candidate string, evidence map[string]any, err error) {
	att, err := c.Disk.Attach(ctx, live, AttachOptions{Raw: true, NoKernel: true})
	if err != nil {
		return "", nil, err
	}
	c.att = att
	c.vars = c.newVars()
	if err := c.refreshVars(ctx); err != nil {
		return "", nil, err
	}
	if err := c.autoMount(ctx); err != nil {
		return "", nil, err
	}
	if len(att.Volumes) != 1 || att.Volumes[0].Mount == "" {
		return "", nil, errors.New("interruption capture requires one mounted volume")
	}
	helperName := "apfs-checkpoint-capture"
	mode := ctl.Params["window"]
	if ctl.Action == "journal-window" {
		helperName = "hfs-journal-capture"
		mode = "end"
		if strings.HasSuffix(ctl.Params["shape"], "tail") {
			mode = "tail"
		}
	}
	helper, ok := c.Helpers[helperName]
	if !ok {
		return "", nil, fmt.Errorf("missing capture helper %s", helperName)
	}
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- c.churnRecovery(workerCtx, filepath.Join(att.Volumes[0].Mount, "Fixture")) }()
	defer func() {
		cancel()
		select {
		case workerErr := <-done:
			err = errors.Join(err, workerErr)
		case <-time.After(10 * time.Second):
			err = errors.Join(err, errors.New("native recovery workload did not stop within 10 seconds"))
		}
		// The helper has resumed (or its independent watchdog has fired) before
		// the workload is joined and the attachment is torn down.
		err = errors.Join(err, c.detach(context.Background()))
	}()
	deadline := time.Now().Add(90 * time.Second)
	for attempt := 0; time.Now().Before(deadline); attempt++ {
		if err := ctx.Err(); err != nil {
			return "", nil, err
		}
		identifier, err := c.ownedImageHelper(ctx, live, att.Dev)
		if err != nil {
			return "", nil, err
		}
		candidate = filepath.Join(c.Work, fmt.Sprintf("%s.%s.candidate-%d.raw", c.prefix(), stage, attempt))
		argv := []string{helper, live, strconv.Itoa(identifier)}
		if helperName == "hfs-journal-capture" {
			s, err := measureJournal(live)
			if err != nil {
				return "", nil, err
			}
			argv = append(argv, strconv.FormatUint(s.Offset, 10))
		}
		argv = append(argv, candidate, mode)
		cmd := Command{Label: "capture-window", Argv: argv, Sudo: true, Expected: "0", Timeout: 30 * time.Second}
		result := c.C.Run(ctx, cmd)
		if err := c.t.Record(cmd, result); err != nil {
			return "", nil, err
		}
		var window map[string]any
		if err := json.Unmarshal(result.Stdout, &window); err != nil {
			return "", nil, err
		}
		evidence = map[string]any{"attempt": attempt, "window": window}
		accepted := false
		if helperName == "hfs-journal-capture" {
			s, err := measureJournal(candidate)
			if err != nil {
				return "", nil, err
			}
			changes, tail, err := measureJournalChanges(candidate, s)
			if err != nil {
				return "", nil, err
			}
			shape := "linear"
			if s.Start > s.End {
				shape = "wrapped"
			}
			if mode == "tail" {
				shape = tail
			}
			evidence["journal"], evidence["unappliedSectors"], evidence["shape"] = s, changes, shape
			accepted = journalWindowMatches(s, ctl.Params["shape"], uint64(number(window["observedEnd"])), changes, tail)
		} else {
			s, err := measureCheckpoints(candidate)
			if err != nil {
				return "", nil, err
			}
			evidence["checkpoint"] = s
			switch mode {
			case "data", "mapping":
				_, accepted = s.Future[mode]
			case "committed":
				accepted = s.Latest.XID == uint64(number(window["observedXID"])) && s.Latest.XID > s.BlockZero
			case "wrapped":
				accepted = s.Latest.XID == uint64(number(window["observedXID"])) && s.Latest.DataIndex < uint32(number(window["previousDataIndex"]))
			default:
				return "", nil, fmt.Errorf("unknown checkpoint window %q", mode)
			}
		}
		entry, _ := json.Marshal(evidence)
		c.t.Commands = append(c.t.Commands, schema.Command{Label: "window-measurement", Argv: []string{helperName, stage}, Status: "0", Expected: "record", StdoutText: string(entry)})
		if accepted {
			return candidate, evidence, nil
		}
		if err := os.Remove(candidate); err != nil {
			return "", nil, err
		}
	}
	return "", nil, fmt.Errorf("no %s native capture window within 90 seconds", stage)
}

func (c *Capture) churnRecovery(ctx context.Context, root string) error {
	for generation := uint64(1); ; generation++ {
		for index := 0; index < 256; index++ {
			if ctx.Err() != nil {
				return nil
			}
			path := filepath.Join(root, fmt.Sprintf("entry-%d", index))
			if err := c.Vol.Lchmod(path, 0o600|uint32(generation&0o77)); err != nil {
				return err
			}
			var payload [12]byte
			binary.BigEndian.PutUint64(payload[:], generation)
			binary.BigEndian.PutUint32(payload[8:], uint32(index))
			if err := c.Vol.Setxattr(path, "org.go-apfs.recovery", payload[:], ""); err != nil {
				return err
			}
		}
		if err := c.Vol.Fullfsync(filepath.Join(root, "entry-0")); err != nil {
			return err
		}
	}
}

func (c *Capture) ownedImageHelper(ctx context.Context, image, dev string) (int, error) {
	cmd := Command{Label: "image-helper-inventory", Argv: []string{"hdiutil", "info", "-plist"}, Expected: "0"}
	result := c.C.Run(ctx, cmd)
	if err := c.t.Record(cmd, result); err != nil {
		return 0, err
	}
	d := &HostDisk{C: c.C, T: c.t}
	inventory, err := d.plist(ctx, result.Stdout)
	if err != nil {
		return 0, err
	}
	return imageHelperOwner(inventory, image, dev, os.Getuid())
}

func imageHelperOwner(inventory map[string]any, image, dev string, uid int) (int, error) {
	image, err := filepath.EvalSymlinks(image)
	if err != nil {
		return 0, err
	}
	var identifiers []int
	entries, _ := inventory["images"].([]any)
	for _, entry := range entries {
		m, _ := entry.(map[string]any)
		path, _ := m["image-path"].(string)
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil || resolved != image {
			continue
		}
		entities, _ := m["system-entities"].([]any)
		owned := false
		for _, e := range entities {
			entity, _ := e.(map[string]any)
			if entity["dev-entry"] == dev {
				owned = true
			}
		}
		if !owned {
			continue
		}
		writable, _ := m["writeable"].(bool)
		owner, ownerOK := m["owner-uid"]
		pid, pidOK := m["hdid-pid"]
		if !writable || !ownerOK || int(number(owner)) != uid || !pidOK || number(pid) <= 1 || number(pid) > 2147483647 || number(pid) != float64(int(number(pid))) {
			return 0, errors.New("image helper is not exclusively owned by this runner")
		}
		identifiers = append(identifiers, int(number(pid)))
	}
	if len(identifiers) != 1 {
		return 0, errors.New("expected exactly one writable helper for the attached image and device")
	}
	return identifiers[0], nil
}

func (c *Capture) replayJournal(ctx context.Context, live, stage string) (*schema.Image, error) {
	helper, ok := c.Helpers["hfs-journal-replay"]
	if !ok {
		return nil, errors.New("missing Apple HFS replay helper")
	}
	att, err := c.Disk.Attach(ctx, live, AttachOptions{Raw: true})
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Disk.Detach(context.Background(), att) }()
	cmd := Command{Label: "apple-replay-journal", Argv: []string{helper, att.RDev}, Sudo: true, Expected: "0"}
	result := c.C.Run(ctx, cmd)
	if err := c.t.Record(cmd, result); err != nil {
		return nil, err
	}
	archive := filepath.Join(c.Out, c.prefix()+"."+stage+".replay-only.raw.gz")
	digest, n, err := c.Disk.DeviceDigest(ctx, att.RDev, archive)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(archive)
	if err != nil {
		return nil, err
	}
	sum, err := schema.FileDigest(archive)
	if err != nil {
		return nil, err
	}
	// Read the replayed device rather than depending on the backing file's
	// writeback timing. The original interruption stays in its own archive.
	deviceCopy := live + ".replayed"
	if err := gunzipCopy(archive, deviceCopy); err != nil {
		return nil, err
	}
	if err := os.Rename(deviceCopy, live); err != nil {
		return nil, err
	}
	state, err := measureJournal(live)
	if err != nil {
		return nil, err
	}
	if state.Start != state.End {
		return nil, errors.New("apple replay-only syscall left a pending journal")
	}
	return &schema.Image{File: filepath.Base(archive), SHA256: sum, Bytes: info.Size(), Format: "raw", DiskSHA256: digest, DiskBytes: n, SectorSize: 512, PartitionMap: "none"}, nil
}
