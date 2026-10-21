package acceptance_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/session"
)

var commandBinary struct {
	sync.Once
	path string
	err  error
}

func portableCommandBinary(t *testing.T) string {
	t.Helper()
	commandBinary.Do(func() {
		commandBinary.path = filepath.Join(outputDir(t), "apfs-commands")
		if runtime.GOOS == "windows" {
			commandBinary.path += ".exe"
		}
		data, err := exec.Command("go", "build", "-o", commandBinary.path, "../cmd/apfs").CombinedOutput()
		if err != nil {
			commandBinary.err = fmt.Errorf("build product commands: %w: %s", err, data)
		}
	})
	if commandBinary.err != nil {
		t.Fatal(commandBinary.err)
	}
	return commandBinary.path
}

type commandSession struct {
	scratch      string
	actor, group uint32
	clock        time.Time
	host         string
	library      bool
}

func (s *commandSession) run(t *testing.T, reject bool, args ...string) {
	t.Helper()
	if s.library {
		s.libraryCommand(t, args...)
		return
	}
	current := filepath.Join(s.scratch, "build", "current")
	var before []byte
	if reject {
		var err error
		before, err = os.ReadFile(current)
		if err != nil {
			t.Fatal(err)
		}
	}
	var argv []string
	if args[0] == "session" {
		argv = append([]string{"session", args[1], "--scratch-dir", s.scratch}, args[2:]...)
	} else {
		argv = append([]string{args[0], "--scratch-dir", s.scratch, "--session", "build"}, args[1:]...)
	}
	data, err := exec.Command(portableCommandBinary(t), argv...).CombinedOutput()
	if reject {
		exit, ok := err.(*exec.ExitError)
		if !ok || exit.ExitCode() != 1 {
			t.Fatalf("expected command rejection %v: %v %s", args, err, data)
		}
		after, err := os.ReadFile(current)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("rejected command changed the published revision", err)
		}
	} else if err != nil {
		t.Fatalf("command %v: %v\n%s", args, err, data)
	}
}

// Permission semantics use public library calls and reopen after each command.
// The journey test separately exercises the CLI/process boundary. Keeping these
// paths separate also avoids forking unrelated CLI children with live API locks.
func (s *commandSession) libraryCommand(t *testing.T, args ...string) {
	t.Helper()
	ctx := context.Background()
	directory := filepath.Join(s.scratch, "build")
	if args[0] == "session" && args[1] == "remove" {
		if err := session.Remove(ctx, directory); err != nil {
			t.Fatal(err)
		}
		return
	}
	w, err := session.Open(ctx, directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := w.Close(); err != nil {
			t.Error(err)
		}
	}()
	switch args[0] {
	case "session":
		switch args[1] {
		case "verify":
			err = w.Verify(ctx)
		case "export":
			_, err = w.Export(ctx, args[3])
		default:
			t.Fatal("unsupported library session operation", args)
		}
	case "mkdir":
		_, err = w.Mkdir(ctx, args[1:], session.MkdirOptions{})
	case "touch":
		_, err = w.Touch(ctx, args[1:], session.TouchOptions{})
	case "chmod":
		_, err = w.Chmod(ctx, args[2:], args[1], session.WalkOptions{})
	case "chown":
		_, err = w.Chown(ctx, args[2:], args[1], session.WalkOptions{})
	case "cp":
		options := session.CopyOptions{}
		var operands []string
		for _, a := range args[1:] {
			switch a {
			case "-p":
				options.Preserve = true
			case "-X":
				options.NoAttributes = true
			default:
				if strings.HasPrefix(a, "-") {
					t.Fatal("unsupported permission copy flag", a)
				}
				operands = append(operands, a)
			}
		}
		_, err = w.Copy(ctx, operands[:len(operands)-1], operands[len(operands)-1], options)
	default:
		t.Fatal("unsupported permission library command", args)
	}
	if err != nil {
		t.Fatal(args, err)
	}
}

func nativeActor(t *testing.T, k corpus.Case) (uint32, uint32) {
	t.Helper()
	for _, e := range k.Observation.Views[0].Entries {
		if e.Path == "Fixture" {
			return e.UID, e.GID
		}
	}
	t.Fatal("native fixture has no creator ownership")
	return 0, 0
}

func commandClock(cases []corpus.Case) time.Time {
	var latest int64
	for _, k := range cases {
		for _, v := range k.Observation.Views {
			for _, e := range v.Entries {
				latest = max(latest, e.Times.Birth, e.Times.Modify, e.Times.Change, e.Times.Access)
			}
		}
	}
	// A clock after the capture avoids making cp -p's birth-time minimum
	// differ merely because the deterministic test clock predates its source.
	return time.Unix(0, latest).Add(time.Hour).Truncate(time.Second).UTC()
}

func openCommandSession(t *testing.T, before corpus.Case, clock time.Time) *commandSession {
	t.Helper()
	uid, gid := nativeActor(t, before)
	s := &commandSession{scratch: filepath.Join(t.TempDir(), "scratch"), actor: uid, group: gid, clock: clock, host: t.TempDir()}
	s.run(t, false, "session", "open", "--image", before.Image(), "--path", "Fixture", "--uid", fmt.Sprint(uid), "--gid", fmt.Sprint(gid), "--time", clock.Format(time.RFC3339Nano), "build")
	return s
}

func openPermissionSession(t *testing.T, before corpus.Case, clock time.Time, recipe schema.Recipe) *commandSession {
	t.Helper()
	ctx := context.Background()
	uid, gid := nativeActor(t, before)
	s := &commandSession{scratch: filepath.Join(t.TempDir(), "scratch"), actor: uid, group: gid, clock: clock, host: t.TempDir(), library: true}
	_, reader, closeSource := openSingleVolume(t, ctx, before, recipe)
	defer closeSource()
	root, err := filesystem.LookupExact(ctx, reader, "Fixture")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(s.scratch, 0700); err != nil {
		t.Fatal(err)
	}
	w, err := session.Capture(ctx, buildRoot{reader, root}, filepath.Join(s.scratch, "build"), session.Options{UID: uid, GID: gid, Time: &clock})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return s
}

func (s *commandSession) export(t *testing.T, before, after corpus.Case) {
	t.Helper()
	w := produceWorkspace(t, before, after, "session", &schema.WorkspaceExpectation{Policy: "commands", ClockNS: s.clock.UnixNano()}, func(dir string) error {
		s.run(t, false, "session", "export", "build", dir)
		return nil
	})
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func (s *commandSession) input(t *testing.T, h *schema.HostStep) {
	t.Helper()
	data := []byte(h.Content)
	if h.Payload != "" {
		var err error
		data, err = os.ReadFile(filepath.Join("recipes", "payloads", h.Payload))
		if err != nil {
			t.Fatal(err)
		}
	} else if h.Pattern != "" && h.Pattern != "text" {
		data = generatePattern(h.Pattern, h.Label, h.Bytes)
	}
	filename := filepath.Join(s.host, h.Path)
	mode := os.FileMode(h.Mode)
	if mode == 0 {
		mode = 0644
	}
	if err := os.WriteFile(filename, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filename, s.clock, s.clock); err != nil {
		t.Fatal(err)
	}
}

func (s *commandSession) tool(t *testing.T, tool *schema.ToolStep) {
	t.Helper()
	args := []string{tool.Program}
	host, fork := false, false
	for _, a := range tool.Args {
		if strings.Contains(a, "$STAGE/") {
			host = true
			a = strings.ReplaceAll(a, "$STAGE/", s.host+string(filepath.Separator))
		}
		a = strings.ReplaceAll(a, "$MOUNT/Fixture", "")
		a = strings.ReplaceAll(a, "$UID", fmt.Sprint(s.actor))
		a = strings.ReplaceAll(a, "$GID", fmt.Sprint(s.group))
		if strings.HasSuffix(a, "/..namedfork/rsrc") {
			fork = true
			a = strings.TrimSuffix(a, "/..namedfork/rsrc")
		}
		args = append(args, a)
	}
	if host {
		args = append(args, "--from-host")
	}
	if fork {
		args = append(args, "--resource-fork")
	}
	s.run(t, tool.Expect != "" && tool.Expect != "0", args...)
}

func TestFileCommandSessionsMatchAppleJourney(t *testing.T) {
	cases, _ := loadCorpus(t)
	indexed := indexCases(cases)
	recipe := recipesByName(t)["file-command-journeys"]
	for _, before := range cases {
		if before.Recipe != recipe.Name || before.Stage != "before" {
			continue
		}
		after := indexed[stageKey(before.Producer, before.Recipe, before.Profile, "after")]
		if after.Observation == nil {
			t.Fatal("missing native file-command after state")
		}
		t.Run(fmt.Sprintf("macos-%d/%s", before.Producer, before.Profile), func(t *testing.T) {
			t.Parallel()
			sum, err := schema.FileDigest(before.Image())
			if err != nil {
				t.Fatal(err)
			}
			s := openCommandSession(t, before, commandClock([]corpus.Case{before, after}))
			s.export(t, before, before)
			for _, step := range recipe.Stages[1].Steps {
				switch {
				case step.Host != nil:
					s.input(t, step.Host)
				case step.Tool != nil:
					s.tool(t, step.Tool)
				default:
					t.Fatal("unhandled file-command journey step")
				}
			}
			s.run(t, false, "session", "verify", "build")
			s.export(t, before, after)
			if got, err := schema.FileDigest(before.Image()); err != nil || got != sum {
				t.Fatal("commands changed the source image", err)
			}
			s.run(t, false, "session", "remove", "build")
		})
	}
}

// Actor changes use a fresh logical capture, never the host process's account.
// Every subsequent operation reopens persisted state in a separate CLI process.
func (s *commandSession) actorContext(t *testing.T, uid uint32) {
	t.Helper()
	if s.actor == uid {
		return
	}
	ctx := context.Background()
	old, err := session.Open(ctx, filepath.Join(s.scratch, "build"))
	if err != nil {
		t.Fatal(err)
	}
	nextRoot := filepath.Join(t.TempDir(), "scratch")
	if err := os.Mkdir(nextRoot, 0700); err != nil {
		t.Fatal(err)
	}
	next, err := session.Capture(ctx, old, filepath.Join(nextRoot, "build"), session.Options{UID: uid, GID: s.group, Time: &s.clock})
	if err != nil {
		t.Fatal(err)
	}
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	s.scratch, s.actor = nextRoot, uid
}

func (s *commandSession) fs(t *testing.T, f *schema.FSStep) {
	t.Helper()
	p := "/" + workspacePath(f.Path)
	switch f.Op {
	case "mkdir":
		s.run(t, false, "mkdir", p)
	case "chmod":
		s.run(t, false, "chmod", strconv.FormatUint(uint64(f.Mode), 8), p)
	case "write", "append", "truncate":
		ctx := context.Background()
		current, err := session.Open(ctx, filepath.Join(s.scratch, "build"))
		if err != nil {
			t.Fatal(err)
		}
		data, err := stepBytes(f)
		if err != nil {
			t.Fatal(err)
		}
		id, lookupErr := current.LookupPath(ctx, p, true)
		if f.Op == "append" {
			if lookupErr != nil {
				t.Fatal(lookupErr)
			}
			v, err := current.OpenData(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			old, err := readValue(v)
			if err != nil {
				t.Fatal(err)
			}
			data = append(old, data...)
		}
		if f.Op == "truncate" {
			data = make([]byte, f.Bytes)
		}
		if lookupErr == nil {
			_, err = current.ReplaceData(ctx, p, bytes.NewReader(data))
		} else {
			// POSIX create/write has no host-import metadata. Create through
			// touch, then write through the public session API; the parent ACL,
			// group and explicit actor determine creation on every host.
			if err := current.Close(); err != nil {
				t.Fatal(err)
			}
			s.run(t, false, "touch", p)
			current, err = session.Open(ctx, filepath.Join(s.scratch, "build"))
			if err != nil {
				t.Fatal(err)
			}
			_, err = current.ReplaceData(ctx, p, bytes.NewReader(data))
		}
		if err != nil {
			t.Fatal(f.Op, p, err)
		}
		if err := current.Close(); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unhandled permission filesystem operation %s", f.Op)
	}
}

func TestSessionPermissionsMatchAppleStates(t *testing.T) {
	cases, _ := loadCorpus(t)
	indexed := indexCases(cases)
	recipe := recipesByName(t)["permission-inheritance"]
	for _, before := range cases {
		if before.Recipe != recipe.Name || before.Stage != "before" {
			continue
		}
		after := indexed[stageKey(before.Producer, before.Recipe, before.Profile, "after")]
		copied := indexed[stageKey(before.Producer, before.Recipe, before.Profile, "copied")]
		if after.Observation == nil || copied.Observation == nil {
			t.Fatal("missing native permission states")
		}
		t.Run(fmt.Sprintf("macos-%d/%s", before.Producer, before.Profile), func(t *testing.T) {
			t.Parallel()
			s := openPermissionSession(t, before, commandClock([]corpus.Case{before, after, copied}), recipe)
			actor, _ := nativeActor(t, before)
			s.export(t, before, before)
			for _, stage := range recipe.Stages[1:] {
				for _, step := range stage.Steps {
					switch {
					case step.Host != nil:
						s.input(t, step.Host)
					case step.FS != nil:
						s.actorContext(t, actor)
						s.fs(t, step.FS)
					case step.Tool != nil:
						uid := actor
						if step.Tool.Sudo {
							uid = 0
						}
						s.actorContext(t, uid)
						if step.Tool.Program == "cp" && strings.HasPrefix(step.Tool.Args[0], "$STAGE/") {
							// The recipe's declared host input contains bytes only.
							// Exercise the root writer without importing unrelated
							// metadata from the machine running this portable test.
							data, err := os.ReadFile(filepath.Join(s.host, strings.TrimPrefix(step.Tool.Args[0], "$STAGE/")))
							if err != nil {
								t.Fatal(err)
							}
							s.fs(t, &schema.FSStep{Op: "write", Path: step.Tool.Args[len(step.Tool.Args)-1], Content: string(data)})
							continue
						}
						tool := *step.Tool
						tool.Args = append([]string(nil), tool.Args...)
						for i, a := range tool.Args {
							tool.Args[i] = strings.ReplaceAll(a, "$UID", fmt.Sprint(actor))
						}
						s.tool(t, &tool)
					default:
						t.Fatal("unhandled permission recipe step")
					}
				}
				s.run(t, false, "session", "verify", "build")
				s.export(t, before, indexed[stageKey(before.Producer, before.Recipe, before.Profile, stage.Name)])
			}
		})
	}
}
