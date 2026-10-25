package fixture

import (
	"strings"
	"testing"
)

// These are synthetic rows worked from Apple's pinned fs_usage formatter,
// not recorded native evidence: system_cmds 408bba7453608006b89772db185defbac8fe2fd0,
// fs_usage.c print_open, FMT_IOCTL, FMT_FD and wide process.thread suffix.
const syntheticEjectTrace = "12:34:56.100001  open              F=7        (R_______________) /dev/rdisk42 0.000005 diskarbitrationd.921\n" +
	"12:34:56.100010  ioctl             F=7   <CMD=0x20006415> 0.000004 diskarbitrationd.921\n" +
	"12:34:56.100015  close             F=7   0.000002 diskarbitrationd.921\n"

func TestEjectTraceCoverageRequiresTheCompleteExactDeviceLifecycle(t *testing.T) {
	got, err := inspectEjectTrace([]byte(syntheticEjectTrace), "/dev/rdisk42")
	if err != nil || !got.Complete || got.TargetRaw != "/dev/rdisk42" || got.FD != 7 || got.Thread != "921" || got.OpenErrno != 0 || got.EjectErrno != 0 {
		t.Fatalf("complete exact-target lifecycle was not identified: %+v, %v", got, err)
	}
	if got.OpenTime != "12:34:56.100001" || got.EjectTime != "12:34:56.100010" || got.CloseTime != "12:34:56.100015" || len(got.Attempts) != 1 {
		t.Fatalf("event times or individual attempt were lost: %+v", got)
	}
}

func TestEjectTraceCoverageRejectsMissingOrAmbiguousDeviceEvents(t *testing.T) {
	rows := strings.SplitAfter(syntheticEjectTrace, "\n")
	for _, tc := range []struct{ name, data string }{
		{"absent", "12:34:56.100001  stat /unrelated 0.000005 diskarbitrationd.921\n"},
		{"substring target", strings.ReplaceAll(syntheticEjectTrace, "/dev/rdisk42", "/dev/rdisk420")},
		{"path suffix", strings.ReplaceAll(syntheticEjectTrace, "/dev/rdisk42", "/tmp/dev/rdisk42")},
		{"block alias", strings.ReplaceAll(syntheticEjectTrace, "/dev/rdisk42", "/dev/disk42")},
		{"unmatched eject", rows[1] + rows[2]},
		{"missing close", rows[0] + rows[1]},
		{"later unfinished attempt", syntheticEjectTrace + rows[0]},
		{"close before eject", rows[0] + rows[2] + rows[1]},
		{"failed close", rows[0] + rows[1] + strings.Replace(rows[2], "F=7", "F=7 [  9]", 1)},
		{"changed descriptor", rows[0] + strings.Replace(rows[1], "F=7", "F=8", 1) + rows[2]},
		{"descriptor outside formatter int", strings.ReplaceAll(syntheticEjectTrace, "F=7", "F=2147483648")},
		{"changed eject thread", rows[0] + strings.Replace(rows[1], ".921\n", ".922\n", 1) + rows[2]},
		{"changed close thread", rows[0] + rows[1] + strings.Replace(rows[2], ".921\n", ".922\n", 1)},
		{"descriptor overwrite", rows[0] + rows[0] + rows[1] + rows[2]},
		{"extended open overwrite", rows[0] + strings.Replace(strings.Replace(rows[0], "open ", "open_extended ", 1), "/dev/rdisk42", "/dev/rdisk3", 1) + rows[1] + rows[2]},
		{"uninterpreted descriptor mutation", rows[0] + "12:34:56.100005  fcntl F=8 DUPFD 0.000001 diskarbitrationd.921\n" + rows[1] + rows[2]},
		{"duplicate eject", rows[0] + rows[1] + rows[1] + rows[2]},
		{"wrong ioctl", strings.ReplaceAll(syntheticEjectTrace, "0x20006415", "0x20006416")},
		{"dropped events", syntheticEjectTrace + "fs_usage: buffer overrun, events generated too quickly\n"},
		{"foreign process", strings.ReplaceAll(syntheticEjectTrace, "diskarbitrationd", "another-daemon")},
		{"missing thread suffix", strings.ReplaceAll(syntheticEjectTrace, ".921", "")},
		{"zero thread", strings.ReplaceAll(syntheticEjectTrace, ".921", ".0")},
		{"overflowed thread", strings.ReplaceAll(syntheticEjectTrace, ".921", ".9999999999999999999999999999")},
		{"partial final row", strings.TrimSuffix(syntheticEjectTrace, "\n")},
		{"invalid time", strings.ReplaceAll(syntheticEjectTrace, "12:34:", "25:34:")},
		{"no events", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := inspectEjectTrace([]byte(tc.data), "/dev/rdisk42")
			if err == nil || got.Complete || got.Reason == "" {
				t.Fatalf("incomplete or ambiguous trace became qualified: %+v, %v", got, err)
			}
		})
	}
}

func TestEjectTraceCoverageSeparatesConcurrentKnownDevices(t *testing.T) {
	rows := strings.SplitAfter(syntheticEjectTrace, "\n")
	other := strings.SplitAfter(strings.NewReplacer("F=7", "F=8", "/dev/rdisk42", "/dev/rdisk43", ".921\n", ".922\n").Replace(syntheticEjectTrace), "\n")
	// A process-wide trace contains both existing controls' cleanup and may
	// contain earlier unrelated descriptor operations; no PID-wide exclusivity
	// or completeness is inferred from either positively bound target chain.
	data := "12:34:56.000001  fcntl F=4 GETFL 0.000001 diskarbitrationd.919\n" + rows[0] + other[0] + other[1] + rows[1] + other[2] + rows[2]
	for _, tc := range []struct {
		target, thread string
		fd             int
	}{{"/dev/rdisk42", "921", 7}, {"/dev/rdisk43", "922", 8}} {
		got, err := inspectEjectTrace([]byte(data), tc.target)
		if err != nil || !got.Complete || got.FD != tc.fd || got.Thread != tc.thread || len(got.Attempts) != 1 {
			t.Fatalf("known foreign events displaced exact target coverage: %+v, %v", got, err)
		}
	}
}

func TestEjectTraceCoverageNeverAttributesUnboundOrReusedForeignDescriptors(t *testing.T) {
	rows := strings.SplitAfter(syntheticEjectTrace, "\n")
	foreign := strings.Replace(rows[0], "/dev/rdisk42", "/dev/rdisk3", 1) + rows[1] + rows[2]
	data := rows[1] + rows[2] + syntheticEjectTrace + foreign
	got, err := inspectEjectTrace([]byte(data), "/dev/rdisk42")
	if err != nil || !got.Complete || len(got.Attempts) != 1 || got.Attempts[0].FD != 7 {
		t.Fatalf("unbound/foreign reuse was attributed to this target or hid its positive chain: %+v, %v", got, err)
	}
}

func TestEjectTraceCoveragePreservesBusyErrnoAndSequentialAttempts(t *testing.T) {
	busy := strings.Replace(syntheticEjectTrace, "F=7   <CMD=", "F=7  [ 16] <CMD=", 1)
	got, err := inspectEjectTrace([]byte(busy+syntheticEjectTrace), "/dev/rdisk42")
	if err != nil || !got.Complete || len(got.Attempts) != 2 || got.Attempts[0].EjectErrno != 16 || got.Attempts[1].EjectErrno != 0 {
		t.Fatalf("separate complete busy/success attempts were collapsed: %+v, %v", got, err)
	}
	if got.EjectErrno != 0 || got.FD != 7 || got.Thread != "921" {
		t.Fatalf("summary does not describe the last completed attempt: %+v", got)
	}
}

func TestEjectTraceCoverageDistinguishesOpenRefusalWithoutInventingAnIoctl(t *testing.T) {
	data := "12:34:56.100001  open [ 16] (R_______________) /dev/rdisk42 0.000005 diskarbitrationd.921\n"
	got, err := inspectEjectTrace([]byte(data), "/dev/rdisk42")
	if err == nil || got.Complete || got.OpenErrno != 16 || got.FD != -1 || got.EjectTime != "" || got.CloseTime != "" || len(got.Attempts) != 1 {
		t.Fatalf("open refusal was lost or relabelled as an ioctl: %+v, %v", got, err)
	}
}

func TestEjectTraceCoverageBoundsInputsAndDoesNotInventTargetAliases(t *testing.T) {
	for _, target := range []string{"/dev/disk42", "/dev/rdisk42/", "/dev/rdisk42s1", "/dev/../dev/rdisk42", "", "/dev/rdisk42\x00"} {
		if got, err := inspectEjectTrace([]byte(syntheticEjectTrace), target); err == nil || got.Complete {
			t.Fatalf("unsupported target was silently normalized: %q: %+v, %v", target, got, err)
		}
	}
	for _, data := range [][]byte{[]byte(strings.Repeat(" ", 4097) + "\n"), []byte(strings.Repeat("\n", 65537)), []byte(strings.Repeat("\n", (8<<20)+1)), {0xff, '\n'}} {
		if got, err := inspectEjectTrace(data, "/dev/rdisk42"); err == nil || got.Complete || got.Reason == "" {
			t.Fatalf("unbounded or invalid bytes became coverage: %+v, %v", got, err)
		}
	}
}

func TestEjectTraceCoverageRefusesImpossibleTargetClockOrdering(t *testing.T) {
	for _, data := range []string{
		strings.Replace(syntheticEjectTrace, "12:34:56.100010", "12:34:56.100000", 1),
		strings.Replace(syntheticEjectTrace, "12:34:56.100015", "12:34:56.100005", 1),
		strings.NewReplacer("12:34:56.100010", "12:35:07.100010", "12:34:56.100015", "12:35:07.100015").Replace(syntheticEjectTrace),
		strings.NewReplacer("12:34:56.100001", "00:00:00.000010", "12:34:56.100010", "23:59:59.999999", "12:34:56.100015", "00:00:00.000015").Replace(syntheticEjectTrace),
	} {
		if got, err := inspectEjectTrace([]byte(data), "/dev/rdisk42"); err == nil || got.Complete {
			t.Fatalf("an impossible bounded target chronology became positive: %+v, %v", got, err)
		}
	}
}

func TestEjectTraceCoverageKeepsPossibleMidnightAndEqualClockRows(t *testing.T) {
	for _, data := range []string{
		strings.NewReplacer("12:34:56.100001", "23:59:59.999990", "12:34:56.100010", "00:00:00.000001", "12:34:56.100015", "00:00:00.000009").Replace(syntheticEjectTrace),
		strings.NewReplacer("12:34:56.100010", "12:34:56.100001", "12:34:56.100015", "12:34:56.100001").Replace(syntheticEjectTrace),
	} {
		if got, err := inspectEjectTrace([]byte(data), "/dev/rdisk42"); err != nil || !got.Complete {
			t.Fatalf("possible chronology lost its original raw times: %+v, %v", got, err)
		}
	}
}

func TestEjectTraceCoverageDoesNotInventHeadersOrIgnoreErrorNotices(t *testing.T) {
	// The pinned startup/completion code has no stdout table header/footer;
	// its two shared-cache diagnostic printfs are disabled by #if 0. Do not
	// whitelist imagined framing that could hide a new tool error or version.
	for _, extra := range []string{"TIMESTAMP CALL FD PATH TIME PROCESS\n", "fs_usage: complete\n", "fs_usage: buffer overrun, events generated too quickly\n"} {
		if got, err := inspectEjectTrace([]byte(extra+syntheticEjectTrace), "/dev/rdisk42"); err == nil || got.Complete {
			t.Fatalf("unsupported framing/error notice was silently ignored: %+v, %v", got, err)
		}
	}
}
