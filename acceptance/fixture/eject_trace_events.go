package fixture

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// The caller binds the numeric process filter and complete stdout/stderr
// retention. Wide fs_usage suffixes are thread IDs, never process IDs.
type ejectTraceCoverage struct {
	TargetRaw                      string
	FD                             int
	Thread                         string
	OpenErrno, EjectErrno          int
	OpenTime, EjectTime, CloseTime string
	Complete                       bool
	Reason                         string
	Attempts                       []ejectTraceAttempt
}

type ejectTraceAttempt struct {
	FD                             int
	Thread                         string
	OpenErrno, EjectErrno          int
	OpenTime, EjectTime, CloseTime string
}

var (
	ejectTraceTarget    = regexp.MustCompile(`^/dev/rdisk[0-9]+$`)
	ejectTraceRow       = regexp.MustCompile(`^([0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6})\s+(\S+)\s+(.*?)\s+[0-9]+\.[0-9]{6}(?:\s+W)?\s+diskarbitrationd\.([0-9]+)$`)
	ejectTraceOpen      = regexp.MustCompile(`^F=\s*([0-9]+)\s+\([^)]*\)\s+(.+)$`)
	ejectTraceOpenError = regexp.MustCompile(`^\[\s*([0-9]+)\]\s+\([^)]*\)\s+(.+)$`)
	ejectTraceIOCTL     = regexp.MustCompile(`^F=\s*([0-9]+)\s*(?:\[\s*([0-9]+)\])?\s+<CMD=0x([0-9a-fA-F]+)>$`)
	ejectTraceClose     = regexp.MustCompile(`^F=\s*([0-9]+)\s*(?:\[\s*([0-9]+)\])?$`)
)

// inspectEjectTrace recognizes a pinned-formatter synchronous daemon open ->
// DKIOCEJECT -> checked close chain. Complete is positive target coverage, not
// whole-trace coverage: foreign/unbound ejects cannot create target attempts.
// It does not infer dates, PID, missing events, aliases or an eject blocker.
// Summary fields describe the last completed attempt; Attempts preserves the
// observed, positively bound target attempts, not all possible target activity.
func inspectEjectTrace(data []byte, targetRaw string) (out ejectTraceCoverage, err error) {
	out.TargetRaw, out.FD = targetRaw, -1
	fail := func(reason string) (ejectTraceCoverage, error) {
		out.Complete, out.Reason = false, reason
		return out, fmt.Errorf("inspect eject trace: %s", reason)
	}
	if !ejectTraceTarget.MatchString(targetRaw) || len(data) > 8<<20 || !utf8.Valid(data) {
		return fail("target or trace bytes outside supported bounds")
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return fail("empty or incomplete final trace row")
	}
	// Track all observed opens, including foreign paths, so an FD cannot be
	// silently rebound to this target after close/reuse.
	opened := map[int]*ejectTraceAttempt{}
	targetFD := map[int]bool{}
	liveTargets := 0
	openFailed := false
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 1024), 4096)
	lines := 0
	for scanner.Scan() {
		lines++
		if lines > 65536 {
			return fail("trace row count exceeds supported bounds")
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		row := ejectTraceRow.FindStringSubmatch(line)
		if row == nil {
			return fail("malformed, dropped, or unqualified process trace row")
		}
		if _, parseErr := time.Parse("15:04:05.000000", row[1]); parseErr != nil {
			return fail("invalid trace clock value")
		}
		thread, parseErr := strconv.ParseUint(row[4], 10, 64)
		if parseErr != nil || thread == 0 || strconv.FormatUint(thread, 10) != row[4] {
			return fail("invalid wide thread identifier")
		}
		switch row[2] {
		case "open", "open_extended", "open_dprotected", "guarded_open_np":
			if failed := ejectTraceOpenError.FindStringSubmatch(row[3]); failed != nil {
				if failed[2] == targetRaw {
					code, parseErr := strconv.Atoi(failed[1])
					if parseErr != nil || code == 0 {
						return fail("invalid target open errno")
					}
					attempt := ejectTraceAttempt{FD: -1, Thread: row[4], OpenTime: row[1], OpenErrno: code}
					out.Attempts = append(out.Attempts, attempt)
					out.setAttempt(attempt)
					openFailed = true
				}
				continue
			}
			fields := ejectTraceOpen.FindStringSubmatch(row[3])
			if fields == nil {
				return fail("open result cannot bind a descriptor and exact path")
			}
			fd, parseErr := ejectTraceFD(fields[1])
			if parseErr != nil || opened[fd] != nil {
				return fail("open descriptor is invalid or reused before close")
			}
			opened[fd] = &ejectTraceAttempt{FD: fd, Thread: row[4], OpenTime: row[1]}
			targetFD[fd] = fields[2] == targetRaw
			if targetFD[fd] {
				liveTargets++
			}
		case "ioctl":
			fields := ejectTraceIOCTL.FindStringSubmatch(row[3])
			if fields == nil {
				return fail("ioctl descriptor, errno or request is malformed")
			}
			request, parseErr := strconv.ParseUint(fields[3], 16, 32)
			if parseErr != nil {
				return fail("invalid ioctl request")
			}
			if request != 0x20006415 { // Apple's _IO('d', 21), DKIOCEJECT.
				continue
			}
			fd, parseErr := ejectTraceFD(fields[1])
			attempt := opened[fd]
			if parseErr != nil {
				return fail("invalid eject descriptor")
			}
			if attempt == nil || !targetFD[fd] {
				continue // Unknown or positively foreign, never target evidence.
			}
			if attempt.Thread != row[4] || attempt.EjectTime != "" {
				return fail("eject ioctl lacks one exact-target open on the same thread")
			}
			attempt.EjectTime = row[1]
			if fields[2] != "" {
				attempt.EjectErrno, parseErr = strconv.Atoi(fields[2])
				if parseErr != nil || attempt.EjectErrno == 0 {
					return fail("invalid eject errno")
				}
			}
		case "close", "guarded_close_np":
			fields := ejectTraceClose.FindStringSubmatch(row[3])
			if fields == nil {
				return fail("close descriptor or errno is malformed")
			}
			fd, parseErr := ejectTraceFD(fields[1])
			if parseErr != nil {
				return fail("invalid close descriptor")
			}
			if attempt := opened[fd]; attempt != nil && targetFD[fd] {
				if fields[2] != "" || attempt.Thread != row[4] || attempt.EjectTime == "" {
					return fail("target close failed or lacks its same-thread eject")
				}
				attempt.CloseTime = row[1]
				if !ejectTraceChronology(*attempt) {
					return fail("target event clocks cannot form one bounded ordered lifecycle")
				}
				out.Attempts = append(out.Attempts, *attempt)
				out.setAttempt(*attempt)
				liveTargets--
			}
			delete(opened, fd)
			delete(targetFD, fd)
		case "dup", "dup2", "fcntl":
			if liveTargets > 0 {
				return fail("descriptor mutation during the target lifetime is ambiguous")
			}
		case "fork", "vfork", "execve", "posix_spawn", "exit":
			return fail("descriptor or process lifetime became ambiguous")
		default:
			if liveTargets > 0 && (strings.HasPrefix(row[2], "open") || strings.HasPrefix(row[2], "guarded_open") || strings.HasPrefix(row[2], "close") || strings.HasPrefix(row[2], "guarded_close")) {
				return fail("uninterpreted descriptor acquisition or close")
			}
		}
	}
	if scanErr := scanner.Err(); scanErr != nil {
		out.Reason = "trace row exceeds supported bounds"
		return out, errors.Join(errors.New(out.Reason), scanErr)
	}
	for fd := range opened {
		if targetFD[fd] {
			return fail("target descriptor lifecycle is incomplete")
		}
	}
	if openFailed || len(out.Attempts) == 0 {
		return fail("no complete exact-target eject lifecycle")
	}
	out.Complete = true
	return out, nil
}

func (c *ejectTraceCoverage) setAttempt(a ejectTraceAttempt) {
	c.FD, c.Thread, c.OpenErrno, c.EjectErrno = a.FD, a.Thread, a.OpenErrno, a.EjectErrno
	c.OpenTime, c.EjectTime, c.CloseTime = a.OpenTime, a.EjectTime, a.CloseTime
}

func ejectTraceFD(text string) (int, error) {
	fd, err := strconv.ParseInt(text, 10, 32) // Formatter casts the FD to C int.
	return int(fd), err
}

func ejectTraceChronology(a ejectTraceAttempt) bool {
	// Rows already passed the clock grammar. The existing capture has a six-
	// second duration and ten-second command deadline. Modulo-day offsets allow
	// a possible midnight crossing without assigning any date; the caller must
	// still bind those original UTC times to its actual execution window.
	open, _ := time.Parse("15:04:05.000000", a.OpenTime)
	eject, _ := time.Parse("15:04:05.000000", a.EjectTime)
	closeTime, _ := time.Parse("15:04:05.000000", a.CloseTime)
	ejectAfterOpen, closeAfterOpen := eject.Sub(open), closeTime.Sub(open)
	if ejectAfterOpen < 0 {
		ejectAfterOpen += 24 * time.Hour
	}
	if closeAfterOpen < 0 {
		closeAfterOpen += 24 * time.Hour
	}
	return ejectAfterOpen <= closeAfterOpen && closeAfterOpen <= 10*time.Second
}
