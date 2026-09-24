package inspect

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/base/exit"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
)

// The identities the walk asks about are the ones a sandbox carries through
// both of the access checks its token faces. A directory either of them may
// change is a directory every sandbox may change, however it was meant to be
// handed out, which is what makes this list worth printing.
//
// Authenticated Users was on it for as long as the account was the whole of a
// sandbox: an account that logged on carries it, so a directory naming it was
// one every sandbox could change. The restricted token is back on top of the
// account and puts it out of reach again -- the second check names a short
// list, and Authenticated Users is not on it -- so listing it now would report
// places the boundary does reach.
//
// Audit lists directories the identities above may write to. The sandbox can
// write there too: it carries both, and has to, or no program starts in it
// and nothing under System32 can be read.
func Audit(args []string) error {
	depth, err := auditDepth(args)
	if err != nil {
		return err
	}
	drives, driveErr := fixedDrives()
	if driveErr != nil && len(drives) == 0 {
		fmt.Fprintf(os.Stderr, "audit incomplete: could not list fixed drives: %v\n", driveErr)
		return fmt.Errorf("audit incomplete: could not list fixed drives: %w", driveErr)
	}
	pass, err := acl.BeginWritable()
	if err != nil {
		return err
	}
	defer pass.End()
	result := walkAudit(drives, depth, pass.Writable, os.ReadDir,
		func(line string) { fmt.Println(line) }, reportAuditIssue)
	if driveErr != nil {
		issue := fmt.Errorf("fixed drive discovery stopped early: %w", driveErr)
		reportAuditIssue(issue)
		result.firstErr = issue
	}
	fmt.Fprintf(os.Stderr, "%d directories writable by Everyone or Users\n", result.found)
	if result.permissionUnknown > 0 {
		fmt.Fprintf(os.Stderr, "%d directories had permissions that could not be read; nothing is claimed about them\n", result.permissionUnknown)
	}
	if result.enumerationFailures > 0 {
		fmt.Fprintf(os.Stderr, "%d directories could not be enumerated; findings above are partial\n", result.enumerationFailures)
	}
	return result.err()
}

func reportAuditIssue(err error) {
	fmt.Fprintf(os.Stderr, "audit incomplete: %v\n", err)
}

func auditDepth(args []string) (int, error) {
	// Sscanf read the depth and said nothing about what came after it, so
	// "-5" parsed and so did "2x". The walk's only boundary is left == 0,
	// which a negative start never reaches: one negative argument turned
	// --audit from a two-level glance into a walk of every fixed drive to
	// its last leaf, two permission reads per directory the whole way down.
	// Atoi answers both questions: the whole argument, and nothing else.
	depth := 2
	if len(args) == 1 {
		parsed, err := strconv.Atoi(args[0])
		if err != nil {
			return 0, exit.Errorf(exit.Usage, "usage: wuserbox --audit [depth]")
		}
		if parsed < 0 {
			return 0, exit.Errorf(exit.Usage,
				"a negative depth would walk without a bottom; give 0 to stop at the drive roots")
		}
		depth = parsed
	} else if len(args) > 1 {
		return 0, exit.Errorf(exit.Usage, "usage: wuserbox --audit [depth]")
	}
	return depth, nil
}

type auditResult struct {
	found               int
	permissionUnknown   int
	enumerationFailures int
	firstErr            error
}

func (r auditResult) err() error {
	if r.firstErr != nil {
		return fmt.Errorf("audit incomplete: %w", r.firstErr)
	}
	return nil
}

func (r *auditResult) recordError(err error) {
	if r.firstErr == nil {
		r.firstErr = err
	}
}

func walkAudit(roots []string, depth int, writable func(string) (bool, bool, error), readDir func(string) ([]os.DirEntry, error), findingOut func(string), issueOut func(error)) auditResult {
	var result auditResult
	var walk func(dir string, left int)
	walk = func(dir string, left int) {
		// One read of the directory's permission list answers for both
		// identities at once, and says whether the list could be read at
		// all -- the walk used to pay a read per identity and a third for
		// the second answer.
		everyone, users, err := writable(dir)
		switch {
		case err != nil:
			findingOut(finding(dir, nil))
			result.permissionUnknown++
		case !everyone && !users:
		default:
			var by []string
			if everyone {
				by = append(by, "Everyone")
			}
			if users {
				by = append(by, "Users")
			}
			findingOut(finding(dir, by))
			result.found++
		}
		if left == 0 {
			return
		}
		entries, err := readDir(dir)
		if err != nil {
			result.enumerationFailures++
			issue := fmt.Errorf("could not enumerate %s: %w", dir, err)
			result.recordError(issue)
			issueOut(issue)
		}
		for _, e := range entries {
			if e.IsDir() && e.Type()&os.ModeSymlink == 0 {
				walk(filepath.Join(dir, e.Name()), left-1)
			}
		}
	}
	for _, drive := range roots {
		walk(drive, depth)
	}
	return result
}

// finding is one line of the list. Naming the identities is the answer; "the
// permissions could not be read" is a different answer and has to look like
// one, or the most alarming lines in the list are the ones that mean the
// least -- another person's profile is unreadable here exactly because it is
// closed.
func finding(dir string, by []string) string {
	if len(by) == 0 {
		return fmt.Sprintf("%s (the permissions could not be read)", dir)
	}
	return fmt.Sprintf("%s (%s)", dir, strings.Join(by, ", "))
}

func fixedDrives() ([]string, error) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getStrings := kernel32.NewProc("GetLogicalDriveStringsW")
	getType := kernel32.NewProc("GetDriveTypeW")
	query := func(buf []uint16) (uint32, error) {
		n, _, callErr := getStrings.Call(uintptr(len(buf)), uintptr(unsafe.Pointer(&buf[0])))
		if n == 0 {
			if callErr != nil && !errors.Is(callErr, syscall.Errno(0)) {
				return 0, callErr
			}
			return 0, syscall.EINVAL
		}
		return uint32(n), nil
	}
	typeOf := func(drive string) (uint32, error) {
		name, err := syscall.UTF16PtrFromString(drive)
		if err != nil {
			return 0, err
		}
		t, _, callErr := getType.Call(uintptr(unsafe.Pointer(name)))
		if t == 0 {
			if callErr != nil && !errors.Is(callErr, syscall.Errno(0)) {
				return 0, callErr
			}
			return 0, syscall.EINVAL
		}
		return uint32(t), nil
	}
	return fixedDrivesWith(query, typeOf)
}

func fixedDrivesWith(query func([]uint16) (uint32, error), typeOf func(string) (uint32, error)) ([]string, error) {
	buf := make([]uint16, 512)
	var count uint32
	for {
		n, err := query(buf)
		if err != nil {
			return nil, fmt.Errorf("GetLogicalDriveStringsW: %w", err)
		}
		if n == 0 {
			return nil, fmt.Errorf("GetLogicalDriveStringsW returned no roots")
		}
		if uint64(n) >= uint64(len(buf)) {
			size := uint64(n)
			if size == uint64(len(buf)) {
				size *= 2
			}
			if size > 1<<20 {
				return nil, fmt.Errorf("GetLogicalDriveStringsW requested an unreasonable buffer: %d", n)
			}
			buf = make([]uint16, int(size))
			continue
		}
		count = n
		break
	}
	if count < 2 || buf[0] == 0 {
		return nil, fmt.Errorf("GetLogicalDriveStringsW returned an empty drive list")
	}
	var out []string
	terminated := false
	for i := 0; i < len(buf); {
		if buf[i] == 0 {
			if i+1 < len(buf) && buf[i+1] == 0 {
				if i != int(count) {
					return out, fmt.Errorf("GetLogicalDriveStringsW returned %d characters but terminated at %d", count, i)
				}
				terminated = true
				break
			}
			return out, fmt.Errorf("GetLogicalDriveStringsW returned an empty drive name")
		}
		end := i
		for end < len(buf) && buf[end] != 0 {
			end++
		}
		if end == len(buf) || end == i {
			return out, fmt.Errorf("GetLogicalDriveStringsW returned a malformed drive list")
		}
		drive := syscall.UTF16ToString(buf[i:end])
		i = end + 1
		const driveFixed = 3
		t, err := typeOf(drive)
		if err != nil {
			return out, fmt.Errorf("GetDriveTypeW(%s): %w", drive, err)
		}
		if t == driveFixed {
			out = append(out, drive)
		}
	}
	if !terminated {
		return out, fmt.Errorf("GetLogicalDriveStringsW returned an unterminated drive list (%d characters)", count)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("GetLogicalDriveStringsW returned no fixed drives")
	}
	return out, nil
}
