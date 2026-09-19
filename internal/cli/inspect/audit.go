package inspect

import (
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

// writableIdentities are the identities a sandbox carries through both of the
// access checks its token faces. A directory either of them may change is a
// directory every sandbox may change, however it was meant to be handed out,
// which is what makes this list worth printing.
//
// Authenticated Users was on it for as long as the account was the whole of a
// sandbox: an account that logged on carries it, so a directory naming it was
// one every sandbox could change. The restricted token is back on top of the
// account and puts it out of reach again -- the second check names a short
// list, and Authenticated Users is not on it -- so listing it now would report
// places the boundary does reach.
var writableIdentities = []struct {
	name     string
	writable func(string) bool
}{
	{"Everyone", acl.EveryoneWritable},
	{"Users", acl.UsersWritable},
}

// Audit lists directories the identities above may write to. The sandbox can
// write there too: it carries both, and has to, or no program starts in it
// and nothing under System32 can be read.
func Audit(args []string) error {
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
			return exit.Errorf(exit.Usage, "usage: wuserbox --audit [depth]")
		}
		if parsed < 0 {
			return exit.Errorf(exit.Usage,
				"a negative depth would walk without a bottom; give 0 to stop at the drive roots")
		}
		depth = parsed
	} else if len(args) > 1 {
		return exit.Errorf(exit.Usage, "usage: wuserbox --audit [depth]")
	}
	found, unreadable := 0, 0
	var walk func(dir string, left int)
	walk = func(dir string, left int) {
		// Which of them, and not merely that one of them did: a directory
		// open to Everyone and one open to Users are different problems with
		// different fixes, and the list exists to be acted on.
		var by []string
		for _, who := range writableIdentities {
			if who.writable(dir) {
				by = append(by, who.name)
			}
		}
		switch {
		case len(by) == 0:
		case acl.Unreadable(dir):
			fmt.Println(finding(dir, nil))
			unreadable++
		default:
			fmt.Println(finding(dir, by))
			found++
		}
		if left == 0 {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if e.IsDir() && e.Type()&os.ModeSymlink == 0 {
				walk(filepath.Join(dir, e.Name()), left-1)
			}
		}
	}
	for _, drive := range fixedDrives() {
		walk(drive, depth)
	}
	fmt.Fprintf(os.Stderr, "%d directories writable by Everyone or Users\n", found)
	if unreadable > 0 {
		fmt.Fprintf(os.Stderr, "%d more could not be read by this account, so nothing is claimed about them; "+
			"a list this account may not look at usually belongs to somebody else\n", unreadable)
	}
	return nil
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

func fixedDrives() []string {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getStrings := kernel32.NewProc("GetLogicalDriveStringsW")
	getType := kernel32.NewProc("GetDriveTypeW")
	buf := make([]uint16, 512)
	getStrings.Call(uintptr(len(buf)), uintptr(unsafe.Pointer(&buf[0])))
	var out []string
	for i := 0; i < len(buf) && buf[i] != 0; {
		end := i
		for buf[end] != 0 {
			end++
		}
		drive := syscall.UTF16ToString(buf[i:end])
		i = end + 1
		name, _ := syscall.UTF16PtrFromString(drive)
		const driveFixed = 3
		if t, _, _ := getType.Call(uintptr(unsafe.Pointer(name))); t == driveFixed {
			out = append(out, drive)
		}
	}
	return out
}
