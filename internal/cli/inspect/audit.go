package inspect

import (
	"fmt"
	"os"
	"path/filepath"
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
	depth := 2
	if len(args) == 1 {
		if _, err := fmt.Sscanf(args[0], "%d", &depth); err != nil {
			return exit.Errorf(exit.Usage, "usage: wuserbox --audit [depth]")
		}
	} else if len(args) > 1 {
		return exit.Errorf(exit.Usage, "usage: wuserbox --audit [depth]")
	}
	found := 0
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
		if len(by) > 0 {
			fmt.Printf("%s (%s)\n", dir, strings.Join(by, ", "))
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
	return nil
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
