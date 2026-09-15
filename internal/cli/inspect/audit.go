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

// writableIdentities are the identities a sandbox carries. A directory any
// one of them may change is a directory every sandbox may change, however it
// was meant to be handed out, which is what makes this list worth printing.
//
// Authenticated Users was missing from it for as long as a sandbox was a
// restricted token that did not carry it. It does now, and a list of where
// the boundary does not reach that left out one of the three ways through
// would be worse than no list.
var writableIdentities = []struct {
	name     string
	writable func(string) bool
}{
	{"Everyone", acl.EveryoneWritable},
	{"Users", acl.UsersWritable},
	{"Authenticated Users", acl.AuthenticatedWritable},
}

// Audit lists directories the identities above may write to. The sandbox can
// write there too: it carries all of them, and has to, or no program starts
// in it and nothing under System32 can be read.
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
		// All three, because all three are carried by a sandbox and any one
		// of them makes a directory writable from inside one. Listing only
		// two would have left the third out of the very list that exists to
		// say where the boundary does not reach.
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
