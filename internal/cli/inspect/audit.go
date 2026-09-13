package inspect

import (
	"fmt"
	"github.com/PHPCraftdream/wuserbox/internal/exit"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

// auditCmd lists directories that Everyone may write to. The sandbox can write
// there too, because Everyone has to be a restricting SID for processes to
// start at all.
func Audit(args []string) error {
	depth := 2
	if len(args) == 1 {
		if _, err := fmt.Sscanf(args[0], "%d", &depth); err != nil {
			return exit.Errorf(exit.Usage, "usage: wuserbox audit [depth]")
		}
	} else if len(args) > 1 {
		return exit.Errorf(exit.Usage, "usage: wuserbox audit [depth]")
	}
	found := 0
	var walk func(dir string, left int)
	walk = func(dir string, left int) {
		if acl.EveryoneWritable(dir) {
			fmt.Println(dir)
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
	fmt.Fprintf(os.Stderr, "%d directories writable by Everyone\n", found)
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
