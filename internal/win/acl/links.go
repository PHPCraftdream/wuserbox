// The second-name inspection: a permission list belongs to the file, not to
// the name, and a file that answers to a name outside the tree stops a
// grant.

package acl

import (
	"fmt"
	"path/filepath"
	"syscall"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/pathid"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var (
	procFindFirstFileName = w32.Kernel32.NewProc("FindFirstFileNameW")
	procFindNextFileName  = w32.Kernel32.NewProc("FindNextFileNameW")
	procFindClose         = w32.Kernel32.NewProc("FindClose")
)

// EnvAllowLinks hands the tree over even where a file in it answers to another
// name as well. It is read for the whole process, the way the switch for
// prompts is, so that it survives wuserbox starting itself again with
// administrator rights.
const EnvAllowLinks = "WUSERBOX_ALLOW_LINKS"

// insideOnly refuses a file that answers to a name outside the tree being
// handed over.
//
// A hard link is not a second file. It is a second name for the same one, and
// a permission list belongs to the file rather than to the name, so handing a
// directory over hands over every name the files in it have. Windows
// propagates the inheritable entry into the file itself, and a name outside
// the tree then leads to a list that says the sandbox may write and delete
// there. Measured, with icacls on the outside name.
//
// Where the other names are all inside the same tree, nothing reaches further
// than the grant already does, and this passes. That distinction is not a
// refinement: refusing on any second name turned out to refuse the ordinary
// case. Package managers deduplicate inside one directory -- two agents under
// ~/.config sharing one copy of a library, one agent's file history sharing a
// version between sessions -- which is thousands of files in the very
// directories the preset hands over, and not one of them reaches outside.
// Measured, on a real profile, after the strict form made `--init` fail.
//
// The sandbox cannot make such a link itself against anything it may not
// already write, so this is not a way out that a sandbox takes: it is a grant
// reaching further than it says.
//
// Directories are passed over because NTFS does not give one a second name.
func insideOnly(root, path string, isDir bool) error {
	if isDir {
		return nil
	}
	names, err := namesOf(path)
	if err != nil {
		return err
	}
	if names == 1 {
		return nil
	}
	others, err := otherNames(path)
	if err != nil {
		// The count says there is another name and asking which went wrong,
		// so nothing here can say where it is. That is the one case where the
		// count alone has to decide, and it decides against handing over.
		return fmt.Errorf(
			"%s is one of %d names for the same file and the others could not be read (%w); "+
				"handing this directory over may hand over a file outside it, "+
				"so it is refused; pass --allow-links to hand it over regardless",
			path, names, err)
	}
	for _, other := range others {
		inside, err := within(root, other)
		if err != nil {
			return fmt.Errorf("checking whether %s is inside %s: %w", other, root, err)
		}
		if inside {
			continue
		}
		return fmt.Errorf(
			"%s is also named %s, which is outside %s, and handing this directory over "+
				"would hand that one over too; move it aside, "+
				"or pass --allow-links to hand the directory over regardless",
			path, other, root)
	}
	return nil
}

// within reports whether path is root or lies under it.
func within(root, path string) (bool, error) {
	return pathid.Within(root, path)
}

// finalName is the one spelling Windows itself uses for a path: long names
// rather than their 8.3 abbreviations, the letter case the disk holds, and the
// real volume behind a substituted drive or a symbolic link.
//
// Two spellings of one directory are not equal as strings, and comparing them
// as strings is how a tree was refused for containing a link to itself: a
// build machine's TEMP is handed out as C:\Users\RUNNER~1\..., while the names
// a file answers to come back as C:\Users\runneradmin\.... Everything compared
// here goes through this first.
func finalName(path string) (string, error) {
	return pathid.Canonical(path)
}

// otherNames lists every name the file at path answers to, as full paths.
//
// Windows gives them relative to the volume root, and a hard link cannot cross
// volumes, so the volume of the path that was asked about is the volume of
// them all. That path is spelled out first, or a substituted drive would put
// the wrong letter in front of all of them.
func otherNames(path string) ([]string, error) {
	absolute, err := finalName(path)
	if err != nil {
		return nil, err
	}
	volume := filepath.VolumeName(absolute)

	buffer := make([]uint16, syscall.MAX_LONG_PATH)
	length := uint32(len(buffer))
	handle, _, callErr := procFindFirstFileName.Call(
		uintptr(unsafe.Pointer(w32.UTF16(absolute))), 0,
		uintptr(unsafe.Pointer(&length)), uintptr(unsafe.Pointer(&buffer[0])))
	if handle == uintptr(syscall.InvalidHandle) {
		return nil, fmt.Errorf("listing the names of %s: %w", absolute, callErr)
	}
	defer procFindClose.Call(handle)

	var found []string
	for {
		found = append(found, volume+syscall.UTF16ToString(buffer))
		length = uint32(len(buffer))
		if r, _, _ := procFindNextFileName.Call(handle,
			uintptr(unsafe.Pointer(&length)), uintptr(unsafe.Pointer(&buffer[0]))); r == 0 {
			return found, nil
		}
	}
}

// namesOf is how many names the file at path answers to.
func namesOf(path string) (uint32, error) {
	const readAttributes = 0x80
	const openReparsePoint = 0x00200000
	handle, err := syscall.CreateFile(w32.UTF16(path), readAttributes,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil,
		syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS|openReparsePoint, 0)
	if err != nil {
		return 0, fmt.Errorf("opening %s to count its names: %w", path, err)
	}
	defer func() { _ = syscall.CloseHandle(handle) }()

	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(handle, &info); err != nil {
		return 0, fmt.Errorf("asking how many names %s has: %w", path, err)
	}
	return info.NumberOfLinks, nil
}
