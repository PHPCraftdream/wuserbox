// Package pathid asks Windows which directory entries a path names.
package pathid

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var procGetFinalPathName = w32.Kernel32.NewProc("GetFinalPathNameByHandleW")

var (
	procFindFirstFileName = w32.Kernel32.NewProc("FindFirstFileNameW")
	procFindNextFileName  = w32.Kernel32.NewProc("FindNextFileNameW")
	procFindClose         = w32.Kernel32.NewProc("FindClose")
)

// fileID is the identity Windows assigns to a directory entry. The volume is
// part of it because a file index is only unique within one volume.
type fileID struct {
	volume uint32
	high   uint32
	low    uint32
}

// Canonical returns the spelling Windows resolves for an existing path. In
// particular, it retains the volume's distinction between names such as K and
// the Kelvin sign; Go's Unicode folding must not decide a filesystem boundary.
func Canonical(path string) (string, error) {
	const readAttributes = 0x80
	handle, err := syscall.CreateFile(w32.UTF16(path), readAttributes,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil,
		syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return "", fmt.Errorf("opening %s to resolve its directory entry: %w", path, err)
	}
	defer func() { _ = syscall.CloseHandle(handle) }()

	const volumeNameDOS = 0x0
	buffer := make([]uint16, syscall.MAX_LONG_PATH)
	written, _, callErr := procGetFinalPathName.Call(uintptr(handle),
		uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), volumeNameDOS)
	if written == 0 || int(written) >= len(buffer) {
		return "", fmt.Errorf("resolving %s: %w", path, callErr)
	}
	name := syscall.UTF16ToString(buffer[:written])
	if rest, found := strings.CutPrefix(name, `\\?\UNC\`); found {
		return `\\` + rest, nil
	}
	return strings.TrimPrefix(name, `\\?\`), nil
}

// Key returns a stable identity key for a path. Existing entries use the
// spelling Windows resolved from the directory entry. A missing path has no
// directory-entry identity, so only ASCII case is folded in its fallback;
// non-ASCII names stay distinct rather than being merged by a Unicode fold.
func Key(path string) (string, error) {
	if canonical, err := Canonical(path); err == nil {
		return "entry:" + canonical, nil
	} else if _, statErr := os.Stat(path); statErr == nil {
		return "", fmt.Errorf("resolving existing path %s: %w", path, err)
	} else if !os.IsNotExist(statErr) {
		return "", fmt.Errorf("checking %s: %w", path, statErr)
	}
	return "missing:" + asciiFold(filepath.Clean(path)), nil
}

// Within reports whether path is root or is below root according to the
// filesystem's directory-entry identities. It follows ordinary path aliases,
// but does not let a Unicode string fold turn a sibling into a child.
func Within(root, path string) (bool, error) {
	rootInfo, err := os.Stat(root)
	if err != nil {
		return false, fmt.Errorf("inspecting %s: %w", root, err)
	}
	// A file has no descendants. Comparing file IDs here would mistake an
	// external hard-link name for the named directory entry, and would let a
	// single-file grant escape through that second name. Canonical resolves the
	// actual directory-entry spelling, so aliases still work while hard links
	// do not.
	if !rootInfo.IsDir() {
		rootName, err := Canonical(root)
		if err != nil {
			return false, err
		}
		pathName, err := Canonical(path)
		if err != nil {
			return false, err
		}
		return rootName == pathName, nil
	}
	wanted, err := of(root)
	if err != nil {
		return false, err
	}
	current := filepath.Clean(path)
	for {
		id, err := of(current)
		if err != nil {
			return false, err
		}
		if id == wanted {
			return true, nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return false, nil
		}
		current = parent
	}
}

// Same reports whether two existing paths name the same filesystem entry.
func Same(first, second string) (bool, error) {
	a, err := of(first)
	if err != nil {
		return false, err
	}
	b, err := of(second)
	if err != nil {
		return false, err
	}
	return a == b, nil
}

// Names returns every directory entry Windows has for the file at path.
// Hard links are names for one file object, so checking only the name being
// copied to is not enough before opening it for write.
func Names(path string) ([]string, error) {
	absolute, err := Canonical(path)
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
	defer func() { _, _, _ = procFindClose.Call(handle) }()

	var names []string
	for {
		names = append(names, volume+syscall.UTF16ToString(buffer[:length]))
		length = uint32(len(buffer))
		if r, _, _ := procFindNextFileName.Call(
			handle, uintptr(unsafe.Pointer(&length)), uintptr(unsafe.Pointer(&buffer[0]))); r == 0 {
			return names, nil
		}
	}
}

// OutsideNames returns hard-link names for path that are not directory
// entries below root. A file with only one name returns no names. The caller
// can therefore allow links wholly inside its protected tree while refusing
// a link that would make a write reach an external file.
func OutsideNames(root, path string) ([]string, error) {
	names, err := Names(path)
	if err != nil {
		return nil, err
	}
	var outside []string
	for _, name := range names {
		inside, err := Within(root, name)
		if err != nil {
			return nil, fmt.Errorf("checking whether hard-link name %s is inside %s: %w", name, root, err)
		}
		if !inside {
			outside = append(outside, name)
		}
	}
	return outside, nil
}

func of(path string) (fileID, error) {
	const readAttributes = 0x80
	handle, err := syscall.CreateFile(w32.UTF16(path), readAttributes,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil,
		syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return fileID{}, fmt.Errorf("opening %s to inspect its directory entry: %w", path, err)
	}
	defer func() { _ = syscall.CloseHandle(handle) }()
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(handle, &info); err != nil {
		return fileID{}, fmt.Errorf("inspecting %s: %w", path, err)
	}
	return fileID{
		volume: info.VolumeSerialNumber,
		high:   info.FileIndexHigh,
		low:    info.FileIndexLow,
	}, nil
}

// asciiFold preserves the case-insensitive behavior useful for old records
// without pretending that Go's Unicode equivalence is NTFS's equivalence.
func asciiFold(path string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, path)
}
