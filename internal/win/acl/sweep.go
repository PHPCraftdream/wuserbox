// Narrowing the tree under a directory that has just been handed over.
//
// Rewriting the directory itself is not enough: an object inside it whose
// permissions are its own no longer hears from above, so whatever Everyone
// or BUILTIN\Users hold there survives the grant and every sandbox that
// holds the tree can write through it. The whole tree is read before any of
// it is changed, so the ordinary reason to stop happens before anything has
// moved.

package acl

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

// sweep takes the changing rights of Everyone and BUILTIN\Users away from
// everything under path that holds them in its own entries.
//
// Rewriting the directory at the top is not enough on its own. Windows hands
// an inheritable entry down to what is below, but handing it down only
// replaces the handed-down part of a child's list and leaves the child's own
// entries alone — so a directory inside a granted one, carrying an entry of
// its own that lets Users write, stayed writable by every other sandbox.
// Measured, with a peer writing there after the grant.
//
// What is below is not pinned the way the top is. Its own entries are
// narrowed and the rest keeps arriving from the top, which is what lets
// taking the grant away reach it later.
func sweep(root string, everyone, users, holder uintptr) error {
	// Read the whole tree before changing any of it. Doing both in one pass
	// left a failure halfway down with part of the tree already rewritten and
	// the grant not written at all: narrowings nobody asked for and no record
	// anywhere that they happened. Reading first is not a promise -- the tree
	// can change underneath between the passes -- but it turns the ordinary
	// reason for stopping, an entry of a kind that cannot be carried over,
	// into a refusal before anything has moved.
	if err := inspect(root); err != nil {
		return err
	}
	return walkTree(root, func(path string, _ fs.DirEntry) error {
		return narrowOwn(path, everyone, users, holder)
	})
}

var (
	procFindFirstFileName = w32.Kernel32.NewProc("FindFirstFileNameW")
	procFindNextFileName  = w32.Kernel32.NewProc("FindNextFileNameW")
	procFindClose         = w32.Kernel32.NewProc("FindClose")
	procGetFinalPathName  = w32.Kernel32.NewProc("GetFinalPathNameByHandleW")
)

// EnvAllowLinks hands the tree over even where a file in it answers to another
// name as well. It is read for the whole process, the way the switch for
// prompts is, so that it survives wuserbox starting itself again with
// administrator rights.
const EnvAllowLinks = "WUSERBOX_ALLOW_LINKS"

// inspect is the reading pass: it asks of every object whether its permissions
// can be carried over, and whether it is the only name for what it points at.
//
// It runs on several goroutines because both questions are answered by the
// disk rather than by this program, and one of them costs an open handle per
// file. Whichever answer comes back wrong first stops the rest: nothing has
// been written at that point, so stopping early costs only the reading that
// was already under way.
func inspect(root string) error {
	counting := os.Getenv(EnvAllowLinks) == ""
	// The one spelling of the tree that the names below can be compared with.
	// Where it cannot be worked out, the given one stands in: that can only
	// refuse a tree it should have allowed, never the other way round.
	spelled := root
	if counting {
		if out, err := finalName(root); err == nil {
			spelled = out
		}
		// The root is asked about here rather than in the walk, which passes
		// over it. Its own entry is written directly rather than inherited,
		// but a file granted by name is still one name among however many the
		// file has, and the others would receive that entry too.
		info, err := os.Lstat(root)
		if err != nil {
			return fmt.Errorf("looking at %s: %w", root, err)
		}
		if err := insideOnly(spelled, root, info.IsDir()); err != nil {
			return err
		}
	}
	return together(root, func(path string, entry fs.DirEntry) error {
		if _, err := readable(path); err != nil {
			return err
		}
		if !counting {
			return nil
		}
		return insideOnly(spelled, path, entry.IsDir())
	})
}

// together runs check over everything under root, on several goroutines, and
// returns the first answer that was an error.
func together(root string, check func(string, fs.DirEntry) error) error {
	type object struct {
		path  string
		entry fs.DirEntry
	}
	objects := make(chan object, 128)
	stop := make(chan struct{})
	var said sync.Once
	var failure error
	var hands sync.WaitGroup
	for i := 0; i < workers(); i++ {
		hands.Add(1)
		go func() {
			defer hands.Done()
			for one := range objects {
				if err := check(one.path, one.entry); err != nil {
					// Whoever is first owns the answer, and closing stop is
					// what lets the walk stop feeding the others.
					said.Do(func() { failure = err; close(stop) })
					return
				}
			}
		}()
	}
	walked := walkTree(root, func(path string, entry fs.DirEntry) error {
		select {
		case objects <- object{path, entry}:
			return nil
		case <-stop:
			return filepath.SkipAll
		}
	})
	close(objects)
	hands.Wait()
	if failure != nil {
		return failure
	}
	return walked
}

// workers is how many of these run at once. The work is waiting on the disk
// rather than thinking, so it is worth more than one, and a bound keeps a tree
// on a slow disk from asking the machine for a thousand open handles at once.
func workers() int {
	const most = 8
	if hands := runtime.NumCPU(); hands < most {
		return hands
	}
	return most
}

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
		if within(root, other) {
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
func within(root, path string) bool {
	root = filepath.Clean(root)
	path = filepath.Clean(path)
	if strings.EqualFold(root, path) {
		return true
	}
	prefix := root
	if !strings.HasSuffix(prefix, string(filepath.Separator)) {
		prefix += string(filepath.Separator)
	}
	return strings.HasPrefix(strings.ToLower(path), strings.ToLower(prefix))
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
	const readAttributes = 0x80
	handle, err := syscall.CreateFile(w32.UTF16(path), readAttributes,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil,
		syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return "", fmt.Errorf("opening %s to spell it out: %w", path, err)
	}
	defer func() { _ = syscall.CloseHandle(handle) }()

	const volumeNameDOS = 0x0
	buffer := make([]uint16, syscall.MAX_LONG_PATH)
	written, _, callErr := procGetFinalPathName.Call(uintptr(handle),
		uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), volumeNameDOS)
	if written == 0 || int(written) >= len(buffer) {
		return "", fmt.Errorf("spelling out %s: %w", path, callErr)
	}
	// Windows answers in its own extended form: \\?\C:\... for a local path,
	// \\?\UNC\server\share\... for one on the network.
	name := syscall.UTF16ToString(buffer[:written])
	if rest, found := strings.CutPrefix(name, `\\?\UNC\`); found {
		return `\\` + rest, nil
	}
	return strings.TrimPrefix(name, `\\?\`), nil
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

// walkTree visits everything under root that a sweep is allowed to touch.
func walkTree(root string, visit func(string, fs.DirEntry) error) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		switch {
		case err != nil:
			// A place that cannot be read is a place nothing can be promised
			// about, so this is not passed over quietly.
			return fmt.Errorf("looking through %s: %w", path, err)
		case path == root:
			return nil // rewritten already, and pinned
		case entry.Type()&os.ModeSymlink != 0:
			return nil // a name for somewhere else, whose permissions are its own
		}
		return visit(path, entry)
	})
}

// readable reports whether an object's permission list can be carried over,
// and is what the first pass asks of every one of them.
func readable(path string) ([]heldEntry, error) {
	var dacl *aclHeader
	var descriptor uintptr
	if r, _, _ := procGetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(w32.UTF16(path))),
		seFileObject, daclInfo, 0, 0, uintptr(unsafe.Pointer(&dacl)), 0,
		uintptr(unsafe.Pointer(&descriptor))); r != 0 {
		return nil, fmt.Errorf("reading the permissions of %s: error %d", path, r)
	}
	defer w32.Free(descriptor)
	if dacl == nil {
		return nil, nil
	}
	held, err := entriesOf(dacl)
	if err != nil {
		return nil, fmt.Errorf("reading the permissions of %s: %w", path, err)
	}
	return held, nil
}

// narrowOwn takes the changing rights of Everyone and BUILTIN\Users out of
// the entries one object holds itself, leaving what it is handed from above
// alone, and hands whatever it took to the owner by name.
//
// The handback is not a courtesy, it is the same rule the granted directory
// itself follows: those two are not who is being kept out, and a grant must
// not cost the person granting it the directory they were granting. One level
// down it was left out, and a directory inside a granted tree that had stopped
// inheriting -- one wuserbox pinned for another sandbox, or one anybody
// protected -- whose only write path was Users went read-only to its owner the
// moment the tree above it was handed over. Measured, by writing a file there
// before and after.
func narrowOwn(path string, everyone, users, holder uintptr) error {
	var dacl *aclHeader
	var descriptor uintptr
	if r, _, _ := procGetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(w32.UTF16(path))),
		seFileObject, daclInfo, 0, 0, uintptr(unsafe.Pointer(&dacl)), 0,
		uintptr(unsafe.Pointer(&descriptor))); r != 0 {
		return fmt.Errorf("reading the permissions of %s: error %d", path, r)
	}
	defer w32.Free(descriptor)

	if dacl == nil {
		// No permission list at all, which Windows reads as everybody having
		// everything -- the widest an object gets. It has no entries, so
		// narrowing them reaches nothing, and a directory inside a granted tree
		// carrying one stayed open to every sandbox on the machine after the
		// tree was handed over. Measured, with a second sandbox writing there.
		return giveAList(path, holder)
	}

	held, err := entriesOf(dacl)
	if err != nil {
		return fmt.Errorf("reading the permissions of %s: %w", path, err)
	}
	var update, handback []explicitAccess
	for _, who := range []uintptr{everyone, users} {
		var kept []explicitAccess
		narrowed := false
		for _, one := range held {
			if one.inherited || !sameSID(one.access.trustee.name, who) {
				continue
			}
			access := one.access
			if access.mode == grantAccess && access.permissions&changing != 0 {
				narrowed = true
				// Handed back with the reach the entry it came from had, so
				// the owner keeps exactly what the crowd was holding here and
				// nothing further.
				handback = append(handback,
					entry(holder, access.permissions&changing, access.inheritance, grantAccess))
				access.permissions &^= changing
				if access.permissions == 0 {
					continue
				}
			}
			// Refusals are carried over untouched: taking one away would
			// widen, which is never what this is for.
			kept = append(kept, access)
		}
		if !narrowed {
			continue
		}
		update = append(update, entry(who, 0, InheritNone, setAccess))
		update = append(update, kept...)
	}
	if len(update) == 0 {
		return nil
	}
	return apply(path, append(update, handback...), false)
}

// StripOwn takes away the entries an object holds itself for one account,
// leaving whatever a directory above hands down to it alone.
//
// It is the other half of pinning a granted directory. Pinning copies what
// the directory was handed into its own list, another sandbox's entry among
// them, and that copy then answers to nobody: taking the other sandbox's
// grant away rewrites the directory it was granted, which this one no longer
// hears from. So the account's access here has to be taken away by name.
func StripOwn(path, account string) error {
	value, err := sid.Parse(account)
	if err != nil {
		return err
	}
	var dacl *aclHeader
	var descriptor uintptr
	if r, _, _ := procGetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(w32.UTF16(path))),
		seFileObject, daclInfo, 0, 0, uintptr(unsafe.Pointer(&dacl)), 0,
		uintptr(unsafe.Pointer(&descriptor))); r != 0 {
		return fmt.Errorf("reading the permissions of %s: error %d", path, r)
	}
	defer w32.Free(descriptor)

	held, err := entriesOf(dacl)
	if err != nil {
		return fmt.Errorf("reading the permissions of %s: %w", path, err)
	}
	for _, one := range held {
		if one.inherited || !sameSID(one.access.trustee.name, value) {
			continue
		}
		// Only what the object holds itself is cleared. What it is handed from
		// above goes when the directory above is rewritten, which is the
		// caller's next move anyway.
		return apply(path, []explicitAccess{entry(value, 0, InheritNone, setAccess)}, false)
	}
	return nil
}
