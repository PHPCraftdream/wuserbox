// The thin profile wuserbox builds for a sandbox itself, as opposed to
// profile.go's: an empty registry hive and three folders under a directory
// of our own, told to Windows in place of the one it would build unattended
// in C:\Users on the account's first logon.
//
// A hive RegLoadAppKey creates comes out granting Everyone full control.
// tightenHive replaces that list before the hive is ever loaded for real --
// loading it under a temporary name nothing else can reach, rather than
// after the first run loads it as HKEY_CURRENT_USER, which measured an
// outsider writing into a sandbox's own registry in the meantime.

package account

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

const hkeyUsers = 0x80000003

// MakeProfile builds the directory a sandbox's own thin profile lives in:
// the three subdirectories a shell expects, a permission list naming only
// account, the machine owner, SYSTEM and the administrators, and an empty
// registry hive under it whose own list is narrower still -- account,
// SYSTEM and the administrators, the owner left off on purpose, because the
// directory's own entry for the owner is what removal relies on and the
// hive never has to be reached to use it.
//
// Safe to call again on a profile already built: the directory and its
// subdirectories are made idempotently, and a hive already on disk is left
// exactly as it was tightened the first time. This deliberately does not
// migrate an older hive to a new ACL shape; removing and recreating the
// sandbox is the upgrade path so existing registry data is not rewritten
// under a different security descriptor. Requires administrator
// rights: tightening a hive needs SE_BACKUP_NAME and SE_RESTORE_NAME, which
// only an elevated token can turn on.
func MakeProfile(dir string, account sid.Value) error {
	// The profile's own directory first, and by name: everything above it
	// belongs to whoever is running this, and a sandbox cannot reach into it
	// -- it holds its profile outright but has no write access to the
	// directory that holds the profile, so it cannot put anything in its own
	// place.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("making the profile directory: %w", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("opening the profile directory: %w", err)
	}
	defer func() { _ = root.Close() }()
	for _, sub := range []string{`AppData\Local`, `AppData\Roaming`, "Temp"} {
		if err := makeInside(root, sub); err != nil {
			return err
		}
	}
	if err := acl.ProtectFull(dir, account.String()); err != nil {
		return fmt.Errorf("permissioning the profile directory: %w", err)
	}
	hive := filepath.Join(dir, "NTUSER.DAT")
	if _, err := os.Stat(hive); err == nil {
		return nil
	}
	return makeHive(hive, account)
}

// makeInside builds one of the profile's own subdirectories, one component at
// a time, through a root pinned on the profile so that no part of the path
// can lead out of it.
//
// A sandbox owns its own profile and needs no privilege to put a junction in
// it. Plain MkdirAll follows one: measured, with a junction at AppData
// pointing somewhere else, the missing directories were created inside *that*
// -- by this call, which runs elevated and as the machine's owner. It is the
// same confused deputy the profile copying was taught to refuse, one call
// earlier, and the permissions written a moment later would have been written
// there too if Windows propagated them through a junction, which -- measured
// -- it does not.
//
// Where something that is not a directory sits exactly where a directory
// belongs, refusing is not enough: the name would be pinned for good and
// every later --init would fail on it. It is cleared first, which is safe for
// the same reason the refusal is -- removing a link is not following it.
func makeInside(root *os.Root, name string) error {
	path := ""
	for _, part := range strings.Split(name, `\`) {
		path = filepath.Join(path, part)
		if err := clearWhatIsNotADirectory(root, path); err != nil {
			return err
		}
		if err := root.Mkdir(path, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("making %s inside the profile: %w", path, err)
		}
	}
	return nil
}

// clearWhatIsNotADirectory removes whatever stands where a directory belongs.
// Lstat reports the link rather than what it points at, and Remove takes the
// link away rather than what is behind it, so neither of them follows the one
// thing this exists to stop being followed.
func clearWhatIsNotADirectory(root *os.Root, name string) error {
	info, err := root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil // nothing there yet, which is the ordinary case
	}
	if err != nil {
		// Anything else is worth passing on. A name that cannot even be looked
		// at is not a name to go on and create something under.
		return fmt.Errorf("looking at %s inside the profile: %w", name, err)
	}
	if info.IsDir() {
		return nil // already the directory it should be
	}
	if err := root.Remove(name); err != nil {
		return fmt.Errorf("clearing %s, which is in the way and is not a directory: %w", name, err)
	}
	return nil
}

// makeHive builds the empty hive beside its final name and moves it there
// only once its permissions have been narrowed, so NTUSER.DAT never exists
// except finished.
//
// The two steps need different rights -- creating a hive needs none,
// narrowing one needs SE_BACKUP_NAME and SE_RESTORE_NAME -- so a run
// without them gets through the first and fails the second. Written
// straight to NTUSER.DAT, what that leaves behind is a hive still granting
// Everyone full control, and the next run, elevated or not, sees the file,
// takes the profile for built and never narrows it: exactly the hole the
// narrowing exists to close, held open by the attempt to close it.
func makeHive(hive string, account sid.Value) error {
	partial := hive + ".partial"
	if err := os.Remove(partial); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clearing a half-made profile hive: %w", err)
	}
	if err := createEmptyHive(partial); err != nil {
		return err
	}
	if err := tightenHive(partial, account); err != nil {
		_ = os.Remove(partial)
		return err
	}
	if err := os.Rename(partial, hive); err != nil {
		_ = os.Remove(partial)
		return fmt.Errorf("putting the profile hive in place: %w", err)
	}
	return nil
}

// createEmptyHive makes an empty registry hive at path with RegLoadAppKey,
// the only ordinary way to create a hive file that is not already loaded
// somewhere -- RegCreateKey only ever writes into one already mounted in
// the registry namespace -- and, measured, the one that works without
// administrator rights.
func createEmptyHive(path string) error {
	const keyAllAccess = 0xF003F
	var key uintptr
	if r, _, _ := procRegLoadAppKey.Call(uintptr(unsafe.Pointer(w32.UTF16(path))),
		uintptr(unsafe.Pointer(&key)), keyAllAccess, 0, 0); r != 0 {
		return fmt.Errorf("creating the profile hive: error %d", r)
	}
	procRegCloseKey.Call(key)
	return nil
}

// tightenHive replaces the Everyone-full-control list createEmptyHive's
// call leaves behind with one naming only account, SYSTEM and the
// administrators.
func tightenHive(path string, account sid.Value) error {
	if err := enablePrivilege("SeBackupPrivilege"); err != nil {
		return err
	}
	if err := enablePrivilege("SeRestorePrivilege"); err != nil {
		return err
	}
	// Named per process: two sandboxes initialized at once would otherwise
	// collide here, and RegLoadKey refuses a name already in use rather
	// than waiting for it.
	tempName := fmt.Sprintf(`wuserbox-tighten-hive-%d`, os.Getpid())
	if r, _, _ := procRegLoadKey.Call(hkeyUsers, uintptr(unsafe.Pointer(w32.UTF16(tempName))),
		uintptr(unsafe.Pointer(w32.UTF16(path)))); r != 0 {
		return fmt.Errorf("loading the profile hive to permission it: error %d", r)
	}
	defer procRegUnLoadKey.Call(hkeyUsers, uintptr(unsafe.Pointer(w32.UTF16(tempName))))

	const writeDac = 0x40000
	var key uintptr
	if r, _, _ := procRegOpenKeyEx.Call(hkeyUsers, uintptr(unsafe.Pointer(w32.UTF16(tempName))), 0,
		writeDac, uintptr(unsafe.Pointer(&key))); r != 0 {
		return fmt.Errorf("opening the loaded hive to permission it: error %d", r)
	}
	defer procRegCloseKey.Call(key)

	return setHiveSecurity(key, account)
}

// EXPLICIT_ACCESS_W and its trustee, the shape SetEntriesInAclW and
// SetSecurityInfo both need. win/acl carries the same layout for files;
// this copy is registry-only and kept to itself rather than exported,
// because the two never build a list together.
type trustee struct {
	multipleTrustee uintptr
	multipleOp      int32
	form            int32
	kind            int32
	name            uintptr
}

type explicitAccess struct {
	permissions uint32
	mode        int32
	inheritance uint32
	trustee     trustee
}

var (
	procRegLoadAppKey   = w32.Advapi32.NewProc("RegLoadAppKeyW")
	procRegLoadKey      = w32.Advapi32.NewProc("RegLoadKeyW")
	procRegUnLoadKey    = w32.Advapi32.NewProc("RegUnLoadKeyW")
	procSetSecurityInfo = w32.Advapi32.NewProc("SetSecurityInfo")
	procSetEntriesInAcl = w32.Advapi32.NewProc("SetEntriesInAclW")
)

// setHiveSecurity replaces the loaded hive's own permission list outright:
// SetEntriesInAclW is asked to build a list from nothing (current is 0), so
// nothing already on it -- Everyone among it -- survives into the result.
func setHiveSecurity(key uintptr, account sid.Value) error {
	const (
		keyAllAccess = 0xF003F
		trusteeIsSID = 0
		// TRUSTEE_IS_UNKNOWN. The kind is not read where the form is a SID,
		// which is every entry below; saying unknown rather than guessing
		// keeps it from claiming something that was never checked.
		trusteeIsUnknown = 0
		grantAccess      = 1
		// SUB_CONTAINERS_ONLY_INHERIT: CONTAINER_INHERIT_ACE on the entry,
		// which on a registry key grants the key it is set on and is
		// inherited by every key below it, by each of those onward. The
		// hive is empty when this list is written -- createEmptyHive makes
		// a root and nothing else -- so what the root offers to inherit is
		// the only list keys the first logon creates, Software among them,
		// are born with; without it, measured 2026-09-17 on a CI runner,
		// they took their creator's default list instead, and the profile
		// service's does not name the account. docs/investigations/
		// a-hive-per-slot.md. The spelling matters: an OBJECT_INHERIT-only
		// entry is inherited by container children inherit-only, which
		// would grant them nothing while looking like inheritance, and
		// INHERIT_ONLY would take the grant off the root, which the
		// account writes to.
		subContainersOnlyInherit = 0x2
	)
	who := func(p uintptr) trustee {
		return trustee{form: trusteeIsSID, kind: trusteeIsUnknown, name: p}
	}
	systemSID, err := sid.Parse(sid.System)
	if err != nil {
		return err
	}
	adminSID, err := sid.Parse(sid.Administrators)
	if err != nil {
		return err
	}
	entries := []explicitAccess{
		{permissions: keyAllAccess, mode: grantAccess, inheritance: subContainersOnlyInherit, trustee: who(uintptr(unsafe.Pointer(&account[0])))},
		{permissions: keyAllAccess, mode: grantAccess, inheritance: subContainersOnlyInherit, trustee: who(systemSID)},
		{permissions: keyAllAccess, mode: grantAccess, inheritance: subContainersOnlyInherit, trustee: who(adminSID)},
	}
	var newACL uintptr
	r, _, _ := procSetEntriesInAcl.Call(uintptr(len(entries)), uintptr(unsafe.Pointer(&entries[0])),
		0, uintptr(unsafe.Pointer(&newACL)))
	runtime.KeepAlive(account)
	if r != 0 {
		return fmt.Errorf("building the hive's permissions: error %d", r)
	}
	defer w32.Free(newACL)

	const (
		seRegistryKey                    = 4
		daclSecurityInformation          = 0x4
		protectedDaclSecurityInformation = 0x80000000
	)
	if r, _, _ := procSetSecurityInfo.Call(key, seRegistryKey,
		daclSecurityInformation|protectedDaclSecurityInformation, 0, 0, newACL, 0); r != 0 {
		return fmt.Errorf("permissioning the hive: error %d", r)
	}
	return nil
}

// LUID and TOKEN_PRIVILEGES, the shape LookupPrivilegeValueW and
// AdjustTokenPrivileges need for exactly one privilege.
type luid struct {
	low  uint32
	high int32
}

type luidAndAttributes struct {
	luid       luid
	attributes uint32
}

type tokenPrivileges struct {
	count      uint32
	privileges [1]luidAndAttributes
}

var (
	procLookupPrivilegeValue  = w32.Advapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPrivileges = w32.Advapi32.NewProc("AdjustTokenPrivileges")
)

const sePrivilegeEnabled = 0x2

// enablePrivilege turns on a privilege this process's token already holds
// but not enabled by default: SeBackupPrivilege and SeRestorePrivilege,
// which RegLoadKey needs and which an elevated administrator token carries
// disabled until something asks for them.
func enablePrivilege(name string) error {
	var token syscall.Token
	if err := syscall.OpenProcessToken(syscall.Handle(^uintptr(0)),
		syscall.TOKEN_ADJUST_PRIVILEGES|syscall.TOKEN_QUERY, &token); err != nil {
		return fmt.Errorf("opening the process token: %w", err)
	}
	defer token.Close()

	var id luid
	if r, _, err := procLookupPrivilegeValue.Call(0, uintptr(unsafe.Pointer(w32.UTF16(name))),
		uintptr(unsafe.Pointer(&id))); r == 0 {
		return fmt.Errorf("looking up %s: %w", name, err)
	}
	priv := tokenPrivileges{count: 1, privileges: [1]luidAndAttributes{{luid: id, attributes: sePrivilegeEnabled}}}
	r, _, err := procAdjustTokenPrivileges.Call(uintptr(token), 0, uintptr(unsafe.Pointer(&priv)), 0, 0, 0)
	if r == 0 {
		return fmt.Errorf("enabling %s: %w", name, err)
	}
	// AdjustTokenPrivileges reports success even when a privilege the token
	// never held was silently skipped; this is the one case that must not
	// pass for success, since it means the tightening below has admin
	// rights but not the two rights it specifically needs.
	const errNotAllAssigned = 1300
	var errno syscall.Errno
	if errors.As(err, &errno) && errno == errNotAllAssigned {
		return fmt.Errorf("enabling %s: not held by this token (administrator required)", name)
	}
	return nil
}

// profileListRoot is where Windows records, per SID, where a profile was
// put -- the same key profile.go's own profileList constant names, kept
// separate because that one already carries a trailing backslash of its
// own and the two files never need each other's copy.
const (
	profileListRoot          = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\`
	profileServiceReferences = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileService\References\`
	regExpandSZ              = 2
	regBinary                = 3
)

// RegisterProfile tells Windows the profile at dir is already there, for
// account's SID, so it copies nothing and builds nothing of its own in
// C:\Users on the account's first logon. All three values below are needed
// together: measured with fewer, Windows ignored the entry outright and
// rebuilt a full profile regardless of what was already on disk. Requires
// administrator rights: the key lives under HKEY_LOCAL_MACHINE.
func RegisterProfile(account sid.Value, dir string) error {
	sidText := account.String()
	var key uintptr
	if r, _, _ := procRegCreateKeyEx.Call(hkeyLocalMachine,
		uintptr(unsafe.Pointer(w32.UTF16(profileListRoot+sidText))), 0, 0, 0, keySetValue, 0,
		uintptr(unsafe.Pointer(&key)), 0); r != 0 {
		return fmt.Errorf("opening the ProfileList entry for %s: error %d", sidText, r)
	}
	defer procRegCloseKey.Call(key)

	wide, err := syscall.UTF16FromString(dir)
	if err != nil {
		return fmt.Errorf("the profile directory cannot be written as a path: %w", err)
	}
	r, _, _ := procRegSetValueEx.Call(key, uintptr(unsafe.Pointer(w32.UTF16("ProfileImagePath"))), 0,
		regExpandSZ, uintptr(unsafe.Pointer(&wide[0])), uintptr(len(wide)*2))
	runtime.KeepAlive(wide)
	if r != 0 {
		return fmt.Errorf("writing ProfileImagePath for %s: error %d", sidText, r)
	}
	r, _, _ = procRegSetValueEx.Call(key, uintptr(unsafe.Pointer(w32.UTF16("Sid"))), 0,
		regBinary, uintptr(unsafe.Pointer(&account[0])), uintptr(len(account)))
	runtime.KeepAlive(account)
	if r != 0 {
		return fmt.Errorf("writing Sid for %s: error %d", sidText, r)
	}
	var state uint32 // 0: the profile is neither mandatory nor already loaded
	if r, _, _ := procRegSetValueEx.Call(key, uintptr(unsafe.Pointer(w32.UTF16("State"))), 0,
		regDword, uintptr(unsafe.Pointer(&state)), 4); r != 0 {
		return fmt.Errorf("writing State for %s: error %d", sidText, r)
	}
	return nil
}

var procRegDeleteKey = w32.Advapi32.NewProc("RegDeleteKeyW")

// RemoveProfileServiceReference clears the entry the profile service keeps
// for account's SID alongside ProfileList -- a second record of the same
// profile that DeleteProfile does not reach. Whether Windows really leaves
// one behind for a sandbox is not something this repository has measured;
// clearing a key that may not be there costs nothing, and a reference that
// was never made is not an error. Requires administrator rights, the same
// as writing the entry it clears.
func RemoveProfileServiceReference(account sid.Value) error {
	sidText := account.String()
	if r, _, _ := procRegDeleteKey.Call(hkeyLocalMachine,
		uintptr(unsafe.Pointer(w32.UTF16(profileServiceReferences+sidText)))); r != 0 && r != errFileNotFound {
		return fmt.Errorf("clearing the profile service reference for %s: error %d", sidText, r)
	}
	return nil
}
