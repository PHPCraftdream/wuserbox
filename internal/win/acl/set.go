// Writing a permission list onto a path: replacing what one account
// holds, taking it away, refusing it outright, and replacing the whole
// list with one of our own that stops listening to the directory above.

package acl

import (
	"fmt"
	"os"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/group"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var (
	procGetNamedSecurityInfo = w32.Advapi32.NewProc("GetNamedSecurityInfoW")
	procSetNamedSecurityInfo = w32.Advapi32.NewProc("SetNamedSecurityInfoW")
	procSetEntriesInAcl      = w32.Advapi32.NewProc("SetEntriesInAclW")
)

const (
	seFileObject = 1
	daclInfo     = 4
	grantAccess  = 1
	// setAccess replaces everything an account holds, refusals included.
	// Revoking does not: it removes permissions and leaves refusals behind,
	// and a refusal outlives the grant it was meant to accompany.
	setAccess    = 2
	denyAccess   = 3
	revokeAccess = 4
)

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

// publish is the step that writes a finished list to the file system. Tests
// replace it to count how often one call to Set reaches the disk.
var publish = apply

// Set replaces the entries for account with the ones given. All of them go in
// a single update, so one account can hold several entries that differ only in
// how they are inherited.
//
// The update is also the only one: nothing is written to the file system until
// the whole list is built. Clearing the account in its own update first would
// leave a moment with neither the old entries nor the new ones, and a directory
// held read-only inside a writable parent would be writable through inheritance
// for exactly as long as that moment lasts.
//
// Windows pushes inheritable entries down to existing children as well, so a
// permission set on a directory reaches the files already in it.
func Set(path, account string, entries []ACE) error {
	if len(entries) == 0 {
		return fmt.Errorf("no access entries given for %s", path)
	}
	value, err := sid.Parse(account)
	if err != nil {
		return err
	}
	return publish(path, listFor(value, entries), false)
}

// listFor builds the whole update for one account, in the order Windows
// applies it.
//
// The list opens by replacing everything the account holds, so stale entries
// cannot survive. It replaces rather than revokes: revoking takes away
// permissions and leaves refusals in place, so an account narrowed to
// read-only and then widened again would stay refused by an entry nobody
// asked to keep.
//
// Refusals come next and permissions last: Windows reads the finished list in
// order, and a refusal placed after a permission would never be reached.
func listFor(value uintptr, entries []ACE) []explicitAccess {
	list := []explicitAccess{entry(value, 0, InheritNone, setAccess)}
	for _, e := range entries {
		if e.Refuse {
			list = append(list, entry(value, e.Access, e.Inheritance, denyAccess))
		}
	}
	for _, e := range entries {
		if !e.Refuse {
			list = append(list, entry(value, e.Access, e.Inheritance, grantAccess))
		}
	}
	return list
}

func entry(account uintptr, access, inheritance uint32, mode int32) explicitAccess {
	const trusteeIsSID, trusteeIsUnknown = 0, 5
	return explicitAccess{
		permissions: access,
		mode:        mode,
		inheritance: inheritance,
		trustee:     trustee{form: trusteeIsSID, kind: trusteeIsUnknown, name: account},
	}
}

// apply writes a finished list to the file system.
//
// whole says the list is the entire permission list of the object rather than
// a change to it: nothing is merged into what is already there, and the
// result is written as the object's own, so no directory above it hands
// anything down to it afterwards. Isolate needs that — merging would bring
// the inherited entries it just rewrote straight back, still inherited, and
// still handing out what they were rewritten to take away.
func apply(path string, list []explicitAccess, whole bool) error {
	const protectedDacl = 0x80000000
	information, current := uintptr(daclInfo), uintptr(0)
	if whole {
		information |= protectedDacl
	} else {
		var descriptor uintptr
		if r, _, _ := procGetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(w32.UTF16(path))),
			seFileObject, daclInfo, 0, 0, uintptr(unsafe.Pointer(&current)), 0,
			uintptr(unsafe.Pointer(&descriptor))); r != 0 {
			return fmt.Errorf("reading the permissions of %s: error %d", path, r)
		}
		defer w32.Free(descriptor)
	}

	var updated uintptr
	if r, _, _ := procSetEntriesInAcl.Call(uintptr(len(list)), uintptr(unsafe.Pointer(&list[0])),
		current, uintptr(unsafe.Pointer(&updated))); r != 0 {
		return fmt.Errorf("building the permissions for %s: error %d", path, r)
	}
	defer w32.Free(updated)

	if r, _, _ := procSetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(w32.UTF16(path))),
		seFileObject, information, 0, 0, updated, 0); r != 0 {
		if r == 5 {
			return fmt.Errorf("changing the permissions of %s: access denied, you do not own it", path)
		}
		return fmt.Errorf("changing the permissions of %s: error %d", path, r)
	}
	return nil
}

// Deny adds an explicit refusal for account on path. Windows checks refusals
// before permissions, so this overrides anything inherited from a parent
// directory.
func Deny(path, account string, access uint32) error {
	value, err := sid.Parse(account)
	if err != nil {
		return err
	}
	return apply(path, []explicitAccess{entry(value, access, InheritNone, denyAccess)}, false)
}

// Remove drops every entry for account from the permissions of path,
// permissions and refusals alike. Replacing is what does that: revoking
// removes only the permissions.
func Remove(path, account string) error {
	value, err := sid.Parse(account)
	if err != nil {
		return err
	}
	return apply(path, []explicitAccess{entry(value, 0, InheritNone, setAccess)}, false)
}

var (
	procStringToSecurityDescriptor = w32.Advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procGetSecurityDescriptorDacl  = w32.Advapi32.NewProc("GetSecurityDescriptorDacl")
)

// Protect replaces the permissions of path with a fixed list that no sandbox
// can change or delete: full control for the current user, the system and
// administrators, and reading for the group every sandbox's restricted list
// carries. Inheritance is switched off, so a permission granted on a parent
// directory can never reach this object afterwards.
//
// Reading is not part of what this refuses, and the identity it is given to
// is the whole of the care here. A file naming only the owner, the system and
// administrators is unreadable to a sandbox as well as unwritable, and a
// sandbox that cannot read ~/.gitconfig is one most tools will not start in.
// Everyone and BUILTIN\Users would fix that and give it away: this is applied
// to .ssh, .aws, .netrc and the rest of them, so on a machine with a second
// person's account it would hand that account the owner's private keys.
// group.ReadGroup is joined by sandbox accounts and nothing else, so it
// reaches exactly what wuserbox started and no other login on the machine.
//
// So a sandbox reads these files and cannot change or delete them. That is
// the deliberate shape of it, and it is worth saying plainly rather than
// leaving to be inferred: the secret in ~/.ssh is readable from inside a
// sandbox, and what this protects is that it cannot be rewritten, replaced
// or destroyed there.
//
// Where that group does not exist yet, nothing takes its place. A protected
// file the sandbox cannot read is the safe half of that choice.
func Protect(path string) error {
	user, err := sid.CurrentUser()
	if err != nil {
		return err
	}
	inheritance := inheritanceFor(path)
	text := fmt.Sprintf("D:PAI(A;%s;GA;;;%s)(A;%s;GA;;;SY)(A;%s;GA;;;BA)",
		inheritance, user, inheritance, inheritance)
	if reader, err := sid.Lookup(group.ReadGroup); err == nil {
		text += fmt.Sprintf("(A;%s;0x%x;;;%s)", inheritance, AccessReadExecute, reader.String())
	}
	return setProtectedSDDL(path, text)
}

// ProtectFull replaces the permissions of path with a fixed list granting
// full control to the current user, the system, administrators and every
// account named -- unlike Protect, every principal here may change the
// object, not only read it. Built for a sandbox's own profile directory:
// the sandbox account has to write into it as itself, and the machine
// owner's own entry is what lets the directory be deleted later without an
// elevated prompt, the same reasoning Protect's own owner entry rests on.
func ProtectFull(path string, accounts ...string) error {
	user, err := sid.CurrentUser()
	if err != nil {
		return err
	}
	inheritance := inheritanceFor(path)
	text := fmt.Sprintf("D:PAI(A;%s;GA;;;%s)(A;%s;GA;;;SY)(A;%s;GA;;;BA)",
		inheritance, user, inheritance, inheritance)
	for _, account := range accounts {
		text += fmt.Sprintf("(A;%s;GA;;;%s)", inheritance, account)
	}
	return setProtectedSDDL(path, text)
}

// inheritanceFor says whether entries built for path should propagate to
// what is inside it -- only true for a directory, since a file has nothing
// to propagate to.
func inheritanceFor(path string) string {
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return "OICI"
	}
	return ""
}

// setProtectedSDDL builds the security descriptor text describes and writes
// it as path's whole permission list, with inheritance from anything above
// switched off.
func setProtectedSDDL(path, text string) error {
	var descriptor uintptr
	if r, _, err := procStringToSecurityDescriptor.Call(uintptr(unsafe.Pointer(w32.UTF16(text))), 1,
		uintptr(unsafe.Pointer(&descriptor)), 0); r == 0 {
		return fmt.Errorf("building protected permissions: %w", err)
	}
	defer w32.Free(descriptor)

	var present, defaulted int32
	var dacl uintptr
	if r, _, err := procGetSecurityDescriptorDacl.Call(descriptor, uintptr(unsafe.Pointer(&present)),
		uintptr(unsafe.Pointer(&dacl)), uintptr(unsafe.Pointer(&defaulted))); r == 0 {
		return fmt.Errorf("reading protected permissions: %w", err)
	}
	const protectedDacl = 0x80000000
	if r, _, _ := procSetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(w32.UTF16(path))),
		seFileObject, daclInfo|protectedDacl, 0, 0, dacl, 0); r != 0 {
		return fmt.Errorf("protecting %s: error %d", path, r)
	}
	return nil
}
