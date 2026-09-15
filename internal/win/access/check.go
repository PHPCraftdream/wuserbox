package access

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/token"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var (
	procGetNamedSecurityInfo = w32.Advapi32.NewProc("GetNamedSecurityInfoW")
	procAccessCheck          = w32.Advapi32.NewProc("AccessCheck")
	procMapGenericMask       = w32.Advapi32.NewProc("MapGenericMask")
	procImpersonate          = w32.Advapi32.NewProc("ImpersonateLoggedOnUser")
	procRevertToSelf         = w32.Advapi32.NewProc("RevertToSelf")
	procDuplicateTokenEx     = w32.Advapi32.NewProc("DuplicateTokenEx")
)

// Result is the answer to one question about one path.
type Result struct {
	Path      string    `json:"path"`
	Operation Operation `json:"operation"`
	// Checked is the object the answer is about. For creating something that
	// does not exist yet, it is the directory that would hold it.
	Checked string `json:"checked"`
	Allowed bool   `json:"allowed"`
	// Reason says why, in a few words.
	Reason string `json:"reason"`
}

// Check asks Windows whether a sandbox could perform an operation.
//
// The answer comes from a token carrying the sandbox's group, not from the
// account a run actually uses -- logging that account on would need its
// password, and this has to be answerable without one. It is the same answer
// either way: every permission wuserbox writes names the group, and the
// account's only way to any of them is being a member of it.
//
// Nothing is opened for writing and nothing is created, so asking is free of
// consequences.
func Check(group string, path string, operation Operation) (Result, error) {
	result := Result{Path: path, Operation: operation, Checked: path}

	target := path
	if _, err := os.Stat(path); err != nil {
		if operation != Create {
			return result, fmt.Errorf("%s does not exist", path)
		}
	}
	if operation.onParent() {
		if info, err := os.Stat(path); err != nil || !info.IsDir() {
			target = filepath.Dir(path)
		}
	}
	result.Checked = target

	descriptor, err := securityOf(target)
	if err != nil {
		return result, err
	}
	defer w32.Free(descriptor)

	restricted, err := token.Restricted(group)
	if err != nil {
		return result, err
	}
	defer restricted.Close()

	impersonation, err := impersonationCopy(restricted)
	if err != nil {
		return result, err
	}
	defer impersonation.Close()

	granted, allowed, err := accessCheck(impersonation, descriptor, operation.mask())
	if err != nil {
		return result, err
	}
	result.Allowed = allowed
	through := ""
	// Deleting has two doors. Windows lets something go when the thing itself
	// may be deleted, or when the directory holding it may have things
	// removed from it, and an answer that knew only the first would promise a
	// refusal that does not happen.
	if !allowed && operation == Delete {
		throughParent, err := deleteThroughParent(group, target)
		if err != nil {
			return result, fmt.Errorf("asking whether %s may be removed from the directory holding it: %w",
				target, err)
		}
		if throughParent {
			result.Allowed = true
			through = "the directory holding it lets the sandbox remove what is inside"
		}
	}
	// The permission list is not the whole story, and it is the last word on
	// neither door. A file marked read-only is refused by the file system
	// whatever any permission says, so the mark is applied to the answer both
	// doors arrive at rather than to one of them.
	if result.Allowed && operation.changes() && readOnlyAttribute(target) {
		result.Allowed = false
		result.Reason = "the permissions allow it, but the file is marked read-only"
		return result, nil
	}
	if through != "" {
		result.Reason = through
		return result, nil
	}
	if allowed {
		result.Reason = "the sandbox has a permission that covers it"
	} else {
		result.Reason = fmt.Sprintf("no permission for the sandbox covers it (granted %#x of %#x)",
			granted, operation.mask())
	}
	return result, nil
}

// securityOf reads the whole security description of a path.
func securityOf(path string) (uintptr, error) {
	const seFileObject = 1
	const wanted = 0x1 | 0x2 | 0x4 | 0x8 // owner, group, dacl, sacl-less request
	var descriptor uintptr
	if r, _, _ := procGetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(w32.UTF16(path))),
		seFileObject, wanted&^0x8, 0, 0, 0, 0, uintptr(unsafe.Pointer(&descriptor))); r != 0 {
		return 0, fmt.Errorf("reading the permissions of %s: error %d", path, r)
	}
	return descriptor, nil
}

// impersonationCopy turns a token into one this thread can wear.
func impersonationCopy(source syscall.Token) (syscall.Token, error) {
	const securityImpersonation, tokenImpersonation = 2, 2
	var copied syscall.Token
	if r, _, err := procDuplicateTokenEx.Call(uintptr(source), syscall.TOKEN_ALL_ACCESS, 0,
		securityImpersonation, tokenImpersonation, uintptr(unsafe.Pointer(&copied))); r == 0 {
		return 0, fmt.Errorf("copying the sandbox token: %w", err)
	}
	return copied, nil
}

// accessCheck wears the token for the length of one question.
//
// Impersonation is a property of an operating-system thread, not of a
// goroutine. Without pinning, the runtime is free to move the goroutine to
// another thread, and the token would be taken off the wrong one, leaving the
// first thread restricted for whatever runs on it next. That would show up
// later as an unrelated operation failing for no visible reason.
func accessCheck(impersonation syscall.Token, descriptor uintptr, wanted uint32) (granted uint32, allowed bool, err error) {
	runtime.LockOSThread()
	pinned := true
	defer func() {
		if pinned {
			runtime.UnlockOSThread()
		}
	}()

	if r, _, callErr := procImpersonate.Call(uintptr(impersonation)); r == 0 {
		return 0, false, fmt.Errorf("taking on the sandbox token: %w", callErr)
	}
	defer func() {
		if r, _, revertErr := procRevertToSelf.Call(); r == 0 {
			// The thread still wears the sandbox token. It must not go back
			// into the pool, so it stays locked to this goroutine and the
			// runtime retires it when the goroutine ends.
			pinned = false
			if err == nil {
				err = fmt.Errorf("could not put the sandbox token down again: %w", revertErr)
				granted, allowed = 0, false
			}
		}
	}()

	mapping := [4]uint32{
		0x120089, // generic read
		0x120116, // generic write
		0x1200A0, // generic execute
		0x1F01FF, // generic all
	}
	desired := wanted
	procMapGenericMask.Call(uintptr(unsafe.Pointer(&desired)), uintptr(unsafe.Pointer(&mapping)))

	privileges := make([]byte, 1024)
	privilegeSize := uint32(len(privileges))
	var status int32
	r, _, callErr := procAccessCheck.Call(descriptor, uintptr(impersonation), uintptr(desired),
		uintptr(unsafe.Pointer(&mapping)), uintptr(unsafe.Pointer(&privileges[0])),
		uintptr(unsafe.Pointer(&privilegeSize)), uintptr(unsafe.Pointer(&granted)),
		uintptr(unsafe.Pointer(&status)))
	if r == 0 {
		return 0, false, fmt.Errorf("asking Windows: %w", callErr)
	}
	return granted, status != 0, nil
}

// readOnlyAttribute reports whether a file carries the read-only mark. It is
// meaningless on a directory, which Windows marks for unrelated reasons.
func readOnlyAttribute(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	attributes, err := syscall.GetFileAttributes(w32.UTF16(path))
	if err != nil {
		return false
	}
	const readOnly = 0x1
	return attributes&readOnly != 0
}

// deleteThroughParent reports whether the directory holding a path lets the
// sandbox remove what is inside it.
func deleteThroughParent(group, path string) (bool, error) {
	parent := filepath.Dir(path)
	if parent == path {
		return false, nil
	}
	descriptor, err := securityOf(parent)
	if err != nil {
		return false, err
	}
	defer w32.Free(descriptor)

	restricted, err := token.Restricted(group)
	if err != nil {
		return false, err
	}
	defer restricted.Close()

	impersonation, err := impersonationCopy(restricted)
	if err != nil {
		return false, err
	}
	defer impersonation.Close()

	_, allowed, err := accessCheck(impersonation, descriptor, DeleteChild)
	return allowed, err
}
