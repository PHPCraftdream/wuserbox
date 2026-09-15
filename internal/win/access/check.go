package access

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/token"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var (
	procGetNamedSecurityInfo = w32.Advapi32.NewProc("GetNamedSecurityInfoW")
	procAccessCheck          = w32.Advapi32.NewProc("AccessCheck")
	procMapGenericMask       = w32.Advapi32.NewProc("MapGenericMask")
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

// Sandbox is who a question is about: the group every permission it holds
// names, and the account a run of it logs on as.
//
// Password is here because the only way to hold the token a run gets, from
// outside that run, is to log the account on -- and the only way to log an
// account on is with its password. It is already unsealed by the time it
// arrives: opening the seal is the caller's business, since only the account
// that made it can.
//
// Account empty means a sandbox from before sandboxes had accounts, which
// runs as a restricted copy of the caller's own token and is answered with
// exactly that.
// Inside says the process doing the asking is this very sandbox, which
// answers the question without any of the above: the token it is already
// running under is the one being asked about. It is also the only way such a
// process can be answered at all, since the seal on the password belongs to
// whoever is outside.
type Sandbox struct {
	Group    string
	Account  string
	Password string
	Inside   bool
}

// token builds the one a run of this sandbox gets.
func (s Sandbox) token() (syscall.Token, error) {
	switch {
	case s.Inside:
		return token.Own()
	case s.Account == "":
		return token.Restricted(s.Group)
	default:
		return token.OfSandbox(s.Account, s.Password, s.Group)
	}
}

// Asking holds a sandbox's token open across as many questions as a caller
// has.
//
// Building one logs the sandbox's account on, which is not free, so it is
// done once per Asking rather than once per question: --explain puts up to
// four questions to every directory a sandbox holds, and a sandbox can hold
// twenty.
type Asking struct {
	// restricted is the token a run gets; client is the impersonation-level
	// copy of it AccessCheck insists on being handed. Both are this type's to
	// close.
	restricted syscall.Token
	client     syscall.Token
}

// Ask takes the sandbox's token out, ready to answer questions about it.
func Ask(s Sandbox) (*Asking, error) {
	restricted, err := s.token()
	if err != nil {
		return nil, err
	}
	client, err := impersonationCopy(restricted)
	if err != nil {
		restricted.Close()
		return nil, err
	}
	return &Asking{restricted: restricted, client: client}, nil
}

// Close puts the token down and ends the logon that produced it.
func (a *Asking) Close() {
	a.client.Close()
	a.restricted.Close()
}

// Check asks Windows whether a sandbox could perform an operation, and puts
// the token down again. Callers with more than one question should use Ask.
//
// Nothing is opened for writing and nothing is created, so asking is free of
// consequences.
func Check(s Sandbox, path string, operation Operation) (Result, error) {
	asking, err := Ask(s)
	if err != nil {
		return Result{Path: path, Operation: operation, Checked: path}, err
	}
	defer asking.Close()
	return asking.Can(path, operation)
}

// Can answers one question with the token already in hand.
func (a *Asking) Can(path string, operation Operation) (Result, error) {
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

	granted, allowed, err := accessCheck(a.client, descriptor, operation.mask())
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
		throughParent, err := a.deleteThroughParent(target)
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

// accessCheck asks Windows what a token may do to an object.
//
// The thread is deliberately not made to wear the token. AccessCheck takes
// one as an argument and compares it against the descriptor; it never reads
// the thread's own. Wearing it was how this started, and it cost three
// things: the goroutine had to be pinned to its operating-system thread, a
// failure to take the token off again had to retire that thread rather than
// hand it back, and -- what settled it -- whether a token may be worn at all
// turns on privileges and on where the token came from, neither of which has
// anything to do with the question being asked. Now that the token asked
// about belongs to another account, that is a dependency worth not having.
// Measured: the answers are the same either way.
func accessCheck(client syscall.Token, descriptor uintptr, wanted uint32) (granted uint32, allowed bool, err error) {
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
	r, _, callErr := procAccessCheck.Call(descriptor, uintptr(client), uintptr(desired),
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
func (a *Asking) deleteThroughParent(path string) (bool, error) {
	parent := filepath.Dir(path)
	if parent == path {
		return false, nil
	}
	descriptor, err := securityOf(parent)
	if err != nil {
		return false, err
	}
	defer w32.Free(descriptor)

	_, allowed, err := accessCheck(a.client, descriptor, DeleteChild)
	return allowed, err
}
