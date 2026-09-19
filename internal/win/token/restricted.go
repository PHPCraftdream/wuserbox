// Package token builds the restricted access token a sandbox runs under.
package token

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/group"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var (
	procCreateRestrictedToken      = w32.Advapi32.NewProc("CreateRestrictedToken")
	procSetTokenInformation        = w32.Advapi32.NewProc("SetTokenInformation")
	procStringToSecurityDescriptor = w32.Advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procGetSecurityDescriptorDacl  = w32.Advapi32.NewProc("GetSecurityDescriptorDacl")
)

const (
	classLogonSid       = 28
	classDefaultDacl    = 6
	disableMaxPrivilege = 0x1
)

type sidAndAttributes struct {
	sid        uintptr
	attributes uint32
}

// Restricted derives a fully restricted token from the caller's own token.
//
// This was the whole of a sandbox once. It is now one half of one: a run is
// the sandbox's own account and a token restricted to that account's
// identities, which AsSandbox builds from inside. What is left for this is a
// sandbox built by an older version, which runs this way until `--init`
// gives it an account, and `--check` on such a sandbox -- for any other,
// access asks with the account's own token by logging it on.
//
// The boundary tests reach it with a made-up group, which is what lets them
// prove the boundary on a machine with no administrator rights at all. What
// that arrangement cannot show is worth naming, because it reads as though it
// could: the caller's token carries the caller's memberships and not the
// sandbox's group, so the first of the two checks passes by way of the
// caller's own access rather than the sandbox's. A permission this token
// reaches is therefore one a real account reaches as well, and a refusal here
// may be the caller's rather than the sandbox's. Closing that gap is what the
// account tests in internal/e2e are for.
//
// Every access, not only writes, is checked a second time against the
// restricting identifiers, so it succeeds only where the sandbox group — or
// one of the shared identifiers alongside it — has a permission of its own.
// That is what closes deleting outside the sandbox and deleting a peer
// sandbox's files: DELETE and FILE_DELETE_CHILD go through the same check as
// everything else here, unlike the generic-write mapping a write-restricted
// token uses.
//
// Everyone and BUILTIN\Users are restricting identifiers too, not only the
// sandbox's own group: starting any program that loads the window subsystem
// needs Everyone, and reading System32 or Program Files needs Users, since
// those grant Users read and execute rather than Everyone. Granting a
// directory to one sandbox therefore has to take Everyone's and Users' write
// access away on that same directory wherever it is granted — grant.Apply
// does that — or every other sandbox holding either identifier could reach
// it too.
func Restricted(sandboxGroup string) (syscall.Token, error) {
	caller, err := sid.CurrentUser()
	if err != nil {
		return 0, err
	}
	self, err := ownToken()
	if err != nil {
		return 0, err
	}
	defer self.Close()
	return restrict(self, sandboxGroup, group.ReadGroupFor(caller), false)
}

// AsSandbox restricts the token of a process that is already running as the
// sandbox's own account, and puts that account's own identifier in the
// restricting list.
//
// That one addition is the difference between this and Restricted, and it
// would be a catastrophe in the other direction. Restricted cuts down the
// token of the person who owns the machine, and adding *their* identifier
// would let the second check pass on everything they can reach, which is
// everything -- it is the exact move the whole design refuses. Here the
// token belongs to the sandbox, so its own identifier is the confined one,
// and naming it grants nothing beyond what the sandbox already is.
//
// It is also what makes the second check usable again at all. An MSYS
// runtime writes its own descriptors naming the account it runs as and then
// reopens its own objects -- measured, it cannot even query its own process
// token first -- so a restricted token that could not name the user died
// before main. Naming the account instead costs nothing and passes.
//
// readGroup is handed in rather than worked out. Inside a sandbox the
// current user is the sandbox account, so asking which read group belongs to
// "the caller" would name a group for the wrong person.
func AsSandbox(sandboxGroup, readGroup string) (syscall.Token, error) {
	self, err := ownToken()
	if err != nil {
		return 0, err
	}
	defer self.Close()
	return restrict(self, sandboxGroup, readGroup, true)
}

// Own hands back this process's own token, for the one caller that is already
// the thing being asked about: wuserbox running inside a sandbox, asked what
// that sandbox may do. Nothing has to be modeled there, and nothing can be --
// the password is sealed to the person outside -- because the token the
// question is about is the one this process is running under.
func Own() (syscall.Token, error) {
	return ownToken()
}

// ownToken is this process's own, the one every restriction starts from
// except the one OfSandbox builds by logging an account on.
func ownToken() (syscall.Token, error) {
	var self syscall.Token
	if err := syscall.OpenProcessToken(syscall.Handle(^uintptr(0)), syscall.TOKEN_ALL_ACCESS, &self); err != nil {
		return 0, fmt.Errorf("opening the process token: %w", err)
	}
	return self, nil
}

// restrict cuts self down to the identities named here. self stays open and
// belongs to the caller; what comes back is a new token.
func restrict(self syscall.Token, sandboxGroup, readGroup string, ownIdentityToo bool) (syscall.Token, error) {
	userBuf, err := information(self, syscall.TokenUser)
	if err != nil {
		return 0, err
	}
	logonBuf, err := information(self, classLogonSid)
	if err != nil {
		return 0, err
	}
	user := *(*uintptr)(unsafe.Pointer(&userBuf[0]))
	// TOKEN_GROUPS: a count and padding, then the first entry's identifier.
	logon := *(*uintptr)(unsafe.Pointer(&logonBuf[unsafe.Sizeof(uintptr(0))]))

	groupSID, err := sid.Parse(sandboxGroup)
	if err != nil {
		return 0, err
	}
	everyone, err := sid.Parse(sid.Everyone)
	if err != nil {
		return 0, err
	}
	users, err := sid.Parse(sid.Users)
	if err != nil {
		return 0, err
	}
	restricting := []sidAndAttributes{{groupSID, 0}, {everyone, 0}, {users, 0}, {logon, 0}}
	if ownIdentityToo {
		restricting = append(restricting, sidAndAttributes{user, 0})
	}
	// A sandbox built before a read group existed simply runs without it: the
	// profile reads that depended on it fail, the same way any other missing
	// grant would, rather than refusing to run at all.
	//
	// Held in a variable that outlives the if, so it can be kept alive across
	// the call below rather than ending where the condition does.
	var readBuf sid.Value
	if read, err := sid.Lookup(readGroup); err == nil {
		readBuf = read
		restricting = append(restricting, sidAndAttributes{uintptr(unsafe.Pointer(&readBuf[0])), 0})
	}

	var restricted syscall.Token
	r, _, callErr := procCreateRestrictedToken.Call(uintptr(self), disableMaxPrivilege,
		0, 0, 0, 0, uintptr(len(restricting)), uintptr(unsafe.Pointer(&restricting[0])),
		uintptr(unsafe.Pointer(&restricted)))
	// The restricting list holds plain numbers, and a number is not a reference:
	// three of those identifiers live in memory Go allocated and nothing else
	// mentions afterwards, so the collector is entitled to take them back before
	// the call above has read them. The rule that keeps an unsafe.Pointer alive
	// covers the call expression it appears in and nothing further. The two
	// parsed identifiers need no such care -- ConvertStringSidToSid hands back
	// memory belonging to Windows.
	//
	// Losing one would almost certainly refuse to build a token rather than
	// build a weaker one, which is the right direction to fail in, but a
	// boundary should not rest on that.
	runtime.KeepAlive(logonBuf)
	runtime.KeepAlive(readBuf)
	if r == 0 {
		return 0, fmt.Errorf("creating the restricted token: %w", callErr)
	}
	owner := formatSID(user)
	runtime.KeepAlive(userBuf)
	if err := shareWithGroup(restricted, owner, sandboxGroup); err != nil {
		// The token exists by now; only its default permissions are
		// missing. Leaving it open on the way out would leak it, and
		// nothing downstream can use a token nobody shared with the group.
		restricted.Close()
		return 0, err
	}
	return restricted, nil
}

// information reads a token class the only way GetTokenInformation allows,
// in two calls. The first names the size and is refused by design, so its
// error is a failure only when it is some other refusal; a size of zero
// cannot be real -- every class is at least its header wide -- and indexing
// into the buffer it would ask for is a panic on an empty slice.
func information(token syscall.Token, class uint32) ([]byte, error) {
	var size uint32
	err := syscall.GetTokenInformation(token, class, nil, 0, &size)
	if err != nil && !errors.Is(err, syscall.ERROR_INSUFFICIENT_BUFFER) {
		return nil, fmt.Errorf("sizing token information %d: %w", class, err)
	}
	if size == 0 {
		return nil, fmt.Errorf("token information %d reports no size", class)
	}
	buf := make([]byte, size)
	if err := syscall.GetTokenInformation(token, class, &buf[0], size, &size); err != nil {
		return nil, fmt.Errorf("reading token information %d: %w", class, err)
	}
	return buf, nil
}

func formatSID(pointer uintptr) string {
	var text *uint16
	proc := w32.Advapi32.NewProc("ConvertSidToStringSidW")
	if r, _, _ := proc.Call(pointer, uintptr(unsafe.Pointer(&text))); r == 0 {
		return ""
	}
	defer w32.Free(uintptr(unsafe.Pointer(text)))
	return w32.GoString(text)
}

// shareWithGroup makes objects the sandbox creates reachable by other
// processes of the same sandbox: their default permissions name the group,
// which is what the second access check needs.
func shareWithGroup(token syscall.Token, user, group string) error {
	text := fmt.Sprintf("D:(A;;GA;;;%s)(A;;GA;;;%s)(A;;GA;;;%s)", user, sid.System, group)
	var descriptor uintptr
	if r, _, err := procStringToSecurityDescriptor.Call(uintptr(unsafe.Pointer(w32.UTF16(text))), 1,
		uintptr(unsafe.Pointer(&descriptor)), 0); r == 0 {
		return fmt.Errorf("building the default permissions: %w", err)
	}
	defer w32.Free(descriptor)

	var present, defaulted int32
	var dacl uintptr
	if r, _, err := procGetSecurityDescriptorDacl.Call(descriptor, uintptr(unsafe.Pointer(&present)),
		uintptr(unsafe.Pointer(&dacl)), uintptr(unsafe.Pointer(&defaulted))); r == 0 {
		return fmt.Errorf("reading the default permissions: %w", err)
	}
	if r, _, err := procSetTokenInformation.Call(uintptr(token), classDefaultDacl,
		uintptr(unsafe.Pointer(&dacl)), unsafe.Sizeof(dacl)); r == 0 {
		return fmt.Errorf("setting the default permissions: %w", err)
	}
	return nil
}
