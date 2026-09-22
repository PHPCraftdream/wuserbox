// The close test for reading each object's permission list once per
// question instead of once per identity asked about, and for the native
// memory the question holds: the two identifiers a pass resolves at its
// start are system memory the collector does not manage, and End is the
// only thing that gives them back. The counters here count real reads and
// real system-heap allocations -- Go's own allocation counts cannot see
// the second kind at all.

package acl

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var (
	procCreateFile      = syscall.NewLazyDLL("kernel32.dll").NewProc("CreateFileW")
	procSetSecurityInfo = w32.Advapi32.NewProc("SetSecurityInfo")
)

// keepHandle opens the directory while its permission list still reads and
// returns the handle for the cleanup to put the list back with. What a
// handle may do is decided when the handle opens, so a list that stops
// being readable afterwards cannot take the right to rewrite it back -- on
// this machine the rewrite asks to read first, and a closed list refuses
// both at once.
func keepHandle(t *testing.T, path string) syscall.Handle {
	t.Helper()
	const (
		readControl     = 0x20000
		writeDac        = 0x40000
		openExisting    = 3
		backupSemantics = 0x02000000 // a directory can only be opened with this
	)
	h, _, err := procCreateFile.Call(uintptr(unsafe.Pointer(w32.UTF16(path))),
		readControl|writeDac, 0, 0, openExisting, backupSemantics, 0)
	if h == 0 || h == ^uintptr(0) {
		t.Fatalf("opening %s while its list still reads: %v", path, err)
	}
	return syscall.Handle(h)
}

// putBack writes text onto the permission list through an already-open
// handle. It is the same write setSDDL makes, carried by a handle instead
// of the path, because the path is the one way in the closed list blocks.
func putBack(t *testing.T, h syscall.Handle, text string) {
	t.Helper()
	var descriptor uintptr
	if r, _, err := procStringToSecurityDescriptor.Call(uintptr(unsafe.Pointer(w32.UTF16(text))), 1,
		uintptr(unsafe.Pointer(&descriptor)), 0); r == 0 {
		t.Fatalf("building %q: %v", text, err)
	}
	defer w32.Free(descriptor)
	var present, defaulted int32
	var dacl uintptr
	if r, _, err := procGetSecurityDescriptorDacl.Call(descriptor, uintptr(unsafe.Pointer(&present)),
		uintptr(unsafe.Pointer(&dacl)), uintptr(unsafe.Pointer(&defaulted))); r == 0 {
		t.Fatalf("reading %q: %v", text, err)
	}
	const protectedDacl = 0x80000000
	if r, _, _ := procSetSecurityInfo.Call(uintptr(h), seFileObject, daclInfo|protectedDacl, 0, 0, dacl, 0); r != 0 {
		t.Fatalf("putting the permissions of the closed directory back: error %d", r)
	}
}

// describeOwner is diagnostic only, called after the control check above it
// has already failed: it says who the object's owner actually is, resolved
// to a name, against the SID this account claims as its own, so a failure
// here says more than "the closed directory's list could be read" does on
// its own -- an owner the OWNER RIGHTS deny above does not name would read
// it back regardless of the list, and this is the one place that would show.
func describeOwner(t *testing.T, path, expectedSID string) string {
	t.Helper()
	var ownerSID, descriptor uintptr
	if r, _, err := procGetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(w32.UTF16(path))),
		seFileObject, ownerInfo, uintptr(unsafe.Pointer(&ownerSID)), 0, 0, 0,
		uintptr(unsafe.Pointer(&descriptor))); r != 0 {
		return fmt.Sprintf("and the object's own owner could not be read either: %v", err)
	}
	defer w32.Free(descriptor)
	name, nameErr := sid.Name(ownerSID)
	if nameErr != nil {
		name = "<unresolved>"
	}
	return fmt.Sprintf("object owner: %s; this account's own SID: %s", name, expectedSID)
}

// TestAnAuditPassReadsEachObjectOnceAndGivesItsIdentifiersBack answers the
// audit question for a small tree -- one ordinary directory, one whose
// permission list this account is refused -- and counts what the answers
// cost: one read per object, two identifiers parsed at the start, both
// given back at the end. The refused one comes back as a refusal to read,
// never as a writable answer: a list that cannot be read is the one place
// --audit has nothing to say, and folding that into "writable" would print
// the opposite of what it knows.
func TestAnAuditPassReadsEachObjectOnceAndGivesItsIdentifiersBack(t *testing.T) {
	root := t.TempDir()
	closed := filepath.Join(root, "closed")
	if err := os.Mkdir(closed, 0o755); err != nil {
		t.Fatal(err)
	}
	// Owner Rights names no access beyond what the list gives the owner,
	// and naming it at all switches the owner's implicit reading off. The
	// list refuses the owner READ_CONTROL and leaves WRITE_DAC, so this
	// account can neither read the list nor is locked out of putting it
	// back.
	handle := keepHandle(t, closed)
	setSDDL(t, closed, "D:P(D;;0x20000;;;OW)(A;;0x40000;;;WD)")
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		putBack(t, handle, `D:P(A;OICI;FA;;;`+owner+`)`)
		syscall.CloseHandle(handle)
	})

	// Both fixtures have to be what they claim before the counted pass
	// starts, or the counts prove nothing.
	if _, err := heldBy(closed, sid.Everyone, changing); err == nil {
		t.Fatalf("the closed directory's list could be read, so this proves nothing (%s)", describeOwner(t, closed, owner))
	}
	if _, err := heldBy(root, sid.Everyone, changing); err != nil {
		t.Fatalf("the ordinary directory's list could not be read, so this proves nothing: %v", err)
	}

	reads := descriptorReads.Load()
	parses := sid.Parses()
	frees := sid.Frees()

	pass, err := BeginWritable()
	if err != nil {
		t.Fatal(err)
	}
	everyone, users, ordinaryErr := pass.Writable(root)
	closedEveryone, closedUsers, closedErr := pass.Writable(closed)
	pass.End()

	if got := descriptorReads.Load() - reads; got != 2 {
		t.Errorf("one question about each of 2 objects read %d permission lists, want 2", got)
	}
	if got := sid.Parses() - parses; got != 2 {
		t.Errorf("the pass parsed %d identifiers, want the two it was built with", got)
	}
	if got := sid.Frees() - frees; got != 2 {
		t.Errorf("the pass gave %d identifiers back, want both of what it parsed", got)
	}

	if ordinaryErr != nil {
		t.Fatalf("the ordinary directory could not be answered: %v", ordinaryErr)
	}
	if everyone || users {
		t.Error("a fresh directory this account owns was reported writable by a shared identity")
	}
	if closedErr == nil || closedEveryone || closedUsers {
		t.Errorf("an unreadable list came back as an answer (everyone=%v, users=%v, err=%v), want the failure",
			closedEveryone, closedUsers, closedErr)
	}
}

// TestOneQuestionParsesItsIdentifierOnceAndGivesItBack: heldBy is the
// one-object form of the question, and its identifier is system memory for
// exactly as long as the question runs.
func TestOneQuestionParsesItsIdentifierOnceAndGivesItBack(t *testing.T) {
	dir := t.TempDir()
	parses := sid.Parses()
	frees := sid.Frees()
	if _, err := heldBy(dir, sid.Everyone, changing); err != nil {
		t.Fatal(err)
	}
	if got := sid.Parses() - parses; got != 1 {
		t.Errorf("one question parsed %d identifiers, want one", got)
	}
	if got := sid.Frees() - frees; got != 1 {
		t.Errorf("one question gave %d identifiers back, want the one it parsed", got)
	}
}
