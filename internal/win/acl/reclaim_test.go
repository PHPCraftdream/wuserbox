// Taking a grant back caps what the owner of an object the sandbox owns
// holds implicitly -- the same cap the sweep writes on the way in, written
// here on the way out, where a revoke used to leave the owner's WRITE_DAC
// standing beside everything it took. What it spares is the record: a path
// the record holds for this sandbox is passed over, because a grant pinned
// inside the tree holds on different terms. What it replaces is StripOwn's
// old job, which took the account's entries off an object and left the
// implicit grant standing beside them. What these tests measure runs
// unelevated, because the synthetic world's one account is both the sandbox
// and the owner, which is exactly the pair the owner check compares.
//
// Cleanup does not: target here is itself named in its own grant, so once
// capped it has no untouched parent to be recovered through the way a
// single file does, and reclaimTree asks for a privilege only an
// administrator token holds. That is the one part of these tests a CI
// runner exercises that this desk cannot.

package acl

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/quietexec"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

// operators is WRITE_DAC and WRITE_OWNER, added to the setup grant in these
// tests for the reason TestASweepReachesWhatItWroteWhenTheGrantNarrows
// carries the same bits: the operator's rights ride along on the same
// identifier here, because the synthetic world has one account, and target
// is the object the grant is on rather than something inside it -- once the
// cap lands, revoking target's own grant needs a write to target itself,
// which the account's own entry has to carry explicitly or nothing can ever
// make it again. A production revoke is the operator's own call, under
// their own identity, and does not need this.
const operators = 0x80000 | 0x40000

// reclaimRoot creates the directory these tests build their capped tree
// under, outside t.TempDir(): its own automatic cleanup calls t.Errorf on a
// RemoveAll it cannot finish, which fails the test even after reclaimTree
// has already decided, correctly, to skip rather than fail on the one part
// of this it cannot do unelevated.
func reclaimRoot(t *testing.T) string {
	t.Helper()
	root, err := os.MkdirTemp("", "wub-reclaim-")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// reclaimTree recovers a tree these tests capped all the way down: the
// object named in its own grant is stripped of that grant the same way
// anything else the account holds is, so the operator's usual recovery --
// delete through an untouched parent -- has no untouched parent to reach
// through here. Two levels deep, nothing short of a privilege that
// overrides the DACL check outright gets back in.
//
// SeRestorePrivilege is that override, held (disabled) by an administrator
// token and asked for the same way account/ownprofile.go asks for it to
// write a hive's security -- this is the same mechanism, spent on cleanup
// instead of on the fix. An elevated CI runner holds it; this desk, measured,
// does not, so the test skips here rather than fail on something it cannot
// undo without it. What was measured before the skip is not undone by it.
func reclaimTree(t *testing.T, root string) {
	t.Helper()
	if err := os.RemoveAll(root); err == nil {
		return
	}
	if err := enableTestPrivilege("SeRestorePrivilege"); err != nil {
		t.Logf("%s is left behind: reclaiming it needs a privilege this desk's token does not hold (%v)", root, err)
		t.Skip("recovering a fully revoked, self-owned grant root needs SeRestorePrivilege, which an administrator token holds and this one does not")
	}
	// Whatever happens from here, the token goes back the way it was found.
	// A restore privilege left standing is not this test's state to keep: it
	// is granted by the kernel outright on the backup-intent open every list
	// read goes through, READ_CONTROL included, so every later question this
	// package's binary asks about a closed list is answered by the privilege
	// and not by the list -- which is exactly how the audit pass's
	// closed-directory control failed on CI, where the runner's own
	// administrator token holds the privilege and the enable above succeeds.
	// This desk does not hold the privilege at all (the skip above is where
	// the story ends here), but the runner does, so the disable is what
	// keeps the control measuring the list. Disabled, not removed: the next
	// reclaimTree needs to enable it again.
	defer func() { _ = disableTestPrivilege("SeRestorePrivilege") }()
	if out, err := quietexec.Command("icacls", root, "/reset", "/T", "/C").CombinedOutput(); err != nil {
		t.Fatalf("icacls /reset with SeRestorePrivilege enabled: %v\n%s", err, out)
	}
	if err := os.RemoveAll(root); err != nil {
		t.Fatalf("%s stayed behind even with SeRestorePrivilege enabled: %v", root, err)
	}
}

type reclaimLUID struct {
	low  uint32
	high int32
}
type reclaimLUIDAndAttributes struct {
	luid       reclaimLUID
	attributes uint32
}
type reclaimTokenPrivileges struct {
	count      uint32
	privileges [1]reclaimLUIDAndAttributes
}

var (
	procReclaimLookupPrivilegeValue  = w32.Advapi32.NewProc("LookupPrivilegeValueW")
	procReclaimAdjustTokenPrivileges = w32.Advapi32.NewProc("AdjustTokenPrivileges")
)

// enableTestPrivilege is account/ownprofile.go's enablePrivilege, copied
// rather than exported and shared: it is cleanup machinery for this test
// file alone, and the product code that measures and depends on the same
// privilege lives where its own comment is, not re-exported for a test to
// borrow.
func enableTestPrivilege(name string) error {
	var token syscall.Token
	if err := syscall.OpenProcessToken(syscall.Handle(^uintptr(0)),
		syscall.TOKEN_ADJUST_PRIVILEGES|syscall.TOKEN_QUERY, &token); err != nil {
		return fmt.Errorf("opening the process token: %w", err)
	}
	defer func() { _ = token.Close() }()
	var id reclaimLUID
	if r, _, err := procReclaimLookupPrivilegeValue.Call(0, uintptr(unsafe.Pointer(w32.UTF16(name))),
		uintptr(unsafe.Pointer(&id))); r == 0 {
		return fmt.Errorf("looking up %s: %w", name, err)
	}
	const sePrivilegeEnabled = 0x2
	priv := reclaimTokenPrivileges{count: 1, privileges: [1]reclaimLUIDAndAttributes{{luid: id, attributes: sePrivilegeEnabled}}}
	r, _, err := procReclaimAdjustTokenPrivileges.Call(uintptr(token), 0, uintptr(unsafe.Pointer(&priv)), 0, 0, 0)
	if r == 0 {
		return fmt.Errorf("enabling %s: %w", name, err)
	}
	const errNotAllAssigned = 1300
	var errno syscall.Errno
	if errors.As(err, &errno) && errno == errNotAllAssigned {
		return fmt.Errorf("enabling %s: not held by this token (administrator required)", name)
	}
	return nil
}

// disableTestPrivilege puts back what enableTestPrivilege took: the same
// AdjustTokenPrivileges call with the enabled attribute cleared, which leaves
// the privilege held but off again -- the state this process's token was
// found in. A privilege the token does not hold has nothing to disable and
// answers the same not-assigned error the enable reports; here that is the
// ordinary case, not a failure.
func disableTestPrivilege(name string) error {
	var token syscall.Token
	if err := syscall.OpenProcessToken(syscall.Handle(^uintptr(0)),
		syscall.TOKEN_ADJUST_PRIVILEGES|syscall.TOKEN_QUERY, &token); err != nil {
		return fmt.Errorf("opening the process token: %w", err)
	}
	defer func() { _ = token.Close() }()
	var id reclaimLUID
	if r, _, err := procReclaimLookupPrivilegeValue.Call(0, uintptr(unsafe.Pointer(w32.UTF16(name))),
		uintptr(unsafe.Pointer(&id))); r == 0 {
		return fmt.Errorf("looking up %s: %w", name, err)
	}
	priv := reclaimTokenPrivileges{count: 1, privileges: [1]reclaimLUIDAndAttributes{{luid: id}}}
	r, _, err := procReclaimAdjustTokenPrivileges.Call(uintptr(token), 0, uintptr(unsafe.Pointer(&priv)), 0, 0, 0)
	if r == 0 {
		return fmt.Errorf("disabling %s: %w", name, err)
	}
	return nil
}

// TestTakingAGrantBackCapsWhatTheOwnerHolds is the hole a revoke had no
// answer to. The files are made while the grant is writable, hold nothing of
// their own that names the account, and what their owner held through them
// was the one thing no entry refuses -- the WRITE_DAC and READ_CONTROL
// ownership implies. StripOwn passed such objects whole; the cap is what
// closes the window.
func TestTakingAGrantBackCapsWhatTheOwnerHolds(t *testing.T) {
	root := reclaimRoot(t)
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	normalizeOwner(t, target, owner)
	// The tree is held writable in the shape a production run meets, written
	// outright first so that only these entries answer below: the revoke
	// takes the account's entries off the directory, and what the directory
	// stops handing down goes with that rewrite.
	setSDDL(t, target, `D:P(A;OICI;0x1301BF;;;`+owner+`)`)

	// Handed over writable first, and the files made after: created between
	// the sweep and the revoke, which is the ordinary order of a production
	// run and the case StripOwn's old job never reached -- a file like this
	// holds no entry naming the account at all.
	if err := Isolate(target, owner, []ACE{
		{Access: AccessModify, Inheritance: InheritObjects | InheritContainers},
		{Access: operators, Inheritance: InheritObjects | InheritContainers},
	}, InheritObjects|InheritContainers, nil); err != nil {
		t.Fatal(err)
	}
	made := filepath.Join(target, "made.txt")
	const original = "the sandbox wrote this"
	if err := os.WriteFile(made, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	normalizeOwner(t, made, owner)
	wide := filepath.Join(target, "wide.txt")
	if err := os.WriteFile(wide, []byte("wide open"), 0o644); err != nil {
		t.Fatal(err)
	}
	normalizeOwner(t, wide, owner)

	// The positive control, shown after the files exist and before anything
	// caps them: the owner's implicit WRITE_DAC rewrites the list of a file
	// whose entries never name anyone, which is the window a revoke has to
	// close.
	rewriteWorks(t, wide, owner)

	// One call, root included: grant.Revoke's own job now, since target here
	// is owned by the same account being revoked (the synthetic world's one
	// account, playing both roles) -- capping it in a first call and only
	// then trying to change its list in a second would refuse the second
	// outright, the same way any owner-capped object refuses a later change.
	if err := TakeBack(target, owner, nil); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{made, wide} {
		if !holds(t, path, "OWNER RIGHTS", "(RX)") {
			t.Errorf("a file created between the sweep and the revoke was left uncapped by the revoke: %s", path)
		}
		rewriteRefused(t, path, owner, "the same icacls that worked above must not work once the grant has been taken back")
	}
	if err := os.WriteFile(made, []byte("tampered"), 0o644); err == nil {
		t.Fatal("a file whose grant was taken back was rewritten")
	}
	if got, err := os.ReadFile(made); err != nil || string(got) != original {
		t.Fatalf("the content of %s changed: %q (%v)", made, got, err)
	}
	// The cap leaves the owner reading: a revoke is about the changing and
	// the deciding, and READ_CONTROL alone would have taken the reading with
	// it.
	if _, err := os.ReadFile(made); err != nil {
		t.Errorf("the cap took the owner's reading away with the writing: %v", err)
	}

	reclaimTree(t, root)
}

// TestTakingAGrantBackNarrowsAnUnexpectedExplicitGrant covers an object whose
// own list contains a broad grant the sandbox wrote before revoke. The cap
// must not be defeated by carrying that grant into the replacement list.
func TestTakingAGrantBackNarrowsAnUnexpectedExplicitGrant(t *testing.T) {
	root := t.TempDir()
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	probe := filepath.Join(root, "probe.txt")
	if err := os.WriteFile(probe, []byte("probe"), 0o644); err != nil {
		t.Fatal(err)
	}
	normalizeOwner(t, probe, owner)
	t.Cleanup(func() { reclaim(t, probe) })

	// The sandbox owns the object and has explicitly opened it to Everyone.
	// This is the shape a revoke must not preserve merely because the ACE is
	// explicit and the object's list is protected.
	setSDDL(t, probe, `D:P(A;;FA;;;`+owner+`)(A;;FA;;;`+sid.Everyone+`)`)
	if !EveryoneWritable(probe) {
		t.Fatal("the broad Everyone grant was not present before TakeBack")
	}

	if err := TakeBack(probe, owner, nil); err != nil {
		t.Fatal(err)
	}
	if EveryoneWritable(probe) {
		t.Fatal("TakeBack preserved an explicit Everyone changing grant")
	}
	if !holds(t, probe, "OWNER RIGHTS", "(RX)") {
		t.Fatal("TakeBack did not leave the owner cap beside the narrowed grant")
	}
}

// TestTakingAGrantBackNarrowsAnUnexpectedExplicitGrantBesideInheritedAccess
// covers the other TakeBack branch. A file made under a writable directory
// has an inherited owner grant; an explicit broad grant beside it must still
// be narrowed when the file is capped.
func TestTakingAGrantBackNarrowsAnUnexpectedExplicitGrantBesideInheritedAccess(t *testing.T) {
	root := t.TempDir()
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(root, "parent")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	normalizeOwner(t, parent, owner)
	// SYSTEM is the trusted inherited recovery/read path. Everyone is an
	// inherited broad grant as well as the explicit broad grant added below;
	// both must be narrowed, while SYSTEM must survive the whole rewrite.
	setSDDL(t, parent, `D:P(A;OICI;0x1301BF;;;`+owner+`)(A;OICI;0x1F01FF;;;SY)(A;OICI;0x1F01FF;;;`+sid.Everyone+`)`)

	probe := filepath.Join(parent, "probe.txt")
	if err := os.WriteFile(probe, []byte("probe"), 0o644); err != nil {
		t.Fatal(err)
	}
	normalizeOwner(t, probe, owner)
	t.Cleanup(func() { reclaim(t, probe) })

	if out, err := icacls(t, probe, "/grant", "*"+sid.Everyone+":(F)"); err != nil {
		t.Fatalf("adding the broad control grant: %v\n%s", err, out)
	}
	if !EveryoneWritable(probe) {
		t.Fatal("the broad Everyone grant was not present before TakeBack")
	}
	if err := TakeBack(probe, owner, nil); err != nil {
		t.Fatal(err)
	}
	if EveryoneWritable(probe) {
		t.Fatal("TakeBack preserved an inherited or explicit Everyone changing grant")
	}
	if !holds(t, probe, "SYSTEM", "(F)") {
		t.Fatal("TakeBack dropped trusted inherited SYSTEM access while writing the cap")
	}
	if !holds(t, probe, "OWNER RIGHTS", "(RX)") {
		t.Fatal("TakeBack did not cap the owner on an inherited object")
	}
}

// TestTakingBackRepairsACappedObjectWithAnUnexpectedExplicitGrant covers the
// already-capped fast path. OWNER RIGHTS:RX is not sufficient evidence when
// an old or externally written broad ACE remains beside it.
func TestTakingBackRepairsACappedObjectWithAnUnexpectedExplicitGrant(t *testing.T) {
	root := t.TempDir()
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	probe := filepath.Join(root, "probe.txt")
	if err := os.WriteFile(probe, []byte("probe"), 0o644); err != nil {
		t.Fatal(err)
	}
	normalizeOwner(t, probe, owner)
	t.Cleanup(func() { reclaim(t, probe) })

	// The owner cap is present, but an explicit broad grant was added beside
	// it. TakeBack must not accept this shape as already complete.
	setSDDL(t, probe, `D:P(A;;0x1200A9;;;`+sid.OwnerRights+`)(A;;FA;;;`+sid.Everyone+`)`)
	if !EveryoneWritable(probe) {
		t.Fatal("the broad Everyone grant was not present before TakeBack")
	}

	if err := TakeBack(probe, owner, nil); err != nil {
		t.Fatal(err)
	}
	if EveryoneWritable(probe) {
		t.Fatal("the already-capped fast path preserved an explicit Everyone changing grant")
	}
	if !holds(t, probe, "OWNER RIGHTS", "(RX)") {
		t.Fatal("repairing the capped object removed the owner cap")
	}
}

// TestTakingAGrantBackSparesWhatTheRecordPins is the same revoke against a
// tree holding a file the record pins for this sandbox. What spares it is
// the record, not the list's shape: the file beside it, made the same way at
// the same moment and holding the same nothing of its own, was capped.
func TestTakingAGrantBackSparesWhatTheRecordPins(t *testing.T) {
	root := reclaimRoot(t)
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	normalizeOwner(t, target, owner)
	setSDDL(t, target, `D:P(A;OICI;0x1301BF;;;`+owner+`)`)

	if err := Isolate(target, owner, []ACE{
		{Access: AccessModify, Inheritance: InheritObjects | InheritContainers},
		{Access: operators, Inheritance: InheritObjects | InheritContainers},
	}, InheritObjects|InheritContainers, nil); err != nil {
		t.Fatal(err)
	}
	made := filepath.Join(target, "made.txt")
	if err := os.WriteFile(made, []byte("the sandbox wrote this"), 0o644); err != nil {
		t.Fatal(err)
	}
	normalizeOwner(t, made, owner)
	pinned := filepath.Join(target, "pinned.txt")
	if err := os.WriteFile(pinned, []byte("granted in its own right"), 0o644); err != nil {
		t.Fatal(err)
	}
	normalizeOwner(t, pinned, owner)

	if err := TakeBack(target, owner, []string{pinned}); err != nil {
		t.Fatal(err)
	}

	if !holds(t, made, "OWNER RIGHTS", "(RX)") {
		t.Fatal("the revoke did not cap a file the record does not mention")
	}
	if holds(t, pinned, "OWNER RIGHTS", "") {
		t.Fatal("an owner-rights cap was written onto a file the record pins")
	}
	// The pinned file still answers to its owner's implicit WRITE_DAC: the
	// record, not the list's shape, is what spares an object -- and the same
	// command that was refused beside it goes through here.
	rewriteWorks(t, pinned, owner)
	rewriteRefused(t, made, owner, "the file beside it, held by nothing but the grant that was taken back, was capped")

	reclaimTree(t, root)
}

// TestTakingAGrantBackTakesDownWhatTheSandboxHandedItself is the other half
// of StripOwn's old job. A sandbox holding every right can hand itself a
// list of its own -- protected, full control, nothing inherited and no mark
// -- and a revoke that only took the group's entries off left that standing;
// the cap alone does not touch it either, because the cap replaces only what
// ownership implies.
func TestTakingAGrantBackTakesDownWhatTheSandboxHandedItself(t *testing.T) {
	root := reclaimRoot(t)
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	// icacls prints resolved account names, not identifier text, so what the
	// holds helper searches for is the name of this account.
	pointer, err := sid.Parse(owner)
	if err != nil {
		t.Fatal(err)
	}
	name, err := sid.Name(pointer)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	normalizeOwner(t, target, owner)
	setSDDL(t, target, `D:P(A;OICI;0x1301BF;;;`+owner+`)`)

	if err := Isolate(target, owner, []ACE{
		{Access: AccessModify, Inheritance: InheritObjects | InheritContainers},
		{Access: operators, Inheritance: InheritObjects | InheritContainers},
	}, InheritObjects|InheritContainers, nil); err != nil {
		t.Fatal(err)
	}
	made := filepath.Join(target, "made.txt")
	if err := os.WriteFile(made, []byte("made plain"), 0o644); err != nil {
		t.Fatal(err)
	}
	normalizeOwner(t, made, owner)
	self := filepath.Join(target, "self.txt")
	if err := os.WriteFile(self, []byte("the sandbox wrote this"), 0o644); err != nil {
		t.Fatal(err)
	}
	normalizeOwner(t, self, owner)
	// A protected list granting the owner full control: the shape a sandbox
	// writes while it holds every right, with nothing inherited and no mark.
	setSDDL(t, self, `D:P(A;;FA;;;`+owner+`)`)

	if err := TakeBack(target, owner, nil); err != nil {
		t.Fatal(err)
	}

	if !holds(t, self, "OWNER RIGHTS", "(RX)") {
		t.Fatal("the revoke left the owner of a self-granted list uncapped")
	}
	if holds(t, self, name, "(F)") {
		t.Fatal("the full control the sandbox granted itself did not survive the revoke")
	}
	if err := os.WriteFile(self, []byte("tampered"), 0o644); err == nil {
		t.Fatal("a file the sandbox handed itself full control on was rewritten after the revoke")
	}
	if got, err := os.ReadFile(self); err != nil || string(got) != "the sandbox wrote this" {
		t.Fatalf("the content of %s changed: %q (%v)", self, got, err)
	}
	if !holds(t, made, "OWNER RIGHTS", "(RX)") {
		t.Fatal("the file made plain beside it was left uncapped by the revoke")
	}

	reclaimTree(t, root)
}
