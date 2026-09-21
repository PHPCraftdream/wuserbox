// The delete boundary itself: what a sandbox may remove inside what it was
// given, what it may not remove outside, and what taking the grant back or
// narrowing it does to that. Most of these are named one by one in the build
// and may never skip.

package e2e

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/win/access"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
	"github.com/PHPCraftdream/wuserbox/internal/win/quietexec"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
)

// TestDeletingOutsideTheBoundaryIsRefused is the regression guard for the way
// a sandbox could destroy anything its user owned.
//
// A fully restricted token checks every access, deleting included, against
// the sandbox's own restricting identifiers — not only writes, the way a
// write-restricted token's second check did, which left DELETE and
// FILE_DELETE_CHILD answering to the caller's own account instead. By
// Windows' own defaults a user's account holds Full Control all the way down
// their home directory, Full Control included the right to remove things
// inside it whatever they said about themselves, and a write-restricted
// sandbox kept that right wherever the account already had it.
//
// The parent here is given exactly that shape on purpose, rather than
// whatever the machine's temporary directory happens to hand out, so the test
// asks the same question everywhere it runs.
func TestDeletingOutsideTheBoundaryIsRefused(t *testing.T) {
	box := newBox(t)

	outside := filepath.Join(box.root, "not-granted")
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	// Owner, system and administrators, with nothing for the sandbox or for
	// Everyone: the shape C:\Users\<name> has by default.
	if err := acl.Protect(outside); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(outside, "precious.txt")
	place(t, target, "data")

	mustFail(t, box.state, writeFileCommand(target))
	runSandboxed(t, box.state, []string{"cmd.exe", "/c", "del /q " + target})
	if !exists(target) {
		t.Error("a file outside every granted directory was deleted from inside the sandbox")
	}
}

// TestASweepStopsAtTheBoundary is the same guarantee against the command an
// agent actually reaches for when it goes wrong: a recursive delete over
// everything in sight.
func TestASweepStopsAtTheBoundary(t *testing.T) {
	box := newBox(t)

	outside := filepath.Join(box.root, "not-granted")
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := acl.Protect(outside); err != nil {
		t.Fatal(err)
	}
	kept := filepath.Join(outside, "precious.txt")
	place(t, kept, "data")
	own := filepath.Join(box.granted, "scratch.txt")
	place(t, own, "data")

	runSandboxed(t, box.state, []string{"cmd.exe", "/c", "rmdir /s /q " + box.root})

	if !exists(kept) {
		t.Error("a sweep reached a file outside the sandbox")
	}
	if !exists(outside) {
		t.Error("a sweep removed a directory outside the sandbox")
	}
	if exists(own) {
		t.Error("the project directory should still be the sandbox's to empty")
	}
}

// TestTheSandboxKeepsItsOwnWrites is the other side of the same change: the
// sandbox has to be able to write and delete inside what it was given.
func TestTheSandboxKeepsItsOwnWrites(t *testing.T) {
	box := newBox(t)

	target := filepath.Join(box.granted, "mine.txt")
	mustSucceed(t, box.state, writeFileCommand(target))
	if !exists(target) {
		t.Fatal("the sandbox could not write inside its own project directory")
	}
	runSandboxed(t, box.state, []string{"cmd.exe", "/c", "del /q " + target})
	if exists(target) {
		t.Error("the sandbox could not delete what it had just written")
	}
	// New subdirectories inherit the grant, or the sandbox loses the ability
	// to work inside what it just made.
	nested := filepath.Join(box.granted, "nested")
	mustSucceed(t, box.state, []string{"cmd.exe", "/c", "mkdir " + nested})
	mustSucceed(t, box.state, writeFileCommand(filepath.Join(nested, "deep.txt")))
}

// TestReadingIsStillUnrestricted keeps the promise the whole tool is built
// on. A fully restricted token's second check applies to every access, but
// Everyone and BUILTIN\Users still sit in the restricted list to make that
// possible, and grant.Apply only ever narrows either of them to read access,
// never takes reading away — so a sandbox that could no longer read the
// toolchain would be useless.
func TestReadingIsStillUnrestricted(t *testing.T) {
	box := newBox(t)

	outside := filepath.Join(box.root, "readable")
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(outside, "notes.txt")
	place(t, target, "readable")
	mustSucceed(t, box.state, []string{"cmd.exe", "/c", "type " + target})
}

// TestRevokingTakesTheDeleteBackToo is the regression guard for a permission
// that was revoked in name only. Deleting goes through the sandbox's own
// restricting identifier now, the same as any other access, so taking that
// identifier's entry away has to take the delete right with it.
func TestRevokingTakesTheDeleteBackToo(t *testing.T) {
	b := newBox(t)
	extra := filepath.Join(b.root, "extra")
	if err := os.Mkdir(extra, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := b.state.Add(extra, grant.RW); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(extra, "f.txt")
	place(t, target, "data")
	if err := b.state.Remove(extra); err != nil {
		t.Fatal(err)
	}

	runSandboxed(t, b.state, []string{"cmd.exe", "/c", "del /q " + target})
	if !exists(target) {
		t.Error("the sandbox deleted inside a directory it no longer holds")
	}
}

// TestNarrowingToReadOnlyTakesTheDeleteBackToo is the same guarantee for the
// other way a permission is taken away. Read-only that still lets the
// directory be emptied is not read-only.
func TestNarrowingToReadOnlyTakesTheDeleteBackToo(t *testing.T) {
	b := newBox(t)
	narrowed := filepath.Join(b.root, "narrowed")
	if err := os.Mkdir(narrowed, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := b.state.Add(narrowed, grant.RW); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(narrowed, "f.txt")
	place(t, target, "data")
	if err := b.state.Add(narrowed, grant.RO); err != nil {
		t.Fatal(err)
	}

	runSandboxed(t, b.state, []string{"cmd.exe", "/c", "del /q " + target})
	if !exists(target) {
		t.Error("the sandbox emptied a directory it holds read-only")
	}
}

// TestNarrowingNeverHandsOutReading is the regression guard for a narrowing
// that widened. Replacing what Everyone holds with read-and-execute is only a
// narrowing where reading was already part of it: on an entry that covered
// writing alone, it handed reading to every sandbox and to every account on
// the machine, which is what a grant is least entitled to do.
func TestNarrowingNeverHandsOutReading(t *testing.T) {
	a, b := newBox(t), newBox(t)
	// Outside any box, so nothing hands it an ambient reading permission.
	dir := filepath.Join(t.TempDir(), "write-only")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	if out, err := quietexec.Command("icacls", dir, "/inheritance:r",
		"/grant", "*"+owner+":(OI)(CI)F",
		"/grant", "*"+sid.System+":(OI)(CI)F",
		"/grant", "*"+sid.Everyone+":(OI)(CI)(WD)").CombinedOutput(); err != nil {
		t.Fatalf("arranging the directory: %v\n%s", err, out)
	}
	secret := filepath.Join(dir, "secret.txt")
	place(t, secret, "classified")
	if runSandboxed(t, a.state, []string{"cmd.exe", "/c", "type " + secret}) == 0 {
		t.Skip("this machine lets a sandbox read there already, so a widening could not be seen")
	}

	if err := b.state.Add(dir, grant.RW); err != nil {
		t.Fatal(err)
	}
	if runSandboxed(t, a.state, []string{"cmd.exe", "/c", "type " + secret}) == 0 {
		t.Error("granting the directory handed every sandbox the reading it did not have")
	}
}

// TestAProtectedFileInsideAGrantedDirectorySurvives is the regression guard
// for FILE_DELETE_CHILD. grant.RW's AccessModify does not include it — a
// sandbox's right to delete inside its own directory comes from DELETE on
// each file, inherited from the grant — so a file whose own permissions were
// replaced by acl.Protect, with inheritance switched off, never inherits
// that entry and the directory's own grant cannot reach around it.
func TestAProtectedFileInsideAGrantedDirectorySurvives(t *testing.T) {
	box := newBox(t)
	target := filepath.Join(box.granted, "protected.txt")
	place(t, target, "data")
	if err := acl.Protect(target); err != nil {
		t.Fatal(err)
	}
	mustFail(t, box.state, writeFileCommand(target))
	runSandboxed(t, box.state, []string{"cmd.exe", "/c", "del /q " + target})
	if !exists(target) {
		t.Error("a protected file inside a granted directory was deleted")
	}
}

// TestTheDiagnosticAgreesWithWhatHappens pairs every answer --check gives
// with the operation itself, deleting included: a fully restricted token
// applies the same two checks to every access, so --check's simulation and a
// real delete now agree the way they already did for every other operation —
// unlike a write-restricted token, whose second check never applied to
// deleting at all, which used to make a delete refusal from the simulation
// unusable as an answer.
//
// An answer that disagrees with the result is worse than no answer: it is the
// tool certifying a boundary it does not have, and somebody deciding what to
// hand over on the strength of it.
func TestTheDiagnosticAgreesWithWhatHappens(t *testing.T) {
	b := newBox(t)

	outside := filepath.Join(b.root, "not-granted")
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := acl.Protect(outside); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{
		filepath.Join(b.granted, "mine.txt"),
		filepath.Join(outside, "theirs.txt"),
	} {
		place(t, target, "data")
		answer, err := access.Check(access.Sandbox{Group: b.state.SID}, target, access.Delete)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		runSandboxed(t, b.state, []string{"cmd.exe", "/c", "del /q " + target})
		gone := !exists(target)

		if answer.Allowed != gone {
			t.Errorf("%s: --check said deleting is allowed=%v (%s), and the sandbox %s it",
				target, answer.Allowed, answer.Reason,
				map[bool]string{true: "deleted", false: "could not delete"}[gone])
		}
	}
}
