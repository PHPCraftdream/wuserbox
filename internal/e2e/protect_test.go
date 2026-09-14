package e2e

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
)

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// place writes a file as the owner, from outside the sandbox.
func place(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestProtectedSettingsCannotBeRewritten(t *testing.T) {
	box := newBox(t)
	// The rules file lives outside every directory the sandbox was given,
	// the way ~/.wuserbox.ktav lives in the profile root.
	rules := filepath.Join(box.denied, "wuserbox.ktav")
	place(t, rules, "projects: []\n")
	if err := acl.Protect(rules); err != nil {
		t.Fatalf("protect: %v", err)
	}
	mustFail(t, box.state, writeFileCommand(rules))
	mustNotDelete(t, box, rules)
	mustSucceed(t, box.state, []string{"cmd.exe", "/c", "type " + rules})
	place(t, rules, "still mine\n") // the owner keeps full access
}

// TestAPermissionOnADirectoryReachesTheFilesAlreadyInIt records the Windows
// behavior that shapes the whole design: handing over a directory rewrites
// the permissions of the files already in it. That is why the profile root is
// never handed over by default.
func TestAPermissionOnADirectoryReachesTheFilesAlreadyInIt(t *testing.T) {
	box := newBox(t)
	existing := filepath.Join(box.denied, "dotfile")
	place(t, existing, "settings")
	if err := box.state.Add(box.denied, grant.HomeTop); err != nil {
		t.Fatal(err)
	}
	mustSucceed(t, box.state, writeFileCommand(existing))
}

// TestRefusalBeatsAnInheritedPermission covers the guard that makes the opt-in
// profile-root permission safe: every sensitive file gets an explicit refusal.
func TestRefusalBeatsAnInheritedPermission(t *testing.T) {
	box := newBox(t)
	sensitive := filepath.Join(box.denied, "profile")
	place(t, sensitive, "run something dangerous")
	if err := box.state.Add(box.denied, grant.HomeTop); err != nil {
		t.Fatal(err)
	}
	if err := grant.Refuse(box.state.SID, sensitive); err != nil {
		t.Fatalf("refuse: %v", err)
	}
	mustFail(t, box.state, writeFileCommand(sensitive))
	mustNotDelete(t, box, sensitive)
	// New files are still allowed, which is what an agent needs.
	mustSucceed(t, box.state, writeFileCommand(filepath.Join(box.denied, "fresh.txt")))
}

// TestProtectionHoldsEvenInsideAHandedOverDirectory checks the stronger of the
// two possible outcomes: a file whose permissions name neither the sandbox nor
// Everyone survives, even when the directory around it was handed over and a
// normal file there would be deleted.
func TestProtectionHoldsEvenInsideAHandedOverDirectory(t *testing.T) {
	box := newBox(t)
	target := filepath.Join(box.granted, "protected.txt")
	place(t, target, "x")
	if err := acl.Protect(target); err != nil {
		t.Fatal(err)
	}
	mustFail(t, box.state, writeFileCommand(target))
	mustNotDelete(t, box, target)
	// A file the sandbox is meant to own goes away as usual.
	ordinary := filepath.Join(box.granted, "ordinary.txt")
	place(t, ordinary, "x")
	runSandboxed(t, box.state, []string{"cmd.exe", "/c", "del /q " + ordinary})
	if exists(ordinary) {
		t.Error("an ordinary file in the project directory should be deletable")
	}
}

func TestProtectionSurvivesAPermissionOnTheParent(t *testing.T) {
	box := newBox(t)
	target := filepath.Join(box.denied, "protected.txt")
	place(t, target, "x")
	if err := acl.Protect(target); err != nil {
		t.Fatal(err)
	}
	// Hand the directory over afterwards: the file keeps its own permissions,
	// because inheritance was switched off.
	if err := box.state.Add(box.denied, grant.HomeTop); err != nil {
		t.Fatal(err)
	}
	mustSucceed(t, box.state, writeFileCommand(filepath.Join(box.denied, "sibling.txt")))
	mustFail(t, box.state, writeFileCommand(target))
}

func TestRecursiveDeleteStopsAtTheSandboxBoundary(t *testing.T) {
	box := newBox(t)
	outside := filepath.Join(box.denied, "precious.txt")
	inside := filepath.Join(box.granted, "scratch.txt")
	place(t, outside, "data")
	place(t, inside, "data")

	// Whether anything outside can be removed at all is a property of the
	// machine's temporary directory, and has to be asked before the sweep
	// rather than after, when there may be nothing left to ask about. It is
	// asked about the control file: asking about the file this test guards
	// would turn a broken boundary into a skipped test.
	skipIfTheMachineIsOpen(t, box)

	// A sweeping delete over the whole tree, the way `rm -rf` behaves.
	runSandboxed(t, box.state, []string{"cmd.exe", "/c", "rmdir /s /q " + box.root})

	if !exists(outside) {
		t.Error("a file outside the sandbox was deleted")
	}
	if !exists(box.root) {
		t.Error("the parent directory itself was removed")
	}
	if exists(inside) {
		t.Error("the project directory should be the sandbox's to destroy")
	}
}

func TestSandboxCannotChangeItsOwnPermissions(t *testing.T) {
	box := newBox(t)
	mustFail(t, box.state, []string{"cmd.exe", "/c",
		"icacls " + box.denied + " /grant *" + box.state.SID + ":(OI)(CI)M"})
	mustFail(t, box.state, writeFileCommand(filepath.Join(box.denied, "after-icacls.txt")))
}

func TestTwoSandboxesCannotReachEachOther(t *testing.T) {
	first, second := newBox(t), newBox(t)
	if first.state.SID == second.state.SID {
		t.Fatal("two sandboxes were given the same identity")
	}
	target := filepath.Join(second.granted, "crossed.txt")
	mustFail(t, first.state, writeFileCommand(target))
	if exists(target) {
		t.Error("one sandbox wrote into another's project directory")
	}
	if first.state.Temp == second.state.Temp {
		t.Error("two sandboxes share a temp directory")
	}
	mustFail(t, first.state, writeFileCommand(filepath.Join(second.state.Temp, "crossed.txt")))
}

// TestABrokenBoundaryIsAFailureAndNotASkip guards the guard. These tests
// excuse themselves on a machine whose temporary directory hands out rights of
// its own, and that excuse used to be decided by asking whether the sandbox
// could delete the very file under test. A token or an access control entry
// that stopped working would then answer yes, and a security failure would
// have been reported as a skipped test.
func TestABrokenBoundaryIsAFailureAndNotASkip(t *testing.T) {
	box := newBox(t)
	target := filepath.Join(box.denied, "precious.txt")
	place(t, target, "x")
	// What a broken sandbox looks like: the file it must not touch is
	// reachable after all.
	if err := box.state.Add(target, grant.File); err != nil {
		t.Fatal(err)
	}
	if outcome, _ := attemptDelete(t, box, target); outcome != deleted {
		t.Errorf("a file the sandbox could delete was reported as %v, want %v", outcome, deleted)
	}
}

// TestAnOpenMachineIsWhatMakesAQuestionUnanswerable keeps the other half of
// that decision working: where the machine gives the right away by itself, the
// control file says so and the question is not answered wrongly.
func TestAnOpenMachineIsWhatMakesAQuestionUnanswerable(t *testing.T) {
	box := newBox(t)
	target := filepath.Join(box.denied, "precious.txt")
	place(t, target, "x")
	if outcome, _ := attemptDelete(t, box, target); outcome != refused {
		t.Fatalf("the boundary did not hold before the machine was made open: %v", outcome)
	}
	// The control file stands for what the machine hands out on its own.
	if err := box.state.Add(box.control, grant.File); err != nil {
		t.Fatal(err)
	}
	if outcome, _ := attemptDelete(t, box, target); outcome != unanswerable {
		t.Errorf("an open machine gave %v, want %v", outcome, unanswerable)
	}
	if !exists(target) {
		t.Error("the file was deleted while deciding that the question was unanswerable")
	}
}
