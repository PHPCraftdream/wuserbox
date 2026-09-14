package e2e

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
)

// needsLabeling leaves a test unrun where the rights to write an integrity
// label are not held. It is a skip rather than a pass: the boundary these
// tests are about does not exist without the label, so pretending otherwise
// would report a sandbox as safe on exactly the machines where it is not.
func needsLabeling(t *testing.T) {
	t.Helper()
	if !acl.CanLabelHere() {
		t.Skip("writing an integrity label needs administrator rights; " +
			"run these elevated to cover the delete boundary")
	}
}

// labeledBox is newBox carrying the mark an elevated build leaves behind, so
// the sandbox actually runs at Low integrity. The mark is set here rather
// than taken on trust: these tests build their sandbox by hand, without the
// init that would otherwise set it, and every grant above went on labeled
// because needsLabeling has already established that labels can be written.
func labeledBox(t *testing.T) *box {
	t.Helper()
	b := newBox(t)
	b.state.Labeled = true
	if err := b.state.Save(); err != nil {
		t.Fatal(err)
	}
	return b
}

// TestDeletingOutsideTheBoundaryIsRefused is the regression guard for the way
// a sandbox could destroy anything its user owned.
//
// DELETE and FILE_DELETE_CHILD are not part of a file's generic-write
// mapping, so the second access check a write-restricted token gets never saw
// them: the sandbox kept the user's own right to delete wherever their
// account already held it. By Windows' own defaults that is the whole of
// their home directory, which grants the owner Full Control all the way down
// — and Full Control includes removing what is inside a directory, whatever
// the thing inside says about itself. Writing to the file was refused and
// deleting it succeeded.
//
// The parent here is given exactly that shape on purpose, rather than
// whatever the machine's temporary directory happens to hand out, so the test
// asks the same question everywhere it runs.
func TestDeletingOutsideTheBoundaryIsRefused(t *testing.T) {
	needsLabeling(t)
	box := labeledBox(t)

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
	needsLabeling(t)
	box := labeledBox(t)

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

// TestTheSandboxKeepsItsOwnWrites is the other side of the same change, and
// the one that would break first if a grant ever went on without its label:
// the sandbox has to be able to write and delete inside what it was given.
func TestTheSandboxKeepsItsOwnWrites(t *testing.T) {
	needsLabeling(t)
	box := labeledBox(t)

	target := filepath.Join(box.granted, "mine.txt")
	mustSucceed(t, box.state, writeFileCommand(target))
	if !exists(target) {
		t.Fatal("the sandbox could not write inside its own project directory")
	}
	runSandboxed(t, box.state, []string{"cmd.exe", "/c", "del /q " + target})
	if exists(target) {
		t.Error("the sandbox could not delete what it had just written")
	}
	// New subdirectories inherit the label, or the sandbox loses the ability
	// to work inside what it just made.
	nested := filepath.Join(box.granted, "nested")
	mustSucceed(t, box.state, []string{"cmd.exe", "/c", "mkdir " + nested})
	mustSucceed(t, box.state, writeFileCommand(filepath.Join(nested, "deep.txt")))
}

// TestReadingIsStillUnrestricted keeps the promise the whole tool is built
// on. Running Low restricts writing, not reading: the mandatory policy
// Windows applies by default is no-write-up, and a sandbox that could no
// longer read the toolchain would be useless.
func TestReadingIsStillUnrestricted(t *testing.T) {
	needsLabeling(t)
	box := labeledBox(t)

	outside := filepath.Join(box.root, "readable")
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(outside, "notes.txt")
	place(t, target, "readable")
	mustSucceed(t, box.state, []string{"cmd.exe", "/c", "type " + target})
}

// TestASandboxWithoutLabelsIsNotRunLow is the migration guard. A sandbox
// built before the labels existed carries none, and running it Low would
// refuse it its own writes rather than protect anything — so the record says
// so, and the token follows the record.
func TestASandboxWithoutLabelsIsNotRunLow(t *testing.T) {
	b := newBox(t)
	b.state.Labeled = false
	target := filepath.Join(b.granted, "still-writable.txt")
	mustSucceed(t, b.state, writeFileCommand(target))
	if !exists(target) {
		t.Error("a sandbox from before the boundary lost the writes it used to have")
	}
}
