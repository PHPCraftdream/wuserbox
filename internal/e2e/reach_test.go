// What a sandbox reaches inside what it was handed: reading, which is never
// restricted, and writing, which is exactly what the grant decides.

package e2e

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/win/access"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
	"github.com/PHPCraftdream/wuserbox/internal/win/group"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
)

func TestWritesInsideTheProjectDirectory(t *testing.T) {
	box := newBox(t)
	target := filepath.Join(box.granted, "created.txt")
	mustSucceed(t, box.state, writeFileCommand(target))
	if _, err := os.Stat(target); err != nil {
		t.Errorf("file was reported as written but is missing: %v", err)
	}
}

func TestWritesIntoNewSubdirectories(t *testing.T) {
	box := newBox(t)
	nested := filepath.Join(box.granted, "a", "b")
	mustSucceed(t, box.state, []string{"cmd.exe", "/c", "mkdir " + nested})
	mustSucceed(t, box.state, writeFileCommand(filepath.Join(nested, "deep.txt")))
}

func TestDeletesInsideTheProjectDirectory(t *testing.T) {
	box := newBox(t)
	target := filepath.Join(box.granted, "temporary.txt")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	mustSucceed(t, box.state, []string{"cmd.exe", "/c", "del /q " + target})
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("file survived deletion: %v", err)
	}
}

func TestRefusesWritesToASiblingDirectory(t *testing.T) {
	box := newBox(t)
	target := filepath.Join(box.denied, "escaped.txt")
	mustFail(t, box.state, writeFileCommand(target))
	if _, err := os.Stat(target); err == nil {
		t.Error("a file was created outside the sandbox")
		os.Remove(target)
	}
}

func TestRefusesWritesToTheParentDirectory(t *testing.T) {
	box := newBox(t)
	target := filepath.Join(box.root, "escaped.txt")
	mustFail(t, box.state, writeFileCommand(target))
	if _, err := os.Stat(target); err == nil {
		t.Error("a file was created in the parent directory")
		os.Remove(target)
	}
}

func TestRefusesWritesToTheUserProfile(t *testing.T) {
	box := newBox(t)
	target := filepath.Join(paths.Home(), "wuserbox-escape-check.txt")
	if _, err := os.Stat(target); err == nil {
		t.Skipf("%s already exists; refusing to touch it", target)
	}
	mustFail(t, box.state, writeFileCommand(target))
	if _, err := os.Stat(target); err == nil {
		t.Error("a file was created in the user profile")
		os.Remove(target)
	}
}

// TestRefusesWritesToPublicAndProgramData is scoped to what a sandbox can
// actually be asked to refuse. BUILTIN\Users has to sit in every restricted
// list, or a sandbox could not read System32 or Program Files, and some
// machines — this compatibility setting is not universal — also grant Users
// write access to shared system directories like C:\ProgramData by Windows'
// own default. A sandbox cannot refuse what every local account already has
// there regardless of it, so that case is skipped rather than asserted.
func TestRefusesWritesToPublicAndProgramData(t *testing.T) {
	box := newBox(t)
	for _, dir := range []string{`C:\Users\Public`, `C:\ProgramData`} {
		target := filepath.Join(dir, "wuserbox-escape-check.txt")
		if _, err := os.Stat(target); err == nil {
			continue
		}
		if err := os.WriteFile(target, []byte("probe"), 0o644); err == nil {
			os.Remove(target)
			t.Skipf("%s already accepts writes from any local account on this machine", dir)
		}
		mustFail(t, box.state, writeFileCommand(target))
		if _, err := os.Stat(target); err == nil {
			t.Errorf("a file was created in %s", dir)
			os.Remove(target)
		}
	}
}

func TestRefusesWritesToTheRegistry(t *testing.T) {
	box := newBox(t)
	mustFail(t, box.state, []string{"cmd.exe", "/c", `reg add HKCU\Software\wuserbox-escape-check /f`})
}

func TestGrantMakesAnotherDirectoryWritable(t *testing.T) {
	box := newBox(t)
	target := filepath.Join(box.denied, "allowed.txt")
	mustFail(t, box.state, writeFileCommand(target))

	if err := box.state.Add(box.denied, grant.RW); err != nil {
		t.Fatalf("grant: %v", err)
	}
	mustSucceed(t, box.state, writeFileCommand(target))
}

func TestRevokeTakesWriteAccessBack(t *testing.T) {
	box := newBox(t)
	if err := box.state.Add(box.denied, grant.RW); err != nil {
		t.Fatalf("grant: %v", err)
	}
	mustSucceed(t, box.state, writeFileCommand(filepath.Join(box.denied, "before.txt")))

	if err := box.state.Remove(box.denied); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	mustFail(t, box.state, writeFileCommand(filepath.Join(box.denied, "after.txt")))
}

func TestReadOnlyGrantDoesNotAllowWrites(t *testing.T) {
	box := newBox(t)
	if err := box.state.Add(box.denied, grant.RO); err != nil {
		t.Fatalf("grant: %v", err)
	}
	existing := filepath.Join(box.denied, "readable.txt")
	if err := os.WriteFile(existing, []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}
	mustSucceed(t, box.state, []string{"cmd.exe", "/c", "type " + existing})
	mustFail(t, box.state, writeFileCommand(filepath.Join(box.denied, "written.txt")))
}

// TestHomeTopHoldsWhereTheMachineHandsOutNothing is the regression guard for a
// question that asked for more than the deed needs. Creating a file was checked
// for the right to traverse and to list the directory as well as to add to it,
// and the two extra rights were supplied by whatever the machine handed out on
// its own, so the mistake was invisible anywhere %TEMP% is generous and plain
// on a real Windows profile, which grants Everyone and BUILTIN\Users nothing.
// There --home-writes worked and --explain called it broken.
//
// The directory is stripped of what this machine hands out, so the test asks
// the same question on every machine, and the answer and the deed are checked
// together: a check that disagrees with what actually happens is the defect.
func TestHomeTopHoldsWhereTheMachineHandsOutNothing(t *testing.T) {
	box := newBox(t)
	top := filepath.Join(box.root, "profile")
	if err := os.Mkdir(top, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := box.state.Add(top, grant.HomeTop); err != nil {
		t.Fatal(err)
	}
	for _, who := range []string{sid.Everyone, sid.Users} {
		if err := acl.StripOwn(top, who); err != nil {
			t.Fatal(err)
		}
	}

	target := filepath.Join(top, "new.txt")
	answer, err := access.Check(box.state.SID, target, access.Create)
	if err != nil {
		t.Fatal(err)
	}
	mustSucceed(t, box.state, writeFileCommand(target))
	if !answer.Allowed {
		t.Errorf("the sandbox created the file, yet the check refused it: %s", answer.Reason)
	}
}

func TestHomeTopAllowsNewFilesButNotSubdirectories(t *testing.T) {
	box := newBox(t)
	sub := filepath.Join(box.denied, "child")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := box.state.Add(box.denied, grant.HomeTop); err != nil {
		t.Fatalf("grant: %v", err)
	}
	mustSucceed(t, box.state, writeFileCommand(filepath.Join(box.denied, "top.txt")))
	mustFail(t, box.state, writeFileCommand(filepath.Join(sub, "nested.txt")))
}

// TestNarrowingADirectoryInsideAHandedOverOneTakesEffect is the regression
// guard for a read-only grant that was read-only in name only. A permission
// reaches everything below the directory it is set on, so leaving the write
// bits out of the nested grant changed nothing: the sandbox kept writing
// through the permission it had on the parent.
func TestNarrowingADirectoryInsideAHandedOverOneTakesEffect(t *testing.T) {
	box := newBox(t)
	nested := filepath.Join(box.granted, "reference")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(nested, "written.txt")
	mustSucceed(t, box.state, writeFileCommand(target))
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}

	if err := box.state.Add(nested, grant.RO); err != nil {
		t.Fatal(err)
	}
	mustFail(t, box.state, writeFileCommand(target))
	if exists(target) {
		t.Error("a directory narrowed to read-only is still writable")
	}
	// Reading still works, which is the other half of what read-only means.
	place(t, filepath.Join(nested, "readable.txt"), "content")
	mustSucceed(t, box.state, []string{"cmd.exe", "/c", "type " + filepath.Join(nested, "readable.txt")})
	// And the directory around it is untouched.
	mustSucceed(t, box.state, writeFileCommand(filepath.Join(box.granted, "sibling.txt")))
}

// TestNarrowingADirectoryStopsWritesInsideIt is the same fault seen from
// inside a sandbox: a directory handed over separately kept its own permission,
// which Windows reads before the refusal handed down from the directory above
// it, so the write went through after the parent had been made read-only.
func TestNarrowingADirectoryStopsWritesInsideIt(t *testing.T) {
	box := newBox(t)
	parent := filepath.Join(box.denied, "settings")
	child := filepath.Join(parent, "tool")
	if err := os.MkdirAll(child, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{parent, child} {
		if err := box.state.Add(dir, grant.RW); err != nil {
			t.Fatal(err)
		}
	}
	mustSucceed(t, box.state, writeFileCommand(filepath.Join(child, "before.txt")))

	if err := box.state.Add(parent, grant.RO); err != nil {
		t.Fatal(err)
	}
	mustFail(t, box.state, writeFileCommand(filepath.Join(parent, "after.txt")))
	mustFail(t, box.state, writeFileCommand(filepath.Join(child, "after.txt")))
	if exists(filepath.Join(child, "after.txt")) {
		t.Error("the sandbox wrote inside a directory that was made read-only")
	}
}

// needsReadGroup leaves a test unrun where group.ReadGroup was never created.
// Creating it needs administrator rights, the same as a sandbox's own group,
// so an unprivileged run of these tests has nowhere to get it from.
func needsReadGroup(t *testing.T) {
	t.Helper()
	if _, exists, err := group.Comment(group.ReadGroup); err != nil {
		t.Fatal(err)
	} else if !exists {
		t.Skip("wub-read does not exist yet; run `wuserbox --init` elevated once to cover profile reads")
	}
}

func TestReadsFilesTheCallerCanRead(t *testing.T) {
	box := newBox(t)
	// This file lives outside the sandbox and has no entry for its SID.
	secretish := filepath.Join(box.denied, "caller-owned.txt")
	if err := os.WriteFile(secretish, []byte("readable"), 0o644); err != nil {
		t.Fatal(err)
	}
	mustSucceed(t, box.state, []string{"cmd.exe", "/c", "type " + secretish})
}

func TestReadsTheUserProfile(t *testing.T) {
	needsReadGroup(t)
	box := newBox(t)
	mustSucceed(t, box.state, script(t, box, `dir /b "%USERPROFILE%" >nul`))
}

func TestStartsProgramsThatLoadTheWindowSubsystem(t *testing.T) {
	// Without Everyone among the restricting SIDs every process that loads
	// user32 dies at startup with 0xC0000142. This is the regression guard.
	box := newBox(t)
	mustSucceed(t, box.state, []string{`C:\Windows\System32\whoami.exe`})
}

func TestChildProcessesStayRestricted(t *testing.T) {
	box := newBox(t)
	script := filepath.Join(box.granted, "escape.cmd")
	target := filepath.Join(box.denied, "via-child.txt")
	body := "@echo off\r\ncmd.exe /c echo x>" + target + "\r\n"
	if err := os.WriteFile(script, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	mustFail(t, box.state, []string{script})
	if _, err := os.Stat(target); err == nil {
		t.Error("a child process wrote outside the sandbox")
		os.Remove(target)
	}
}

func TestTemporaryFilesLandInTheSandboxDirectory(t *testing.T) {
	box := newBox(t)
	mustSucceed(t, box.state, script(t, box, `echo x>"%TEMP%\scratch.txt"`))
	if _, err := os.Stat(filepath.Join(box.state.Temp, "scratch.txt")); err != nil {
		t.Errorf("TEMP was not redirected into the sandbox: %v", err)
	}
}
