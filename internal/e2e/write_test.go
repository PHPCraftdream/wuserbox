package e2e

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/paths"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
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

func TestRefusesWritesToPublicAndProgramData(t *testing.T) {
	box := newBox(t)
	for _, dir := range []string{`C:\Users\Public`, `C:\ProgramData`} {
		target := filepath.Join(dir, "wuserbox-escape-check.txt")
		if _, err := os.Stat(target); err == nil {
			continue
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
