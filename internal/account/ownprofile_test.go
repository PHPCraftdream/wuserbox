package account

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
)

// junction puts a directory link at path pointing at target, the way a
// sandbox would: mklink /J needs no privilege at all, and a sandbox holds
// Full Control inside its own profile.
func junction(t *testing.T, path, target string) {
	t.Helper()
	out, err := exec.Command("cmd", "/c", "mklink", "/J", path, target).CombinedOutput()
	if err != nil {
		t.Fatalf("making a junction at %s: %v: %s", path, err, out)
	}
}

// me is an identifier to permission a profile with. Which one does not
// matter here -- nothing logs on as it -- so it is the caller's own, which
// every machine has and no test has to create.
func me(t *testing.T) sid.Value {
	t.Helper()
	value, err := sid.Lookup(os.Getenv("USERNAME"))
	if err != nil {
		t.Fatalf("this account cannot be looked up by its own name, which is not a machine this can measure on: %v", err)
	}
	return value
}

// TestMakingAProfileDoesNotReachThroughAJunction is the regression guard for
// the confused deputy one call before the one that was already guarded.
//
// A sandbox owns its own profile and needs no privilege to put a junction in
// it. --init builds the profile again on every run of it, as the machine's
// owner and elevated, so a link left where AppData belongs sent those
// directories somewhere the sandbox could never have created them itself.
//
// The control half says whether the door was open here at all. Windows has a
// mitigation for exactly this shape -- RedirectionGuard -- that a process
// turns on for itself, so a refusal below could as easily be the machine
// refusing as this code refusing. Plain MkdirAll is asked to walk the same
// junction first, and what it did is written into the log.
//
// It is written rather than skipped on, deliberately. What follows holds on
// any Windows, because os.Root refuses the traversal whatever the machine
// would have done, and this test is in the list CI holds to no skips -- a
// guard for a fix of this size should not be able to quietly not run. The
// log is there so a reader can tell a measurement from a tautology.
func TestMakingAProfileDoesNotReachThroughAJunction(t *testing.T) {
	outside := t.TempDir()
	profile := filepath.Join(t.TempDir(), "profile")
	if err := os.MkdirAll(profile, 0o700); err != nil {
		t.Fatal(err)
	}
	junction(t, filepath.Join(profile, "AppData"), outside)

	control := filepath.Join(profile, "AppData", "Control")
	err := os.MkdirAll(control, 0o700)
	_, landed := os.Stat(filepath.Join(outside, "Control"))
	switch {
	case err != nil:
		t.Logf("this machine refuses to create a directory through a junction at all: %v", err)
	case landed != nil:
		t.Log("MkdirAll did not follow the junction here, so the door this closes is already shut")
	default:
		if err := os.RemoveAll(filepath.Join(outside, "Control")); err != nil {
			t.Fatal(err)
		}
	}

	// The hive needs administrator rights and this does not measure the hive.
	// What is measured happens before it, and has to hold whether or not the
	// rest of the profile can be finished.
	_ = MakeProfile(profile, me(t))

	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("making the profile created %d entries outside it", len(entries))
		for _, e := range entries {
			t.Errorf("  %s", e.Name())
		}
	}
	// And the name is not pinned: a sandbox that plants one link must not be
	// able to stop its own profile from ever being built again.
	for _, sub := range []string{`AppData`, `AppData\Local`, `AppData\Roaming`, "Temp"} {
		info, err := os.Lstat(filepath.Join(profile, sub))
		if err != nil {
			t.Errorf("%s was not made inside the profile: %v", sub, err)
			continue
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			t.Errorf("%s inside the profile is %s, not a directory of its own", sub, info.Mode())
		}
	}
}

// TestMakingAProfileAgainLeavesWhatIsAlreadyThere keeps the healing above
// from turning into a sandbox losing its own work: only what is in the way
// of a directory goes, and a directory that is already right is left alone,
// contents and all.
func TestMakingAProfileAgainLeavesWhatIsAlreadyThere(t *testing.T) {
	profile := filepath.Join(t.TempDir(), "profile")
	if err := os.MkdirAll(filepath.Join(profile, `AppData\Roaming`), 0o700); err != nil {
		t.Fatal(err)
	}
	kept := filepath.Join(profile, `AppData\Roaming\settings.json`)
	if err := os.WriteFile(kept, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	_ = MakeProfile(profile, me(t))

	if _, err := os.Stat(kept); err != nil {
		t.Errorf("building the profile again took away what was already in it: %v", err)
	}
}
