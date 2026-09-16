// The lease a run holds, measured from outside the process: at the command
// line, where the slot is now taken, and not at the launch inside. The
// defect that moved it is the subject of the first test here: with the slot
// held, a second run used to fill the shared profile before it was refused
// -- forgetting what the rules file no longer named is the form measured,
// because it takes a file away -- and the run that was going lost a file
// from its profile. What is asserted is the pair: the refusal itself, and
// the file the refused run's fill would have taken away still sitting in the
// profile. The second test holds init to the same standard: its probe
// births a stub through the same launch the lease used to live behind, and
// an ordering that made the probe take the slot again would refuse a
// command that is alone in the world -- five seconds of waiting, then
// "another run is already going", looking exactly like a flake.
//
// Both need administrator rights, like every test here that builds a real
// sandbox: init makes the account, and none of what stands between can be
// arranged without it. They run on CI and skip on a desk without elevation.
// This puts internal/e2e at ten entries where the layout rules ask for about
// seven. Named rather than quietly picked, as CONTRIBUTING asks: it shares
// the command-line harness with cli_test.go and neither the account fixture
// nor the window choreography of slot_test.go, and folding it into either
// would bury the one thing this file is about -- how much of a run the slot
// now covers.

package e2e

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/wuserbox/internal/base/lock"
	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox"
)

// stateDir is a directory to point LOCALAPPDATA at, taken away on the way out
// but not by t.TempDir, whose cleanup is allowed to fail the test and here
// does.
//
// Reading a rules file loads ktav's native library, and ktav extracts that
// library under LOCALAPPDATA before loading it. A DLL a process has loaded
// cannot be unlinked on Windows, and this process keeps it for as long as it
// runs, so t.TempDir's removal of the directory it was extracted into is
// refused -- "Access is denied" against ktav_cabi-windows-amd64.dll, and a
// test that had already measured everything it was written to measure failed
// on the way out.
//
// It failed in one selection of tests and not another, which is the part
// worth keeping: whichever test reads a rules file first pays the extraction,
// and in a whole-package run that was somebody else, under the real
// LOCALAPPDATA, where nothing tries to remove it. Best-effort removal is the
// honest answer rather than a cleanup that knows which file to spare -- what
// is left behind is a few megabytes under the system's temp directory, and
// only where this test was the first to touch ktav.
func stateDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "wuserbox-lease")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// leaseRunner drives the real command line against one project under one
// standing environment: the rules file named by WUSERBOX_CONFIG, the profile
// the rules copy from and the state directory are held fixed across calls,
// because the question asked here -- what did the second run change -- is
// asked across two of them.
func leaseRunner(t *testing.T, project, rules string) func(args ...string) (string, int) {
	t.Helper()
	return func(args ...string) (string, int) {
		t.Helper()
		cmd := exec.Command(binary(t), args...)
		cmd.Dir = project
		cmd.Env = append(os.Environ(), config.EnvPath+"="+rules)
		out, err := cmd.CombinedOutput()
		code := 0
		var failed *exec.ExitError
		if errors.As(err, &failed) {
			code = failed.ExitCode()
		} else if err != nil {
			t.Fatalf("running %v: %v", args, err)
		}
		return string(out), code
	}
}

// TestARunRefusedByTheSlotLeavesTheProfileAlone is the regression for the
// defect that moved the lease: a run refused for a held slot used to fill
// the shared profile first, and only then reach the launch and be refused.
func TestARunRefusedByTheSlotLeavesTheProfileAlone(t *testing.T) {
	requireAdministrator(t)
	home := t.TempDir() // the profile the rules file copies from
	t.Setenv("USERPROFILE", home)
	t.Setenv("LOCALAPPDATA", stateDir(t)) // the record, the facts and the slot

	const entry = "wub-lease-source.txt"
	const content = "the copy a first run holds"
	if err := os.WriteFile(filepath.Join(home, entry), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	rules := filepath.Join(t.TempDir(), "rules.ktav")
	// Set here as well as on the command below, because setRules writes the
	// file from this process and config.Path reads this process's own
	// environment: without it the rules are saved to the default location
	// while the command under test reads the empty path named here, and the
	// entry this test is about is never copied at all.
	t.Setenv(config.EnvPath, rules)
	setRules := func(entries ...string) {
		t.Helper()
		if err := (&config.Config{Profile: config.Entries(entries)}).Save(); err != nil {
			t.Fatal(err)
		}
	}

	project := t.TempDir()
	run := leaseRunner(t, project, rules)
	group, _, err := sandbox.Name(project)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { run("--rm") })

	setRules(entry)
	if out, code := run("--init"); code != 0 {
		t.Fatalf("init failed: %s", out)
	}
	s, err := state.Load(group)
	if err != nil || s == nil {
		t.Fatalf("loading the record init wrote: %v", err)
	}
	// Filling the profile is a run's work and not init's: init builds the
	// account, the profile directory and the record, and reads nothing from
	// the profile section. So the copy this test stands on arrives with the
	// first real run below, and is looked for after it rather than before.
	if out, code := run("cmd.exe", "/c", "exit 0"); code != 0 {
		t.Fatalf("the first run failed, so what is measured below is not a second run: %s", out)
	}
	copied := filepath.Join(s.Profile, entry)
	if got, err := os.ReadFile(copied); err != nil || string(got) != content {
		t.Fatalf("the first run did not leave the copy this test stands on: %v (%q)", err, got)
	}

	// The rules file stops naming the entry. The next fill would take the
	// copy back out of the sandbox's profile -- that is the change the
	// refused run must never get to make.
	setRules()

	// The slot, held the way a first run holds it: for as long as this
	// process keeps it, the sandbox is busy.
	release, err := lock.Lease(group, 5*time.Second)
	if err != nil {
		t.Fatalf("the slot was held before anything here held it: %v", err)
	}
	defer release()

	out, code := run("cmd.exe", "/c", "exit 0")
	if code == 0 {
		t.Fatal("a run whose sandbox's slot was held went ahead")
	}
	if !strings.Contains(out, "already going") {
		t.Errorf("the refusal does not say another run is going: %q", out)
	}
	got, err := os.ReadFile(copied)
	if err != nil {
		t.Fatalf("the refused run's fill removed the copy from the sandbox's profile: %v", err)
	}
	if string(got) != content {
		t.Errorf("the refused run rewrote the copy: %q", got)
	}
}

// TestInitProbesTheStubWhileHoldingTheLeaseItself is the guard for the
// ordering the move could get wrong: init holds the lease across its build
// and its probe, and the probe's birth reaches a slot its own command
// already holds, so it must not wait five seconds and then refuse itself.
func TestInitProbesTheStubWhileHoldingTheLeaseItself(t *testing.T) {
	requireAdministrator(t)
	t.Setenv("USERPROFILE", t.TempDir())
	t.Setenv("LOCALAPPDATA", stateDir(t))
	rules := filepath.Join(t.TempDir(), "rules.ktav")
	// Both here and on the command, for the reason the test above gives: the
	// file is written from this process and read by that one.
	t.Setenv(config.EnvPath, rules)
	if err := (&config.Config{}).Save(); err != nil {
		t.Fatal(err)
	}

	project := t.TempDir()
	run := leaseRunner(t, project, rules)
	t.Cleanup(func() { run("--rm") })

	// Twice, because the second init is also the leak detector: if the
	// first ever failed to let the slot go, the second waits out the five
	// seconds and is refused over a sandbox nobody else is using. The
	// failure this test exists to catch is deterministic either way: the
	// kernel refuses the second exclusive open of a file this command
	// holds, so nothing here depends on timing.
	for i := 0; i < 2; i++ {
		out, code := run("--init")
		if code != 0 {
			t.Fatalf("init %d failed: %s", i+1, out)
		}
		if strings.Contains(out, "already going") {
			t.Errorf("init %d waited on its own lease and refused itself: %q", i+1, out)
		}
	}
}
