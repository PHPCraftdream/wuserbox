package state

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
)

const testSID = "S-1-5-21-1111111111-2222222222-3333333333-765432"

func newState(t *testing.T) *State {
	t.Helper()
	t.Setenv("LOCALAPPDATA", t.TempDir())
	return &State{Group: "wub-test-" + t.Name(), SID: testSID, Dir: t.TempDir(), Temp: t.TempDir()}
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	s := newState(t)
	s.Grants = []grant.Spec{{Path: `C:\tools`, Kind: grant.RW}}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	got, err := Load(s.Group)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("state was not found after saving")
	}
	if got.SID != s.SID || got.Dir != s.Dir || len(got.Grants) != 1 {
		t.Errorf("state came back as %+v", got)
	}
}

func TestLoadMissingStateIsNotAnError(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	got, err := Load("wub-never-created")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("expected no state, got %+v", got)
	}
}

func TestAddRecordsGrantOnceAndPersists(t *testing.T) {
	s := newState(t)
	target := t.TempDir()
	if err := s.Add(target, grant.RW); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(target, grant.RW); err != nil {
		t.Fatal(err)
	}
	if len(s.Grants) != 1 {
		t.Errorf("grant recorded %d times", len(s.Grants))
	}
	if !s.Has(target) {
		t.Error("Has does not see the grant that was just added")
	}
	stored, err := Load(s.Group)
	if err != nil || stored == nil {
		t.Fatalf("state was not persisted: %v", err)
	}
	if len(stored.Grants) != 1 {
		t.Errorf("persisted grants: %+v", stored.Grants)
	}
}

func TestHasIgnoresCase(t *testing.T) {
	s := newState(t)
	target := t.TempDir()
	if err := s.Add(target, grant.RW); err != nil {
		t.Fatal(err)
	}
	if !s.Has(filepath.Clean(target)) {
		t.Error("exact path not found")
	}
	if !s.Has(strings.ToUpper(target)) {
		t.Error("upper-case spelling of the path not found")
	}
	if !s.Has(strings.ToLower(target)) {
		t.Error("lower-case spelling of the path not found")
	}
}

func TestRemoveDropsTheGrant(t *testing.T) {
	s := newState(t)
	target := t.TempDir()
	if err := s.Add(target, grant.RW); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(target); err != nil {
		t.Fatal(err)
	}
	if s.Has(target) {
		t.Error("grant survived removal")
	}
	if err := s.Remove(target); err == nil {
		t.Error("removing an unknown grant should be an error")
	}
}

func TestSaveWritesReadableJSON(t *testing.T) {
	s := newState(t)
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(Path(s.Group))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		t.Error("state file should end with a newline")
	}
}

func TestAddReplacesAGrantOfADifferentKind(t *testing.T) {
	s := newState(t)
	target := t.TempDir()
	if err := s.Add(target, grant.RW); err != nil {
		t.Fatal(err)
	}
	// Narrowing the access has to take effect, not be swallowed because the
	// path is already listed.
	if err := s.Add(target, grant.RO); err != nil {
		t.Fatal(err)
	}
	if len(s.Grants) != 1 {
		t.Fatalf("the path was recorded twice: %+v", s.Grants)
	}
	kind, found := s.Kind(target)
	if !found || kind != grant.RO {
		t.Errorf("recorded kind is %q, want %q", kind, grant.RO)
	}
	stored, err := Load(s.Group)
	if err != nil || stored == nil {
		t.Fatalf("state was not persisted: %v", err)
	}
	if stored.Grants[0].Kind != grant.RO {
		t.Errorf("persisted kind is %q", stored.Grants[0].Kind)
	}
	// Widening it again works the same way.
	if err := s.Add(target, grant.RW); err != nil {
		t.Fatal(err)
	}
	if kind, _ := s.Kind(target); kind != grant.RW {
		t.Errorf("recorded kind is %q after widening", kind)
	}
}

func TestKindReportsAMissingPath(t *testing.T) {
	s := newState(t)
	if _, found := s.Kind(t.TempDir()); found {
		t.Error("a path that was never granted was reported as recorded")
	}
}

// TestOfferYieldsToWhatSomebodyAskedFor pins the rule the agent preset relies
// on: a permission offered on every start must not undo one that was asked
// for by hand.
func TestOfferYieldsToWhatSomebodyAskedFor(t *testing.T) {
	s := newState(t)
	dir := t.TempDir()
	if err := s.Add(dir, grant.RO); err != nil {
		t.Fatal(err)
	}
	if err := s.Offer(dir, grant.RW); err != nil {
		t.Fatal(err)
	}
	if kind, _ := s.Kind(dir); kind != grant.RO {
		t.Errorf("an offer overrode a request: the record says %q", kind)
	}
}

// TestOfferStillFillsInWhatNobodyMentioned keeps an offer doing its work where
// nothing has been said, and keeps it silent about who asked.
func TestOfferStillFillsInWhatNobodyMentioned(t *testing.T) {
	s := newState(t)
	dir := t.TempDir()
	if err := s.Offer(dir, grant.RW); err != nil {
		t.Fatal(err)
	}
	if kind, found := s.Kind(dir); !found || kind != grant.RW {
		t.Fatalf("the offer was not recorded: kind %q, found %v", kind, found)
	}
	if s.Grants[0].Explicit {
		t.Error("an offer was recorded as something somebody asked for")
	}

	// Asking for it afterwards makes it a request, and later offers yield.
	if err := s.Add(dir, grant.RO); err != nil {
		t.Fatal(err)
	}
	if !s.Grants[0].Explicit {
		t.Fatal("asking for a directory did not mark it as asked for")
	}
	if err := s.Offer(dir, grant.RW); err != nil {
		t.Fatal(err)
	}
	if kind, _ := s.Kind(dir); kind != grant.RO {
		t.Errorf("the record says %q after an offer", kind)
	}
}

// TestTheMarkSurvivesTheRecordBeingReread matters because the preset runs in a
// later process than the request it must not undo.
func TestTheMarkSurvivesTheRecordBeingReread(t *testing.T) {
	s := newState(t)
	dir := t.TempDir()
	if err := s.Add(dir, grant.RO); err != nil {
		t.Fatal(err)
	}
	reread, err := Load(s.Group)
	if err != nil {
		t.Fatal(err)
	}
	if reread == nil || len(reread.Grants) != 1 || !reread.Grants[0].Explicit {
		t.Fatalf("the mark did not survive: %+v", reread)
	}
	if err := reread.Offer(dir, grant.RW); err != nil {
		t.Fatal(err)
	}
	if kind, _ := reread.Kind(dir); kind != grant.RO {
		t.Errorf("a fresh process widened it back to %q", kind)
	}
}

// TestLockedKeepsBothChangesToOneSandbox is the regression guard for two
// commands that each read the record, each hand over a different directory and
// each write back. The second write used to be made from a record read before
// the first, so one permission stayed in force on disk while nothing pointed
// at it: explain did not mention it and revoke could not find it.
func TestLockedKeepsBothChangesToOneSandbox(t *testing.T) {
	s := newState(t)
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	first, second := t.TempDir(), t.TempDir()

	var wg sync.WaitGroup
	failures := make(chan error, 2)
	for _, dir := range []string{first, second} {
		wg.Add(1)
		go func(dir string) {
			defer wg.Done()
			failures <- Locked(s.Group, func() error {
				loaded, err := Load(s.Group)
				if err != nil {
					return err
				}
				// The window the other command used to slip into.
				time.Sleep(20 * time.Millisecond)
				return loaded.Add(dir, grant.RW)
			})
		}(dir)
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}

	final, err := Load(s.Group)
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{first, second} {
		if !final.Has(dir) {
			t.Errorf("%s is granted on disk but missing from the record: %+v", dir, final.Grants)
		}
	}
}

// TestLockedCanBeTakenAgainAfterAFailure keeps a command that gives up from
// leaving the sandbox locked for everything that comes after it.
func TestLockedCanBeTakenAgainAfterAFailure(t *testing.T) {
	s := newState(t)
	wanted := errors.New("no")
	if err := Locked(s.Group, func() error { return wanted }); !errors.Is(err, wanted) {
		t.Fatalf("the error did not come back: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- Locked(s.Group, func() error { return nil }) }()
	select {
	case err := <-done:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(5 * time.Second):
		t.Error("the lock was never let go after the work failed")
	}
}

// TestLockedShutsOutAnotherProcess is what the whole mechanism is for: the
// commands that race are separate runs of wuserbox, started by the user, by a
// script, or by wuserbox itself when it needs administrator rights.
func TestLockedShutsOutAnotherProcess(t *testing.T) {
	local := t.TempDir()
	t.Setenv("LOCALAPPDATA", local)
	release, err := take("wub-two-processes")
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	other := exec.Command(os.Args[0], "-test.run=TestLockHelperTakesTheLock")
	other.Env = append(os.Environ(), lockHelperEnv+"=1", "LOCALAPPDATA="+local)
	if err := other.Start(); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- other.Wait() }()

	select {
	case <-finished:
		t.Fatal("the other process took the lock while this one held it")
	case <-time.After(500 * time.Millisecond):
	}
	release()
	select {
	case err := <-finished:
		if err != nil {
			t.Errorf("the other process failed: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Error("the other process never got the lock after it was let go")
	}
}

const lockHelperEnv = "WUSERBOX_LOCK_HELPER"

// TestLockHelperTakesTheLock is the second process of the test above. It does
// nothing when run as part of an ordinary test run.
func TestLockHelperTakesTheLock(t *testing.T) {
	if os.Getenv(lockHelperEnv) == "" {
		t.Skip("runs only as the second process of TestLockedShutsOutAnotherProcess")
	}
	release, err := take("wub-two-processes")
	if err != nil {
		t.Fatal(err)
	}
	release()
}

// TestARecordFromBeforeTheMarkKeepsItsNarrowing is the regression guard for
// the upgrade itself. The mark that tells a request apart from an offer was
// added to the record, and a file written by an earlier build has none, so
// every permission in it read back as an offer: a directory narrowed by hand
// would have been widened again by the next run of the preset.
func TestARecordFromBeforeTheMarkKeepsItsNarrowing(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	group := "wub-old-record"
	narrowed := t.TempDir()
	old := `{
  "group": "` + group + `",
  "sid": "` + testSID + `",
  "dir": ` + quote(t, t.TempDir()) + `,
  "temp": ` + quote(t, t.TempDir()) + `,
  "grants": [
    {"path": ` + quote(t, narrowed) + `, "kind": "ro"}
  ]
}`
	if err := os.MkdirAll(filepath.Dir(Path(group)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(Path(group), []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(group)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Grants[0].Explicit {
		t.Error("a permission from an older record was read as something nobody asked for")
	}
	// What the preset does on the next run must leave it alone.
	if err := loaded.Offer(narrowed, grant.RW); err != nil {
		t.Fatal(err)
	}
	if kind, _ := loaded.Kind(narrowed); kind != grant.RO {
		t.Errorf("the upgrade widened a narrowed directory to %q", kind)
	}
}

// TestANewRecordSaysItCarriesTheMark keeps the upgrade from running twice: a
// record written now must never be adopted again, or an offer recorded today
// would turn into a request tomorrow.
func TestANewRecordSaysItCarriesTheMark(t *testing.T) {
	s := newState(t)
	offered := t.TempDir()
	if err := s.Offer(offered, grant.RW); err != nil {
		t.Fatal(err)
	}
	reread, err := Load(s.Group)
	if err != nil {
		t.Fatal(err)
	}
	if !reread.Marked {
		t.Fatal("a record written now does not say it carries the mark")
	}
	if reread.Grants[0].Explicit {
		t.Error("an offer came back as something somebody asked for")
	}
}

// quote renders a path as a JSON string, so a Windows path lands in the test
// data with its backslashes intact.
func quote(t *testing.T, path string) string {
	t.Helper()
	encoded, err := json.Marshal(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
