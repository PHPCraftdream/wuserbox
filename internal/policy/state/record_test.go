// Tests for the record as a file: written whole, read back, held while it
// changes, and what happens when it stops being readable.

package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/wuserbox/internal/base/lock"
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

// TestTheRecordIsNeverSeenHalfWritten is the regression guard for a writer
// that emptied the file and filled it again. A command reading the record at
// that moment got half a document and failed with "unexpected end of JSON
// input", and readers do not take the writer's lock.
func TestTheRecordIsNeverSeenHalfWritten(t *testing.T) {
	s := newState(t)
	for i := 0; i < 300; i++ {
		s.Grants = append(s.Grants, grant.Spec{
			Path: fmt.Sprintf(`C:\some\directory\number%03d`, i), Kind: grant.RW,
		})
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	writing := make(chan error, 1)
	go func() {
		for i := 0; i < 200; i++ {
			s.Grants[0].Kind = grant.RW
			if err := s.Save(); err != nil {
				writing <- err
				return
			}
		}
		writing <- nil
	}()

	for {
		select {
		case err := <-writing:
			if err != nil {
				t.Fatalf("writing the record failed: %v", err)
			}
			return
		default:
		}
		loaded, err := Load(s.Group)
		if err != nil {
			t.Fatalf("a reader saw a record that was not whole: %v", err)
		}
		if loaded == nil || len(loaded.Grants) != len(s.Grants) {
			t.Fatalf("a reader saw %d of %d permissions", len(loaded.Grants), len(s.Grants))
		}
	}
}

// TestADamagedRecordIsToldApartFromNoRecordAtAll is the difference the callers
// depend on. No record means no sandbox, and starting a fresh one is right. A
// record that will not parse means a sandbox exists with permissions in force
// on directories only that file names, and treating it as absent hands out a
// new one and abandons them.
func TestADamagedRecordIsToldApartFromNoRecordAtAll(t *testing.T) {
	s := newState(t)
	if absent, err := Load(s.Group); absent != nil || err != nil {
		t.Fatalf("a sandbox that was never there gave (%v, %v)", absent, err)
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(Path(s.Group), []byte("{ not a record"), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(s.Group)
	var damaged *Damaged
	if !errors.As(err, &damaged) {
		t.Fatalf("a record that will not parse gave (%v, %v)", loaded, err)
	}
	if loaded != nil {
		t.Error("a damaged record came back as a record as well as an error")
	}
	if !strings.Contains(damaged.Error(), Path(s.Group)) {
		t.Errorf("the error does not say which file it is: %q", damaged.Error())
	}
}

// TestTheCopyBehindARecordNamesWhatTheRecordNoLongerCan is what makes a
// damaged record recoverable: the directories a sandbox holds are named in
// that file and nowhere else, so a copy from before the last save is the only
// thing standing between a damaged record and permissions nothing can find.
func TestTheCopyBehindARecordNamesWhatTheRecordNoLongerCan(t *testing.T) {
	s := newState(t)
	held := t.TempDir()
	s.Grants = []grant.Spec{{Path: held, Kind: grant.RW, Explicit: true}}
	// One save writes the record; the second is what leaves a copy behind it.
	for i := 0; i < 2; i++ {
		if err := s.Save(); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(Path(s.Group), []byte("{ not a record"), 0o600); err != nil {
		t.Fatal(err)
	}

	var damaged *Damaged
	if _, err := Load(s.Group); !errors.As(err, &damaged) {
		t.Fatalf("expected a damaged record, got %v", err)
	}
	if damaged.Previous == nil {
		t.Fatal("nothing was kept behind the record, so the grants in it are unreachable")
	}
	if len(damaged.Previous.Grants) != 1 || !strings.EqualFold(damaged.Previous.Grants[0].Path, held) {
		t.Errorf("the copy remembers %v, not %s", damaged.Previous.Grants, held)
	}

	// A copy that is damaged too is not a half-answer: the caller is told there
	// is nothing behind the record rather than being handed a broken one.
	if err := os.WriteFile(PreviousPath(s.Group), []byte("{ also not a record"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(s.Group); !errors.As(err, &damaged) {
		t.Fatalf("expected a damaged record, got %v", err)
	}
	if damaged.Previous != nil {
		t.Error("a copy that will not parse came back as one that would")
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
			failures <- lock.Hold(s.Group, func() error {
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
	if err := lock.Hold(s.Group, func() error { return wanted }); !errors.Is(err, wanted) {
		t.Fatalf("the error did not come back: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- lock.Hold(s.Group, func() error { return nil }) }()
	select {
	case err := <-done:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(5 * time.Second):
		t.Error("the lock was never let go after the work failed")
	}
}
