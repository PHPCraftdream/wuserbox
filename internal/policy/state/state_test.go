package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/wuserbox/internal/lock"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/win/access"
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

// TestAPermissionIsNotHandedOverWhenItCannotBeRecorded is the regression guard
// for an order that could not be undone. The access control entry went on
// first and the record was written second, so a failure to write left a
// directory the sandbox could change that nothing pointed at: explain did not
// list it and revoke could not find it.
func TestAPermissionIsNotHandedOverWhenItCannotBeRecorded(t *testing.T) {
	// The record cannot be written, because the directory it belongs in cannot
	// be created: a file stands where that directory would go.
	inTheWay := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(inTheWay, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LOCALAPPDATA", inTheWay)

	target := t.TempDir()
	s := &State{Group: "wub-unrecordable", SID: testSID, Dir: t.TempDir(), Temp: t.TempDir()}
	if err := s.Add(target, grant.RW); err == nil {
		t.Fatal("the record could not be written, yet the command reported success")
	}
	if s.Has(target) {
		t.Error("the permission stayed in the record although it was never written")
	}
	answer, err := access.Check(s.SID, target, access.Write)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Allowed {
		t.Errorf("the directory is writable by a sandbox no record mentions: %s", answer.Reason)
	}
}

// TestNarrowingADirectoryTakesBackWhatIsInsideIt is the regression guard for a
// refusal that did not reach as far as it promised. A permission set directly
// on a subdirectory is read before a refusal handed down from above it, so
// `grant ~/.config --ro` refused writing in ~/.config while ~/.config/rush,
// handed over separately by the preset, stayed writable.
func TestNarrowingADirectoryTakesBackWhatIsInsideIt(t *testing.T) {
	s := newState(t)
	parent := t.TempDir()
	child := filepath.Join(parent, "tool")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{parent, child} {
		if err := s.Add(dir, grant.RW); err != nil {
			t.Fatal(err)
		}
	}
	allowed, err := access.Check(s.SID, child, access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed.Allowed {
		t.Fatal("the child was not writable to begin with")
	}

	if err := s.Add(parent, grant.RO); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{parent, child} {
		answer, err := access.Check(s.SID, dir, access.Create)
		if err != nil {
			t.Fatal(err)
		}
		if answer.Allowed {
			t.Errorf("%s is still writable after the directory above it was narrowed: %s",
				dir, answer.Reason)
		}
	}
	if s.Has(child) {
		t.Error("the record still claims a permission that was taken back")
	}
}

// TestNarrowingKeepsTheProjectItself covers a project that happens to sit
// inside a directory being narrowed. It is why the sandbox exists, so it is
// never what a refusal elsewhere takes away.
func TestNarrowingKeepsTheProjectItself(t *testing.T) {
	s := newState(t)
	parent := t.TempDir()
	project := filepath.Join(parent, "project")
	if err := os.Mkdir(project, 0o755); err != nil {
		t.Fatal(err)
	}
	s.Dir = project
	if err := s.Add(project, grant.RW); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(parent, grant.RO); err != nil {
		t.Fatal(err)
	}
	if !s.Has(project) {
		t.Fatal("the project lost its own permission")
	}
	answer, err := access.Check(s.SID, project, access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if !answer.Allowed {
		t.Errorf("the project directory is no longer writable: %s", answer.Reason)
	}
}

// TestAnInterruptedNarrowingIsFinished is the regression guard for the gap the
// record-first order leaves. A process stopped between writing a change down
// and applying it left a record saying read-only while the entries still said
// writable, and asking for read-only again trusted the record and did nothing,
// so the sandbox went on writing.
func TestAnInterruptedNarrowingIsFinished(t *testing.T) {
	s := newState(t)
	dir := t.TempDir()
	if err := s.Add(dir, grant.RW); err != nil {
		t.Fatal(err)
	}
	// What being stopped in the middle leaves behind: the record says
	// read-only and carries the mark, the file system still says writable.
	s.Grants[0].Kind = grant.RO
	s.Grants[0].Pending = true
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	interrupted, err := Load(s.Group)
	if err != nil {
		t.Fatal(err)
	}
	writable, err := access.Check(interrupted.SID, dir, access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if !writable.Allowed {
		t.Fatal("the entries were not left writable, so this test proves nothing")
	}

	// Asking for the same thing again has to act rather than trust the record.
	if err := interrupted.Add(dir, grant.RO); err != nil {
		t.Fatal(err)
	}
	answer, err := access.Check(interrupted.SID, dir, access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Allowed {
		t.Errorf("the sandbox can still write where the record says read-only: %s", answer.Reason)
	}
	if interrupted.Grants[0].Pending {
		t.Error("the change is still marked as unfinished after being applied")
	}
}

// TestFinishPendingRepairsWithoutBeingAsked covers the other way the gap is
// closed: starting a sandbox finishes what an interrupted command began,
// without anyone naming the directory again.
func TestFinishPendingRepairsWithoutBeingAsked(t *testing.T) {
	s := newState(t)
	dir := t.TempDir()
	if err := s.Add(dir, grant.RW); err != nil {
		t.Fatal(err)
	}
	s.Grants[0].Kind = grant.RO
	s.Grants[0].Pending = true
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	reread, err := Load(s.Group)
	if err != nil {
		t.Fatal(err)
	}
	if err := reread.FinishPending(); err != nil {
		t.Fatal(err)
	}
	answer, err := access.Check(reread.SID, dir, access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Allowed {
		t.Errorf("an unfinished change was not put right: %s", answer.Reason)
	}
	if reread.Grants[0].Pending {
		t.Error("the mark survived the change being finished")
	}
}

// TestFinishingTwoMarkedChangesDoesNotUndoOneOfThem is the regression guard
// for a repair that walked a copy of the list. Finishing a read-only parent
// takes back what the sandbox holds inside it, and the child was then handed
// out again from a copy made before that happened: gone from the record and
// writable on disk, which is the one state nothing can put right.
func TestFinishingTwoMarkedChangesDoesNotUndoOneOfThem(t *testing.T) {
	s := newState(t)
	parent := t.TempDir()
	child := filepath.Join(parent, "tool")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	// Both marked, the way two interrupted commands would leave them.
	s.Grants = []grant.Spec{
		{Path: parent, Kind: grant.RO, Explicit: true, Pending: true},
		{Path: child, Kind: grant.RW, Pending: true},
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	if err := s.FinishPending(); err != nil {
		t.Fatal(err)
	}
	answer, err := access.Check(s.SID, child, access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Allowed {
		t.Errorf("the child is writable after the parent was made read-only: %s", answer.Reason)
	}
	if s.Has(child) != answer.Allowed {
		t.Errorf("the record says %v about the child and Windows says %v",
			s.Has(child), answer.Allowed)
	}
}

// TestAnInterruptedNarrowingKeepsItsMark covers the gap between refusing a
// directory and taking back what is inside it. Settling the change before that
// second half left writable subdirectories under a read-only parent with
// nothing marked, so no later run would notice.
func TestAnInterruptedNarrowingKeepsItsMark(t *testing.T) {
	s := newState(t)
	parent := t.TempDir()
	child := filepath.Join(parent, "tool")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(child, grant.RW); err != nil {
		t.Fatal(err)
	}

	// Stop the narrowing halfway: the parent is refused, the child is not yet
	// taken back, and the change is still marked.
	if err := grant.Apply(s.SID, parent, grant.RO); err != nil {
		t.Fatal(err)
	}
	s.Grants = append(s.Grants, grant.Spec{
		Path: parent, Kind: grant.RO, Explicit: true, Pending: true,
	})
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	reread, err := Load(s.Group)
	if err != nil {
		t.Fatal(err)
	}
	if err := reread.FinishPending(); err != nil {
		t.Fatal(err)
	}
	answer, err := access.Check(reread.SID, child, access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Allowed {
		t.Errorf("the child survived the interrupted narrowing: %s", answer.Reason)
	}
}

// TestNarrowingLeavesAChildsOwnRefusalAlone covers what a narrowing must not
// take: an entry inside that already refuses. It never stood in the way, and
// dropping it would cost the directory its own restriction the moment the
// parent was widened again.
func TestNarrowingLeavesAChildsOwnRefusalAlone(t *testing.T) {
	s := newState(t)
	parent := t.TempDir()
	child := filepath.Join(parent, "guarded")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		path string
		kind grant.Kind
	}{{parent, grant.RW}, {child, grant.RO}, {parent, grant.RO}, {parent, grant.RW}} {
		if err := s.Add(step.path, step.kind); err != nil {
			t.Fatal(err)
		}
	}
	if kind, held := s.Kind(child); !held || kind != grant.RO {
		t.Fatalf("the child's own restriction is recorded as %q (held: %v)", kind, held)
	}
	answer, err := access.Check(s.SID, child, access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Allowed {
		t.Errorf("the child became writable when the parent was widened: %s", answer.Reason)
	}
}

// TestNarrowingFinishesAChildsUnappliedRefusal is the regression guard for an
// entry that was passed over on the strength of what the record said. A
// refusal inside the directory never stood in the way of the refusal from
// above, so narrowing skipped it — even when that refusal had been written
// down and never applied, which leaves the sandbox writing there while the
// narrowing reports success.
func TestNarrowingFinishesAChildsUnappliedRefusal(t *testing.T) {
	s := newState(t)
	parent := t.TempDir()
	child := filepath.Join(parent, "guarded")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(child, grant.RW); err != nil {
		t.Fatal(err)
	}
	// What an interrupted narrowing of the child leaves: the record says
	// read-only and carries the mark, the entries still allow writing.
	index, _ := s.find(child)
	s.Grants[index].Kind = grant.RO
	s.Grants[index].Pending = true
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	writable, err := access.Check(s.SID, child, access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if !writable.Allowed {
		t.Fatal("the child was not left writable, so this test proves nothing")
	}

	if err := s.Add(parent, grant.RO); err != nil {
		t.Fatal(err)
	}
	answer, err := access.Check(s.SID, child, access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Allowed {
		t.Errorf("the child is still writable after the directory above it was narrowed: %s",
			answer.Reason)
	}
	if kind, held := s.Kind(child); !held || kind != grant.RO {
		t.Errorf("the child's own restriction is recorded as %q (held: %v)", kind, held)
	}
	if index, found := s.find(child); found && s.Grants[index].Pending {
		t.Error("the child's change is still marked as unfinished")
	}
}

// TestNarrowingHandlesANestedPendingChildRemovingAGrandchild is the
// regression guard for narrow() acting on a copy of its own list without
// looking each entry up again, the same flaw FinishPending was fixed against
// at its own level. Narrowing a parent can meet a child that is itself
// pending and still writable on disk; finishing that child recurses into
// narrow(child), which removes a grandchild — handed out to the child on its
// own, separately from the parent — from the real record. The outer
// narrow(parent), still working from the snapshot it started with, then tried
// to remove that same grandchild again, found it gone, and failed before the
// parent's own change was ever settled.
func TestNarrowingHandlesANestedPendingChildRemovingAGrandchild(t *testing.T) {
	s := newState(t)
	parent := t.TempDir()
	child := filepath.Join(parent, "child")
	leaf := filepath.Join(child, "leaf")
	if err := os.MkdirAll(leaf, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(child, grant.RW); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(leaf, grant.RW); err != nil {
		t.Fatal(err)
	}
	// What an interrupted narrowing of the child leaves: read-only and marked
	// in the record, still writable on disk.
	index, _ := s.find(child)
	s.Grants[index].Kind = grant.RO
	s.Grants[index].Pending = true
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	if err := s.Add(parent, grant.RO); err != nil {
		t.Fatalf("narrowing the parent failed: %v", err)
	}
	if index, found := s.find(parent); !found || s.Grants[index].Pending {
		t.Error("the parent's own change is still marked as unfinished")
	}
	answer, err := access.Check(s.SID, leaf, access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Allowed {
		t.Errorf("the grandchild is still writable after the parent was narrowed: %s", answer.Reason)
	}
}

// TestOfferManyRecordsAndAppliesEveryDirectory covers the path a sandbox is
// built through: several directories handed over at once, each applied and
// each left in the record with no mark on it.
func TestOfferManyRecordsAndAppliesEveryDirectory(t *testing.T) {
	s := newState(t)
	var specs []grant.Spec
	for i := 0; i < 5; i++ {
		specs = append(specs, grant.Spec{Path: t.TempDir(), Kind: grant.RW})
	}
	if err := s.OfferMany(specs); err != nil {
		t.Fatal(err)
	}
	for _, spec := range specs {
		kind, held := s.Kind(spec.Path)
		if !held || kind != grant.RW {
			t.Errorf("%s came back as %q (held: %v)", spec.Path, kind, held)
		}
		answer, err := access.Check(s.SID, spec.Path, access.Create)
		if err != nil {
			t.Fatal(err)
		}
		if !answer.Allowed {
			t.Errorf("%s was recorded but not applied: %s", spec.Path, answer.Reason)
		}
	}
	for _, held := range s.Grants {
		if held.Pending {
			t.Errorf("%s is still marked as unfinished", held.Path)
		}
	}

	// And the record has to survive being read back by another process.
	reread, err := Load(s.Group)
	if err != nil {
		t.Fatal(err)
	}
	if len(reread.Grants) != len(specs) {
		t.Errorf("the record holds %d of %d permissions", len(reread.Grants), len(specs))
	}
}

// TestOfferManyYieldsToWhatSomebodyAskedFor keeps the rule that made offers
// different from requests in the first place: doing several at once must not
// quietly widen one that was narrowed by hand.
func TestOfferManyYieldsToWhatSomebodyAskedFor(t *testing.T) {
	s := newState(t)
	narrowed, ordinary := t.TempDir(), t.TempDir()
	if err := s.Add(narrowed, grant.RO); err != nil {
		t.Fatal(err)
	}
	if err := s.OfferMany([]grant.Spec{
		{Path: narrowed, Kind: grant.RW},
		{Path: ordinary, Kind: grant.RW},
	}); err != nil {
		t.Fatal(err)
	}
	if kind, _ := s.Kind(narrowed); kind != grant.RO {
		t.Errorf("an offer overrode a request: the record says %q", kind)
	}
	if kind, _ := s.Kind(ordinary); kind != grant.RW {
		t.Errorf("the other directory was not handed over: %q", kind)
	}
	answer, err := access.Check(s.SID, narrowed, access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Allowed {
		t.Errorf("the narrowed directory became writable: %s", answer.Reason)
	}
}

// TestOfferManyNarrowsOneAtATime covers the kinds it will not take at once.
// Narrowing reaches inside a directory and changes the record as it goes,
// which is not something to do from several threads.
func TestOfferManyNarrowsOneAtATime(t *testing.T) {
	s := newState(t)
	parent := t.TempDir()
	child := filepath.Join(parent, "inside")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := s.Offer(child, grant.RW); err != nil {
		t.Fatal(err)
	}
	if err := s.OfferMany([]grant.Spec{{Path: parent, Kind: grant.RO}}); err != nil {
		t.Fatal(err)
	}
	if s.Has(child) {
		t.Error("narrowing the parent left the entry inside it")
	}
	answer, err := access.Check(s.SID, child, access.Create)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Allowed {
		t.Errorf("the directory inside is still writable: %s", answer.Reason)
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
