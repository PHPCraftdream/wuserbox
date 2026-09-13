package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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
