// The two failure stages the identity resolution has to refuse at, and the
// lifetime of what a resolution holds. The lookup behind the identities can
// fail in ways that say nothing about the identifier -- a domain out of
// reach, an access refusal, a resolution that ran out of time -- and every
// one of those used to come out as a shorter list that quietly protected
// less. It refuses the operation now, before anything is written, and the
// operation's identifiers go back to Windows when it is over, success or
// not -- the collector cannot see that memory at all, so the counters are
// the only place a leak shows.

package acl

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
)

func TestTheIdentitiesKnowALookupThatFailedFromOneThatSaidNo(t *testing.T) {
	real := accountNameOf
	t.Cleanup(func() { accountNameOf = real })

	// Nothing maps to it, and the lookup says so itself: the identifier
	// stands alone, which is the answer a synthetic identifier in tests
	// has always relied on.
	accountNameOf = func(uintptr) (string, error) {
		return "", fmt.Errorf("resolving the account name: %w", sid.NoneMapped)
	}
	alone, err := identitiesFor(unusedAccount)
	if err != nil {
		t.Fatalf("an identifier nothing maps to was refused: %v", err)
	}
	if len(alone.values) != 1 {
		t.Fatalf("an identifier nothing maps to came out as %d identities, want itself alone", len(alone.values))
	}
	alone.End()

	// The same lookup failing for a reason that says nothing about the
	// identifier is a different answer: nobody knows, and nobody knowing
	// is not a list.
	reason := fmt.Errorf("resolving the account name: %w", syscall.Errno(1722))
	accountNameOf = func(uintptr) (string, error) { return "", reason }
	unknown, err := identitiesFor(unusedAccount)
	if err == nil {
		unknown.End()
		t.Fatal("a lookup that failed for reasons nobody controls came out as a list anyway")
	}
	if unknown != nil {
		t.Errorf("a failed lookup came out as a list of %d identities", len(unknown.values))
	}
	if !errors.Is(err, reason) {
		t.Errorf("the refusal carried %v, want the lookup's own reason", err)
	}
}

// TestAnIsolateThatCannotResolveItsIdentitiesWritesNothing is the first of
// the two stages the failure has to be caught at: the identities are
// resolved before the first read of the tree, and a resolution that fails
// for nobody-knows reasons fails the grant before anything is written --
// the old shape fell back to the group's identifier alone and went on to
// narrow with a list that recognized nothing the sandbox owned.
func TestAnIsolateThatCannotResolveItsIdentitiesWritesNothing(t *testing.T) {
	root := t.TempDir()
	held := filepath.Join(root, "held.txt")
	if err := os.WriteFile(held, []byte("held"), 0o644); err != nil {
		t.Fatal(err)
	}
	real := accountNameOf
	reason := fmt.Errorf("resolving the account name: %w", syscall.Errno(1722))
	accountNameOf = func(uintptr) (string, error) { return "", reason }
	t.Cleanup(func() { accountNameOf = real })

	writes := 0
	original := publish
	publish = func(path string, list []explicitAccess, whole bool) error {
		writes++
		return original(path, list, whole)
	}
	t.Cleanup(func() { publish = original })

	if err := Isolate(root, unusedAccount, []ACE{
		{Access: AccessModify, Inheritance: InheritObjects | InheritContainers},
	}, InheritObjects|InheritContainers, nil); err == nil {
		t.Fatal("a grant went out under identities nobody could resolve")
	} else if !errors.Is(err, reason) {
		t.Errorf("the grant was refused with %v, want the lookup's own reason", err)
	}
	if writes != 0 {
		t.Errorf("the grant was published %d times while its identities could not be resolved", writes)
	}
	if holds(t, held, unusedAccount, "") {
		t.Error("the tree was written while the identities of the grant could not be resolved")
	}
	if err := os.WriteFile(held, []byte("still mine"), 0o644); err != nil {
		t.Errorf("the operator lost access to a tree whose grant never started: %v", err)
	}
}

// TestATakeBackThatCannotResolveItsIdentitiesChangesNothing is the same
// stage for the way out: the revoke is refused before the walk starts, and
// the tree it was asked about is exactly as it was found.
func TestATakeBackThatCannotResolveItsIdentitiesChangesNothing(t *testing.T) {
	root := t.TempDir()
	held := filepath.Join(root, "held.txt")
	if err := os.WriteFile(held, []byte("held"), 0o644); err != nil {
		t.Fatal(err)
	}
	real := accountNameOf
	reason := fmt.Errorf("resolving the account name: %w", syscall.Errno(1722))
	accountNameOf = func(uintptr) (string, error) { return "", reason }
	t.Cleanup(func() { accountNameOf = real })

	if err := TakeBack(root, unusedAccount, nil); err == nil {
		t.Fatal("a revoke went out under identities nobody could resolve")
	} else if !errors.Is(err, reason) {
		t.Errorf("the revoke was refused with %v, want the lookup's own reason", err)
	}
	if holds(t, held, unusedAccount, "") {
		t.Error("the tree changed while the identities of the revoke could not be resolved")
	}
	if err := os.WriteFile(held, []byte("still mine"), 0o644); err != nil {
		t.Errorf("the operator lost access to a tree whose revoke never started: %v", err)
	}
}

// TestAStripPassIsNotUsableWhenItsIdentitiesCannotBeResolved is the second
// stage: the pass never comes into existence, so a caller that strips with
// it strips with nothing -- the old shape handed back a working pass whose
// list named the group alone, and the strip found no account entry to take
// off anything.
func TestAStripPassIsNotUsableWhenItsIdentitiesCannotBeResolved(t *testing.T) {
	real := accountNameOf
	reason := fmt.Errorf("resolving the account name: %w", syscall.Errno(1722))
	accountNameOf = func(uintptr) (string, error) { return "", reason }
	t.Cleanup(func() { accountNameOf = real })

	pass, err := BeginStripOwn(unusedAccount)
	if err == nil {
		pass.End()
		t.Fatal("a stripping pass came back usable on identities nobody could resolve")
	}
	if pass != nil {
		t.Error("a failed resolution came out as a pass with values on it")
	}
	if !errors.Is(err, reason) {
		t.Errorf("the pass was refused with %v, want the lookup's own reason", err)
	}
}

// TestAnIsolateGivesItsIdentifiersBack is the close test of the operation's
// lifetime: one grant parses nine identifiers -- the account, then the
// eight of the cast -- and gives all nine back when it is done. The
// collector cannot see this memory at all, so the balance of the counters
// is the only place a leak shows.
func TestAnIsolateGivesItsIdentifiersBack(t *testing.T) {
	dir := t.TempDir()
	parses, frees := sid.Parses(), sid.Frees()
	if err := Isolate(dir, unusedAccount, []ACE{
		{Access: AccessReadExecute, Inheritance: InheritObjects | InheritContainers},
	}, InheritObjects|InheritContainers, nil); err != nil {
		t.Fatal(err)
	}
	if got := sid.Parses() - parses; got != 9 {
		t.Errorf("one grant parsed %d identifiers, want the nine it owns: the account and the cast", got)
	}
	if got := sid.Frees() - frees; got != 9 {
		t.Errorf("one grant gave %d identifiers back, want all nine of what it parsed", got)
	}
}

// TestAFailedIsolateGivesItsIdentifiersBack is the balance on the path
// that fails early: the one identifier parsed before the refusal is given
// back with the refusal, and nothing is left on the system heap.
func TestAFailedIsolateGivesItsIdentifiersBack(t *testing.T) {
	root := t.TempDir()
	real := accountNameOf
	reason := fmt.Errorf("resolving the account name: %w", syscall.Errno(1722))
	accountNameOf = func(uintptr) (string, error) { return "", reason }
	t.Cleanup(func() { accountNameOf = real })

	parses, frees := sid.Parses(), sid.Frees()
	if err := Isolate(root, unusedAccount, []ACE{
		{Access: AccessReadExecute, Inheritance: InheritObjects | InheritContainers},
	}, InheritObjects|InheritContainers, nil); err == nil {
		t.Fatal("the grant succeeded on identities nobody could resolve")
	}
	if got := sid.Parses() - parses; got != 1 {
		t.Errorf("the failed grant parsed %d identifiers, want the one account it refused on", got)
	}
	if got := sid.Frees() - frees; got != 1 {
		t.Errorf("the failed grant gave %d identifiers back, want the one it parsed", got)
	}
}

// TestATakeBackGivesItsIdentifiersBack is the same balance for the way
// out, which parses the same nine once and frees them once.
func TestATakeBackGivesItsIdentifiersBack(t *testing.T) {
	dir := t.TempDir()
	parses, frees := sid.Parses(), sid.Frees()
	if err := TakeBack(dir, unusedAccount, nil); err != nil {
		t.Fatal(err)
	}
	if got := sid.Parses() - parses; got != 9 {
		t.Errorf("one revoke parsed %d identifiers, want the nine it owns: the account and the cast", got)
	}
	if got := sid.Frees() - frees; got != 9 {
		t.Errorf("one revoke gave %d identifiers back, want all nine of what it parsed", got)
	}
}

// TestRepeatedOperationsLeaveNothingHeldBehind is the growth question the
// global pin used to answer badly: every member identifier used to be held
// for the life of the process, so each operation made the answer bigger.
// The operation now owns its identifiers outright -- there is no global pin
// left to grow -- and the balance below is what proves nothing native is
// left behind: after each grant-and-revoke pair the counters stand where
// they started. A fresh directory each round, because a revoke that works
// takes the write back with it, and a second grant on what the first round
// locked would be refused rather than counted.
func TestRepeatedOperationsLeaveNothingHeldBehind(t *testing.T) {
	entries := []ACE{{Access: AccessReadExecute, Inheritance: InheritObjects | InheritContainers}}
	for i := 0; i < 3; i++ {
		dir := t.TempDir()
		parses, frees := sid.Parses(), sid.Frees()
		if err := Isolate(dir, unusedAccount, entries, InheritObjects|InheritContainers, nil); err != nil {
			t.Fatal(err)
		}
		if err := TakeBack(dir, unusedAccount, nil); err != nil {
			t.Fatal(err)
		}
		if got := sid.Parses() - parses; got != 18 {
			t.Errorf("round %d parsed %d identifiers, want nine for the grant and nine for the revoke", i, got)
		}
		if got := sid.Frees() - frees; got != 18 {
			t.Errorf("round %d gave %d identifiers back, want all of what it parsed", i, got)
		}
	}
}
