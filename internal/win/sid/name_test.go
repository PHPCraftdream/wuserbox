package sid

import (
	"errors"
	"syscall"
	"testing"
)

// This pins what the sizing call of LookupAccountSidW owes the caller: that
// call is refused by design, and its refusal is the only one Name may
// swallow, because what it carries is the sizes the real call needs. Every
// other refusal is the lookup's own answer, and Name keeps it, with the
// errno it traveled with, so that an identifier nothing maps to --
// NoneMapped -- and a lookup nobody could complete stay different answers:
// "this names nothing" is a fact to build on, "nobody knows" is not.
func TestNamePreservesTheReasonALookupFailed(t *testing.T) {
	text, err := CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	pointer, err := Parse(text)
	if err != nil {
		t.Fatalf("parsing the current user %q: %v", text, err)
	}
	name, err := Name(pointer)
	if err != nil {
		t.Fatalf("resolving the current user's name: %v", err)
	}
	if name == "" {
		t.Error("the current user resolved to an empty name")
	}

	// A well-formed identifier no account anywhere has: the lookup runs,
	// finds nothing, and says so with NoneMapped, which is the one answer
	// that tells the caller the identifier stands alone.
	pointer, err = Parse("S-1-5-21-1111111111-2222222222-3333333333-543210")
	if err != nil {
		t.Fatalf("parsing an unused identifier: %v", err)
	}
	if _, err = Name(pointer); err == nil {
		t.Fatal("expected an error for an identifier nothing maps to")
	}
	if !errors.Is(err, NoneMapped) {
		t.Errorf("an unknown but well-formed identifier came back as %v, not NoneMapped", err)
	}

	// A nil pointer is refused outright, and that refusal says nothing
	// about any identifier -- the old code reported it as the same
	// not-found as everything else, which is the regression this closes.
	// The Windows errno has to survive the wrapping.
	if _, err = Name(0); err == nil {
		t.Fatal("expected an error for a nil pointer")
	}
	if errors.Is(err, NoneMapped) {
		t.Error("a nil pointer came back as NoneMapped")
	}
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		t.Errorf("the error for a nil pointer lost its errno: %v", err)
	}
}
