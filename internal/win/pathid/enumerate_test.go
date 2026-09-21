package pathid

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

// The fakes below play the FindFirstFileNameW family at its own contract: a
// successful call writes the name, terminating null included, into the
// buffer it was given, records the length it wrote, and answers 1; a failed
// one answers 0 and names why.

// nextStep is one FindNextFileNameW call: a name to deliver, or a failure.
// required non-zero plays ERROR_MORE_DATA, demanding that many characters
// for the name under the handle.
type nextStep struct {
	name     string
	required uint32
	err      error
}

// scriptEnumeration swaps the calls an enumeration goes through for ones
// that hand out first and then walk steps. When the steps run out, the next
// call is the documented end of the list.
func scriptEnumeration(t *testing.T, first string, steps []nextStep) {
	t.Helper()
	wide := wide16(t, first)
	previousFirst, previousNext := findFirstFileName, findNextFileName
	t.Cleanup(func() { findFirstFileName, findNextFileName = previousFirst, previousNext })

	findFirstFileName = func(name string, length *uint32, buffer []uint16) (uintptr, error) {
		copy(buffer, wide)
		*length = uint32(len(wide))
		return 0x1, nil
	}
	calls := 0
	findNextFileName = func(handle uintptr, length *uint32, buffer []uint16) (uintptr, error) {
		calls++
		if calls > len(steps) {
			return 0, errHandleEOF
		}
		switch step := steps[calls-1]; {
		case step.required != 0:
			*length = step.required
			return 0, errMoreData
		case step.err != nil:
			return 0, step.err
		default:
			name := wide16(t, step.name)
			copy(buffer, name)
			*length = uint32(len(name))
			return 1, nil
		}
	}
}

func wide16(t *testing.T, name string) []uint16 {
	t.Helper()
	wide, err := syscall.UTF16FromString(name)
	if err != nil {
		t.Fatal(err)
	}
	return wide
}

// subject is a real file for Canonical to resolve; the enumeration itself is
// scripted, so its answer says nothing about the file on disk.
func subject(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "subject.txt")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestNamesEndsOnlyAtTheDocumentedEndOfTheList holds the enumerator to the
// API's own contract: the walk ends when Windows says the list is over, and
// not one step earlier.
func TestNamesEndsOnlyAtTheDocumentedEndOfTheList(t *testing.T) {
	path := subject(t)
	scriptEnumeration(t, `\dir\own`, []nextStep{
		{name: `\dir\twin`},
	})

	names, err := Names(path)
	if err != nil {
		t.Fatalf("an enumeration that ended the documented way was refused: %v", err)
	}
	volume := filepath.VolumeName(path)
	want := []string{volume + `\dir\own`, volume + `\dir\twin`}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("names = %v, want %v", names, want)
	}
}

// TestNamesRefusesAnEnumerationThatFailsPartway is the close test for the
// fail-open this package used to carry: FindNextFileNameW answering zero has
// meant "another error" far more often than it has meant the end, and a list
// cut short there says nothing about the names it never reached. A caller
// that takes the partial list for the whole one certifies a file whose
// outside names it has not seen.
func TestNamesRefusesAnEnumerationThatFailsPartway(t *testing.T) {
	path := subject(t)
	scriptEnumeration(t, `\dir\own`, []nextStep{
		{err: syscall.Errno(5)}, // ERROR_ACCESS_DENIED, not the end of the list
	})

	names, err := Names(path)
	if err == nil {
		t.Fatalf("an enumeration cut short by an error came back as the whole list: %v", names)
	}
	if names != nil {
		t.Errorf("a partial list was returned alongside the error: %v", names)
	}
	if !strings.Contains(err.Error(), "listing the names of") {
		t.Errorf("the refusal does not say what was being listed: %v", err)
	}
}

// TestNamesGrowsTheBufferWhenANameDoesNotFit keeps the API's own way to go
// on: ERROR_MORE_DATA names the room the next name needs, the same call is
// made again with that much, and the enumeration continues from the name it
// stopped on rather than past it. The sizes run past the first buffer on
// purpose, so the walk is held to growing and going on rather than
// refusing what it was owed the room for.
func TestNamesGrowsTheBufferWhenANameDoesNotFit(t *testing.T) {
	path := subject(t)
	scriptEnumeration(t, `\dir\own`, []nextStep{
		{required: 65536},
		{required: 131072},
		{name: `\dir\twin`},
	})

	names, err := Names(path)
	if err != nil {
		t.Fatalf("a name that did not fit stopped the enumeration: %v", err)
	}
	volume := filepath.VolumeName(path)
	want := []string{volume + `\dir\own`, volume + `\dir\twin`}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("names = %v, want %v", names, want)
	}
}

// TestNamesRefusesANameThatCannotFitTheBufferItGets holds the line between
// growing a buffer and chasing a number that will never converge: a "did not
// fit" answer that asks for no more room than the buffer already has is not
// a name waiting for space, and the enumeration refuses rather than hand
// back a list it could not finish.
func TestNamesRefusesANameThatCannotFitTheBufferItGets(t *testing.T) {
	path := subject(t)
	scriptEnumeration(t, `\dir\own`, []nextStep{
		{required: initialBufferLen},
	})

	if _, err := Names(path); err == nil {
		t.Fatal("an enumeration that could not converge came back as the whole list")
	}
}

// TestNamesRefusesAnErrorThatComesAfterAGrownBuffer keeps the refusal
// standing once the buffer has grown: making room for a name buys nothing
// when the next answer is a failure all the same.
func TestNamesRefusesAnErrorThatComesAfterAGrownBuffer(t *testing.T) {
	path := subject(t)
	scriptEnumeration(t, `\dir\own`, []nextStep{
		{required: 65536},
		{err: syscall.Errno(5)},
	})

	if _, err := Names(path); err == nil {
		t.Fatal("an error after a grown buffer came back as the whole list")
	}
}
