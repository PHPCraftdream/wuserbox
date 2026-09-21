package pathid

import (
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

// growFirst swaps the FindFirstFileNameW call for one that plays the real
// contract at its own seam: a buffer smaller than the first name is refused
// with the room the name needs, terminating null included, and a buffer
// that holds it gets the name and a search handle. required pushes the
// demanded room past what the name itself would ask for, to play answers
// the volume cannot be made to give.
func growFirst(t *testing.T, name string, required uint32) {
	t.Helper()
	wide := wide16(t, name)
	previous := findFirstFileName
	t.Cleanup(func() { findFirstFileName = previous })
	findFirstFileName = func(_ string, length *uint32, buffer []uint16) (uintptr, error) {
		need := uint32(len(wide))
		if required > need {
			need = required
		}
		if need > uint32(len(buffer)) {
			*length = need
			return uintptr(syscall.InvalidHandle), errMoreData
		}
		copy(buffer, wide)
		*length = uint32(len(wide))
		return 0x1, nil
	}
}

// silenceNext ends the walk after its first name, so a test about the first
// call never depends on what comes after it.
func silenceNext(t *testing.T) {
	t.Helper()
	previous := findNextFileName
	t.Cleanup(func() { findNextFileName = previous })
	findNextFileName = func(uintptr, *uint32, []uint16) (uintptr, error) {
		return 0, errHandleEOF
	}
}

// scriptFinalPath swaps the GetFinalPathNameByHandleW call for one that
// plays the real contract at its own seam: a buffer smaller than the final
// name is refused with the room the name needs, terminating null included,
// and a buffer that holds it gets the name, null left out of the count. The
// real refusal sets no particular error beside the count -- this machine's
// own answer was ERROR_NOT_ENOUGH_MEMORY -- so the seam does not pretend
// one matters. required pushes the demanded room past what the name itself
// would ask for, to play answers the volume cannot be made to give.
func scriptFinalPath(t *testing.T, name string, required uint32) {
	t.Helper()
	wide := wide16(t, name)
	previous := getFinalPathName
	t.Cleanup(func() { getFinalPathName = previous })
	getFinalPathName = func(_ syscall.Handle, buffer []uint16) (int, error) {
		need := len(wide)
		if int(required) > need {
			need = int(required)
		}
		if need > len(buffer) {
			return need, syscall.Errno(8)
		}
		copy(buffer, wide)
		return len(wide) - 1, nil
	}
}

// TestNamesGrowsTheFirstBufferWhenTheFirstNameDoesNotFit keeps the first
// name on the same terms as the rest of the walk: the enumeration starts
// with a small buffer, the refusal names the room the first name needs, and
// the same call is made again with that much before anything is taken as
// read.
func TestNamesGrowsTheFirstBufferWhenTheFirstNameDoesNotFit(t *testing.T) {
	path := subject(t)
	long := `\` + strings.Repeat("component-", 40) + `own`
	growFirst(t, long, 0)
	silenceNext(t)

	names, err := Names(path)
	if err != nil {
		t.Fatalf("a first name longer than the first buffer stopped the enumeration: %v", err)
	}
	want := []string{filepath.VolumeName(path) + long}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("names = %v, want %v", names, want)
	}
}

// TestNamesRefusesAFirstNamePastTheCeilingItAlwaysStoodAt keeps the ceiling
// the first call has always refused past: a name asking for more room than
// MAX_LONG_PATH is not a name waiting for space, and the answer is a
// refusal rather than a buffer that size.
func TestNamesRefusesAFirstNamePastTheCeilingItAlwaysStoodAt(t *testing.T) {
	path := subject(t)
	growFirst(t, `\dir\own`, syscall.MAX_LONG_PATH+1)
	silenceNext(t)

	if _, err := Names(path); err == nil {
		t.Fatal("a first name past the ceiling came back as the whole list")
	}
}

// TestNamesRefusesAFirstNameThatNeverAsksForMoreRoom holds the line between
// growing and chasing a number that will not move: a did not fit answer
// demanding no more room than the buffer that has just failed is not a name
// waiting for space, and the enumeration refuses rather than hand back a
// list it could not finish.
func TestNamesRefusesAFirstNameThatNeverAsksForMoreRoom(t *testing.T) {
	path := subject(t)
	previous := findFirstFileName
	t.Cleanup(func() { findFirstFileName = previous })
	findFirstFileName = func(_ string, length *uint32, buffer []uint16) (uintptr, error) {
		*length = uint32(len(buffer))
		return uintptr(syscall.InvalidHandle), errMoreData
	}
	silenceNext(t)

	if _, err := Names(path); err == nil {
		t.Fatal("an enumeration that could not converge on its first name came back as the whole list")
	}
}

// TestCanonicalGrowsTheBufferWhenTheFinalNameDoesNotFit keeps the resolver
// on the same terms: the resolution starts with a small buffer, the refusal
// names the room the final name needs, and the same call is made again with
// that much before the name is read.
func TestCanonicalGrowsTheBufferWhenTheFinalNameDoesNotFit(t *testing.T) {
	path := subject(t)
	name := `\\?\D:\` + strings.Repeat("component-", 44) + `file.txt`
	scriptFinalPath(t, name, 0)

	got, err := Canonical(path)
	if err != nil {
		t.Fatalf("a final name longer than the first buffer stopped the resolution: %v", err)
	}
	if want := strings.TrimPrefix(name, `\\?\`); got != want {
		t.Errorf("canonical = %q, want %q", got, want)
	}
}

// TestCanonicalKeepsTheUncSpellingOfAnAnswerPastTheFirstBuffer keeps the
// volume prefix of an answer that needed more room than it was offered: a
// UNC spelling arrives through the refusal exactly as it would through a
// buffer that held it at first.
func TestCanonicalKeepsTheUncSpellingOfAnAnswerPastTheFirstBuffer(t *testing.T) {
	path := subject(t)
	name := `\\?\UNC\server\share\` + strings.Repeat("component-", 30) + `file.txt`
	scriptFinalPath(t, name, 0)

	got, err := Canonical(path)
	if err != nil {
		t.Fatalf("a UNC answer longer than the first buffer stopped the resolution: %v", err)
	}
	if want := `\\server\share\` + strings.Repeat("component-", 30) + `file.txt`; got != want {
		t.Errorf("canonical = %q, want %q", got, want)
	}
}

// TestCanonicalRefusesAFinalNamePastTheCeiling keeps the ceiling the
// resolution has always stood at: a final name asking for more room than
// MAX_LONG_PATH is not a name waiting for space, and the answer is a
// refusal, as it has been since the buffer was full-size.
func TestCanonicalRefusesAFinalNamePastTheCeiling(t *testing.T) {
	path := subject(t)
	scriptFinalPath(t, `\\?\D:\file.txt`, syscall.MAX_LONG_PATH+1)

	if _, err := Canonical(path); err == nil {
		t.Fatal("a final name past the ceiling came back as a resolution")
	}
}

// TestCanonicalRefusesWhenTheGrownBufferStillDoesNotHoldIt keeps the
// refusal standing once the buffer has grown: room asked for and given buys
// nothing when the next answer still says the name does not fit.
func TestCanonicalRefusesWhenTheGrownBufferStillDoesNotHoldIt(t *testing.T) {
	path := subject(t)
	previous := getFinalPathName
	t.Cleanup(func() { getFinalPathName = previous })
	getFinalPathName = func(_ syscall.Handle, buffer []uint16) (int, error) {
		return len(buffer) + 1, syscall.Errno(8)
	}

	if _, err := Canonical(path); err == nil {
		t.Fatal("a resolution that never converged came back as a name")
	}
}
