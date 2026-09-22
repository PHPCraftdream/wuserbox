package profile

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
)

// The hold these tests stand on is the ordinary kind: one handle opened
// sharing nothing, so the kernel refuses every other open of the name until
// it closes -- the shape of a credential file a running program keeps, and
// nothing about the name itself has changed. While it stands, a look at the
// name fails without saying it is gone, and that difference is the whole of
// what this file pins: a take-back or a copy that cannot ask must stop with
// the record standing for the retry, where reading the failure as an
// absence reported success over a copy left holding revoked credentials,
// under a record that no longer named it.
func lockExclusive(t *testing.T, path string, directory bool) func() {
	t.Helper()
	flags := uint32(syscall.FILE_ATTRIBUTE_NORMAL)
	if directory {
		flags |= syscall.FILE_FLAG_BACKUP_SEMANTICS
	}
	locked, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := syscall.CreateFile(locked, syscall.GENERIC_READ, 0, nil,
		syscall.OPEN_EXISTING, flags, 0)
	if err != nil {
		t.Fatalf("the kernel refused the exclusive hold the test stands on: %v", err)
	}
	closed := false
	release := func() {
		if closed {
			return
		}
		closed = true
		if err := syscall.CloseHandle(handle); err != nil {
			t.Fatalf("releasing the exclusive hold failed: %v", err)
		}
	}
	t.Cleanup(release)
	return release
}

// holdProof asserts the staged question really is staged: with the handle
// open, a look at the name through the root must fail -- the volume
// refusing to describe a name it still holds -- or the tests below would
// measure nothing.
func holdProof(t *testing.T, root *os.Root, name string) {
	t.Helper()
	if _, err := root.Lstat(name); err == nil {
		t.Skip("this volume still answers a look through the exclusive hold, so the question cannot be staged")
	}
}

// TestALockedCopyStopsTheRunAndTheRetryTakesTheCopyBack is the review's
// measured case end to end through the public Copy: the list stops naming
// an entry while its copy sits behind an exclusive hold, so the take-back
// cannot ask whether the copy is there at all. The run refuses instead of
// reporting the success that would retire the record, and the run after
// the hold lets go -- asked with the record the failed run left the caller
// holding -- takes the copy back and keeps the entry the list still names.
func TestALockedCopyStopsTheRunAndTheRetryTakesTheCopyBack(t *testing.T) {
	home, dest := useProfile(t, []string{"stale", "kept"})
	write(t, filepath.Join(home, "stale"), "revoked credentials")
	write(t, filepath.Join(home, "kept"), "{}")
	fill(t, dest)
	if got := read(t, filepath.Join(dest, "stale")); got != "revoked credentials" {
		t.Fatalf("the copy this test is about never landed: %q", got)
	}

	if err := (&config.Config{Profile: config.Entries([]string{"kept"})}).Save(); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	release := lockExclusive(t, filepath.Join(dest, "stale"), false)
	holdProof(t, root, "stale")

	_, _, err = Copy(dest, lastCopied[dest], lastPrints[dest])
	release()
	if err == nil {
		t.Fatal("a take-back that could not ask whether the copy stood reported success over it")
	}
	if !strings.Contains(err.Error(), "stale") {
		t.Errorf("the refusal did not name the entry it stopped on: %v", err)
	}
	if got := read(t, filepath.Join(dest, "stale")); got != "revoked credentials" {
		t.Fatalf("the locked copy was disturbed by the run that could not ask about it: %q", got)
	}

	copied, _, err := Copy(dest, lastCopied[dest], lastPrints[dest])
	if err != nil {
		t.Fatalf("the retry after the hold let go failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "stale")); !os.IsNotExist(err) {
		t.Errorf("the retry left the stale copy standing: %v", err)
	}
	if got := read(t, filepath.Join(dest, "kept")); got != "{}" {
		t.Errorf("the entry the list still names lost its copy to the take-back beside it: %q", got)
	}
	if !reflect.DeepEqual(pathsOf(copied), []string{"kept"}) {
		t.Errorf("the record came back as %v, want the entry the list names", pathsOf(copied))
	}
}

// TestALockedClearStopsTheTakeBackAndTheRetryTakesItAllBack is the same
// question through Clear, the --no-ai door: the take-back reads no rules
// file, so the record it was handed is all it has, and a name it cannot
// ask about has to stop it with the record standing rather than be read
// as a copy already gone. The run after the hold lets go takes the whole
// record back.
func TestALockedClearStopsTheTakeBackAndTheRetryTakesItAllBack(t *testing.T) {
	home, dest := useProfile(t, []string{"stale", "kept"})
	write(t, filepath.Join(home, "stale"), "revoked credentials")
	write(t, filepath.Join(home, "kept"), "{}")
	copied := fill(t, dest)
	if len(copied) != 2 {
		t.Fatalf("the record this test stands on came back as %v, want both entries", pathsOf(copied))
	}

	root, err := os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	release := lockExclusive(t, filepath.Join(dest, "stale"), false)
	holdProof(t, root, "stale")

	err = Clear(dest, copied)
	release()
	if err == nil {
		t.Fatal("a take-back that could not ask about one of its names reported success over the whole record")
	}
	if !strings.Contains(err.Error(), "stale") {
		t.Errorf("the refusal did not name the entry it stopped on: %v", err)
	}
	if got := read(t, filepath.Join(dest, "stale")); got != "revoked credentials" {
		t.Fatalf("the locked copy was disturbed by the run that could not ask about it: %q", got)
	}
	if _, err := os.Stat(filepath.Join(dest, "kept")); err != nil {
		t.Errorf("the take-back stopped on the locked name but cleared past it: %v", err)
	}

	if err := Clear(dest, copied); err != nil {
		t.Fatalf("the retry after the hold let go failed: %v", err)
	}
	for _, gone := range []string{"stale", "kept"} {
		if _, err := os.Stat(filepath.Join(dest, gone)); !os.IsNotExist(err) {
			t.Errorf("%s survived a Clear nothing holds shut any more: %v", gone, err)
		}
	}
}

// TestAClearThatCannotAskStopsInsteadOfReportingNothing is clearEntry's own
// two answers, asked directly: a name the hold keeps the volume from
// describing is an error with nothing taken -- never the false-and-nil of
// a copy already gone -- and the volume's own nothing is still the no-op it
// always was, for a bare entry and for one carrying limits.
func TestAClearThatCannotAskStopsInsteadOfReportingNothing(t *testing.T) {
	t.Run("bare entry behind the hold", func(t *testing.T) {
		dest := t.TempDir()
		write(t, filepath.Join(dest, "stale"), "the copy to take back")
		root, err := os.OpenRoot(dest)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = root.Close() }()
		release := lockExclusive(t, filepath.Join(dest, "stale"), false)
		holdProof(t, root, "stale")

		taken, err := clearEntry(root, "stale", config.Entry{Path: "stale"})
		if err == nil {
			t.Fatal("a clear that could not ask whether the copy stood reported nothing to take")
		}
		if taken {
			t.Error("the clear reported taking something it could not look at")
		}
		release()
		if got := read(t, filepath.Join(dest, "stale")); got != "the copy to take back" {
			t.Errorf("the locked copy was disturbed: %q", got)
		}
	})

	t.Run("limited entry behind the hold on the entry's directory", func(t *testing.T) {
		dest := t.TempDir()
		write(t, filepath.Join(dest, "agent", "sessions", "one.txt"), "the sandbox's own session")
		write(t, filepath.Join(dest, "agent", "auth.json"), `{"token":"real"}`)
		root, err := os.OpenRoot(dest)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = root.Close() }()
		release := lockExclusive(t, filepath.Join(dest, "agent"), true)
		holdProof(t, root, "agent")

		entry := config.Entry{Path: "agent", Exclude: []config.Mask{{Pattern: "sessions/**"}}}
		taken, err := clearEntry(root, "agent", entry)
		if err == nil {
			t.Fatal("a clear that could not ask whether the entry's tree stood reported nothing to take")
		}
		if taken {
			t.Error("the clear reported taking something it could not look at")
		}
		release()
		if got := read(t, filepath.Join(dest, "agent", "auth.json")); got != `{"token":"real"}` {
			t.Errorf("the copy behind the hold was disturbed: %q", got)
		}
		if got := read(t, filepath.Join(dest, "agent", "sessions", "one.txt")); got != "the sandbox's own session" {
			t.Errorf("the file the entry's own limits protect was disturbed: %q", got)
		}
	})

	t.Run("a name the volume calls gone is still a no-op", func(t *testing.T) {
		dest := t.TempDir()
		root, err := os.OpenRoot(dest)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = root.Close() }()
		for name, entry := range map[string]config.Entry{
			"bare":    {Path: "neverwas"},
			"limited": {Path: "neverwas", Exclude: []config.Mask{{Pattern: "keep/**"}}},
		} {
			t.Run(name, func(t *testing.T) {
				taken, err := clearEntry(root, "neverwas", entry)
				if err != nil {
					t.Fatalf("the volume's own nothing was read as a refusal: %v", err)
				}
				if taken {
					t.Error("a clear over a name that was never there reported taking something")
				}
			})
		}
	})
}

// TestACopyThatCannotAskItsDestinationStopsAndTheRetryCopies is the copy
// direction of the same hold: the source stands, the destination's own
// directory sits behind an exclusive handle, and the question of what
// stands at dst cannot be finished. The run refuses -- the mirror has
// nothing honest to report about a name it never saw -- and the retry
// after the hold lets go carries the source in.
func TestACopyThatCannotAskItsDestinationStopsAndTheRetryCopies(t *testing.T) {
	home, dest := useProfile(t, []string{"agent"})
	write(t, filepath.Join(home, "agent", "settings.json"), `{"fresh":true}`)
	write(t, filepath.Join(dest, "agent", "settings.json"), `{"stale":true}`)

	root, err := os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	release := lockExclusive(t, filepath.Join(dest, "agent"), true)
	holdProof(t, root, "agent")

	_, _, err = Copy(dest, nil, nil)
	release()
	if err == nil {
		t.Fatal("a copy that could not ask what stood at its destination reported success over it")
	}
	if got := read(t, filepath.Join(dest, "agent", "settings.json")); got != `{"stale":true}` {
		t.Fatalf("the standing copy was disturbed by the run that could not look at its directory: %q", got)
	}

	copied, _, err := Copy(dest, nil, nil)
	if err != nil {
		t.Fatalf("the retry after the hold let go failed: %v", err)
	}
	if got := read(t, filepath.Join(dest, "agent", "settings.json")); got != `{"fresh":true}` {
		t.Errorf("the retry did not carry the source in: %q", got)
	}
	if !reflect.DeepEqual(pathsOf(copied), []string{"agent"}) {
		t.Errorf("the record came back as %v, want the copied entry", pathsOf(copied))
	}
}
