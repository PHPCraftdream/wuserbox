package pathid

import (
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
)

// longTree builds a real tree whose final path runs far past the length of
// an ordinary one, so the answers Windows gives for it are longer than the
// first buffer a resolution offers. One component is spelled in Greek, so a
// Unicode answer survives whatever room is offered along the way.
func longTree(tb testing.TB) (short, long string) {
	tb.Helper()
	base := tb.TempDir()
	components := []string{
		"component-00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"component-01-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"component-02-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"component-03-αααααααααααααααααααααααα",
		"component-04-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"component-05-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"component-06-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"component-07-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	deep := filepath.Join(append([]string{base}, components...)...)
	if err := os.MkdirAll(deep, 0o700); err != nil {
		tb.Fatal(err)
	}
	long = filepath.Join(deep, "argument.txt")
	if err := os.WriteFile(long, []byte("x"), 0o600); err != nil {
		tb.Fatal(err)
	}
	short = filepath.Join(base, "short.txt")
	if err := os.WriteFile(short, []byte("x"), 0o600); err != nil {
		tb.Fatal(err)
	}
	return short, long
}

// linkedTree adds a hard link beside the tree, so enumerating the long file
// has more than one name to find.
func linkedTree(tb testing.TB) (short, long string) {
	tb.Helper()
	short, long = longTree(tb)
	twin := filepath.Join(filepath.Dir(short), "twin.txt")
	if err := os.Link(long, twin); err != nil {
		tb.Skipf("hard links unavailable on this volume: %v", err)
	}
	return short, long
}

// TestCanonicalAllocsPerRunShortPath keeps count of the room one ordinary
// resolution needs, so the cost of a path cannot quietly return to a buffer
// the length of the longest one Windows can spell. The logged numbers are
// the point; the assertions only keep the call itself honest.
func TestCanonicalAllocsPerRunShortPath(t *testing.T) {
	short, _ := longTree(t)
	var callErr error
	allocs := testing.AllocsPerRun(200, func() {
		_, callErr = Canonical(short)
	})
	if callErr != nil {
		t.Fatalf("a short path stopped resolving: %v", callErr)
	}
	t.Logf("short path: %v allocs per run", allocs)
}

func TestCanonicalAllocsPerRunLongPath(t *testing.T) {
	_, long := longTree(t)
	var callErr error
	allocs := testing.AllocsPerRun(200, func() {
		_, callErr = Canonical(long)
	})
	if callErr != nil {
		t.Fatalf("a long path stopped resolving: %v", callErr)
	}
	t.Logf("long path (%d characters): %v allocs per run", len(long), allocs)
}

// TestCanonicalAllocsPerRunRepeated watches the same resolution as the
// callers that pay it per file across a whole tree: one thousand runs of
// one ordinary path, counted together.
func TestCanonicalAllocsPerRunRepeated(t *testing.T) {
	short, _ := longTree(t)
	if _, err := Canonical(short); err != nil {
		t.Fatalf("the path stopped resolving before the repetitions: %v", err)
	}
	var callErr error
	allocs := testing.AllocsPerRun(1000, func() {
		_, callErr = Canonical(short)
	})
	if callErr != nil {
		t.Fatalf("a repeated resolution stopped resolving: %v", callErr)
	}
	t.Logf("repeated canonicalizations (1000 runs): %v allocs per run", allocs)
}

// TestNamesAllocsPerRunHardLinkEnumeration keeps count of the room one
// enumeration of a linked file needs, canonical spelling included.
func TestNamesAllocsPerRunHardLinkEnumeration(t *testing.T) {
	_, long := linkedTree(t)
	names, err := Names(long)
	if err != nil {
		t.Fatalf("the linked file stopped enumerating: %v", err)
	}
	if len(names) < 2 {
		t.Fatalf("a file with a hard link has more than one name: %v", names)
	}
	var callErr error
	allocs := testing.AllocsPerRun(200, func() {
		_, callErr = Names(long)
	})
	if callErr != nil {
		t.Fatalf("a linked file stopped enumerating: %v", callErr)
	}
	t.Logf("hard-link enumeration of a %d-character path: %v allocs per run", len(long), allocs)
}

func BenchmarkCanonicalShortPath(b *testing.B) {
	short, _ := longTree(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Canonical(short); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCanonicalLongPath(b *testing.B) {
	_, long := longTree(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Canonical(long); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNamesHardLinkEnumeration(b *testing.B) {
	_, long := linkedTree(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Names(long); err != nil {
			b.Fatal(err)
		}
	}
}

// TestConcurrentResolutionsKeepTheirOwnBuffers holds parallel callers to the
// answers a single caller got: every goroutine resolves the same short
// path, the same long one, and enumerates the same linked file, each through
// its own buffer, under the race detector's eye. A buffer shared between
// callers would answer one of them with another's bytes.
func TestConcurrentResolutionsKeepTheirOwnBuffers(t *testing.T) {
	short, long := linkedTree(t)

	wantShort, err := Canonical(short)
	if err != nil {
		t.Fatalf("the short path stopped resolving: %v", err)
	}
	wantLong, err := Canonical(long)
	if err != nil {
		t.Fatalf("the long path stopped resolving: %v", err)
	}
	if len(wantLong) <= 256 {
		t.Fatalf("the long path came back %d characters; the fixture is supposed to reach past the first buffer a resolution offers", len(wantLong))
	}
	wantNames, err := Names(long)
	if err != nil {
		t.Fatalf("the linked file stopped enumerating: %v", err)
	}
	slices.Sort(wantNames)

	var wg sync.WaitGroup
	const workers, iterations = 8, 50
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				got, err := Canonical(short)
				if err != nil {
					t.Errorf("the short path failed under load: %v", err)
					return
				}
				if got != wantShort {
					t.Errorf("the short path resolved to %q under load, want %q", got, wantShort)
					return
				}
				got, err = Canonical(long)
				if err != nil {
					t.Errorf("the long path failed under load: %v", err)
					return
				}
				if got != wantLong {
					t.Errorf("the long path resolved to %q under load, want %q", got, wantLong)
					return
				}
				names, err := Names(long)
				if err != nil {
					t.Errorf("the enumeration failed under load: %v", err)
					return
				}
				slices.Sort(names)
				if !slices.Equal(names, wantNames) {
					t.Errorf("the enumeration answered %v under load, want %v", names, wantNames)
					return
				}
			}
		}()
	}
	wg.Wait()
}
