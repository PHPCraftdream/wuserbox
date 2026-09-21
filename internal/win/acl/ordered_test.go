// The order the sweep publishes in, and the bounds that keep one slow answer
// from turning the walk into a held map with a path for everything in the
// tree. These are tests of order and bookkeeping, not of the ACL work: the
// reading and the writing are stood in for, which is what lets a single
// answer be held back or made to fail on demand.

package acl

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

// flatTree makes root hold count files, named so that WalkDir meets f0.txt
// first and a test can put its barrier exactly at the head of the order.
func flatTree(t *testing.T, count int) string {
	t.Helper()
	root := t.TempDir()
	for i := 0; i < count; i++ {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("f%d.txt", i)), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// TestTheWalkRunsOnlyWindowObjectsAheadOfTheWriter holds the very first
// answer back and watches the walk stop where the credits run out. The
// channels alone would not do that: the writer reads whatever arrives, so
// without the bound the rest of the tree would walk straight past a held
// first place and pile up as held paths.
func TestTheWalkRunsOnlyWindowObjectsAheadOfTheWriter(t *testing.T) {
	const window = 3
	if hands := runtime.NumCPU(); hands < window {
		t.Skipf("the test wants at least %d workers to fill the window, this machine offers %d", window, hands)
	}
	const count = 12
	root := flatTree(t, count)
	first := filepath.Join(root, "f0.txt")

	var started, finished, applied atomic.Int64
	release := make(chan struct{})
	classify := func(path string) (narrowDecision, error) {
		started.Add(1)
		if path == first {
			<-release
		}
		finished.Add(1)
		return narrowApply, nil
	}
	apply := func(path string) error {
		applied.Add(1)
		return nil
	}

	type answer struct {
		most int
		err  error
	}
	done := make(chan answer, 1)
	go func() {
		most, err := orderedNarrow(root, window, classify, apply)
		done <- answer{most, err}
	}()

	// The writer cannot commit while the first place is held, so every
	// credit stays out and the walk may not send a single object past the
	// window, now or at any later moment.
	deadline := time.Now().Add(10 * time.Second)
	for started.Load() < window && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := started.Load(); got != window {
		t.Fatalf("the walk sent %d objects toward a writer stuck at the first, the window is %d", got, window)
	}
	time.Sleep(200 * time.Millisecond)
	if got := started.Load(); got != window {
		t.Errorf("the walk crept past the window while the writer was stuck: %d started", got)
	}
	if got := applied.Load(); got != 0 {
		t.Errorf("the writer published %d objects ahead of its place in the order", got)
	}
	close(release)
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("the walk failed once the barrier fell: %v", got.err)
		}
		if got.most > window {
			t.Errorf("the writer held %d results at once, the window is %d", got.most, window)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the walk never finished after the barrier fell")
	}
	if got := started.Load(); got != count || finished.Load() != count {
		t.Errorf("the workers started %d and finished %d classifications, the tree holds %d", got, finished.Load(), count)
	}
	if got := applied.Load(); got != count {
		t.Errorf("the writer published %d objects, the tree holds %d", got, count)
	}
}

// TestASkippedRootSparesOnlyItsOwnSubtree pins two directories and checks
// what the writer does with everything the walk still hands it from inside
// them: their descendants are discarded, the neighbors beside them -- one
// spelled so that it merely begins with a held name -- are published in the
// walk's own order, parent first.
func TestASkippedRootSparesOnlyItsOwnSubtree(t *testing.T) {
	root := t.TempDir()
	for _, one := range []struct{ dir, file string }{
		{"a", "1.txt"},
		{filepath.Join("a", "deep"), "2.txt"},
		{"a2", "3.txt"},
		{"b", "4.txt"},
		{"c", "5.txt"},
		{"d", "6.txt"},
	} {
		dir := filepath.Join(root, one.dir)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, one.file), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	held := map[string]bool{
		filepath.Join(root, "a"): true,
		filepath.Join(root, "c"): true,
	}
	applyWanted := map[string]bool{
		filepath.Join(root, "a2", "3.txt"): true,
		filepath.Join(root, "b"):           true,
		filepath.Join(root, "b", "4.txt"):  true,
		filepath.Join(root, "d"):           true,
		filepath.Join(root, "d", "6.txt"):  true,
	}
	classify := func(path string) (narrowDecision, error) {
		switch {
		case held[path]:
			return narrowSkip, nil
		case applyWanted[path]:
			return narrowApply, nil
		}
		return narrowNoop, nil
	}

	var applied []string
	apply := func(path string) error {
		applied = append(applied, path)
		return nil
	}

	most, err := orderedNarrow(root, 4, classify, apply)
	if err != nil {
		t.Fatal(err)
	}
	if most > 4 {
		t.Errorf("the writer held %d results at once, the window is 4", most)
	}
	want := []string{
		filepath.Join(root, "a2", "3.txt"),
		filepath.Join(root, "b"),
		filepath.Join(root, "b", "4.txt"),
		filepath.Join(root, "d"),
		filepath.Join(root, "d", "6.txt"),
	}
	if !slices.Equal(applied, want) {
		t.Errorf("the writer published %v, wanted %v", applied, want)
	}
}

// TestAFailingAnswerStopsTheWalkAndLeavesNothingStanding is the refusal and
// the aftermath: a failing answer from a worker, or a failing write, must
// come back out of orderedNarrow, must publish nothing past itself, and must
// leave every goroutine the run started gone when it returns.
func TestAFailingAnswerStopsTheWalkAndLeavesNothingStanding(t *testing.T) {
	root := flatTree(t, 8)
	sentinel := errors.New("the answer would not come")

	before := runtime.NumGoroutine()

	t.Run("a failing read", func(t *testing.T) {
		published := 0
		_, err := orderedNarrow(root, 2,
			func(string) (narrowDecision, error) { return narrowNoop, sentinel },
			func(string) error { published++; return nil })
		if !errors.Is(err, sentinel) {
			t.Fatalf("the failing answer did not come back: %v", err)
		}
		if published != 0 {
			t.Error("the writer published past a failing answer")
		}
	})
	t.Run("a failing write", func(t *testing.T) {
		_, err := orderedNarrow(root, 2,
			func(string) (narrowDecision, error) { return narrowApply, nil },
			func(string) error { return sentinel })
		if !errors.Is(err, sentinel) {
			t.Fatalf("the failing write did not come back: %v", err)
		}
	})
	t.Run("a walk that cannot start", func(t *testing.T) {
		if _, err := orderedNarrow(filepath.Join(root, "gone"), 2,
			func(string) (narrowDecision, error) { return narrowNoop, nil },
			func(string) error { return nil }); err == nil {
			t.Fatal("a root that is not there reported success")
		}
	})

	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if left := runtime.NumGoroutine(); left > before {
		t.Errorf("%d goroutines were still standing after the walk gave up, started with %d", left, before)
	}
}
