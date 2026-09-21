package profile

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
)

// skipTree plants the representative profile the P3-1 close test walks: one
// program's cache the cleanup globs are scoped to, beside the histories,
// logs and sessions of other programs in the same profile, and the profile
// service's own registry files. Sixteen directories under the root, of
// which a scoped glob can reach a branch of three.
func skipTree(t *testing.T, root string) {
	t.Helper()
	for _, f := range []string{
		"NTUSER.DAT",
		"root.log",
		"AppData/Local/Microsoft/Windows/UsrClass.dat",
		"AppData/Local/Microsoft/Windows/stale.log",
		"cache/entries/alpha.tmp",
		"cache/entries/beta.tmp",
		"cache/entries/nested/gamma.tmp",
		"history/2024/session-one.log",
		"logs/scan.log",
		"logs/agent/debug.log",
		".codex/sessions/first/one.json",
		"sessions/old/x.log",
	} {
		write(t, filepath.Join(root, filepath.FromSlash(f)), "content of "+f)
	}
}

// atDepth is a mask depth for the tables below, the pointer the config
// carries so omitted and zero stay different answers.
func atDepth(d int) *int { return &d }

// legacyCleanDir is cleanDir as this branch found it: every non-matching
// plain directory is recursed into, whatever the globs could ever reach
// inside it. It is here and not in production so the close test can run
// both walkers over one tree and hold their results against each other --
// the number it clocks is what the skip saves. The body is the old walk's
// own: the same matchesCleanup, the same lookAt guard, the same recursion.
func legacyCleanDir(root *os.Root, dir, rel string, cleanup []config.Mask, matched *[]CleanupPlan, remove bool, visits *int) error {
	d, err := root.Open(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	children, err := d.ReadDir(-1)
	_ = d.Close()
	if err != nil {
		return err
	}
	*visits++
	for _, child := range children {
		childRel := child.Name()
		if rel != "" {
			childRel = rel + "/" + child.Name()
		}
		childPath := filepath.Join(dir, child.Name())
		if matchesCleanup(cleanup, childRel) {
			if remove {
				if err := root.RemoveAll(childPath); err != nil {
					return err
				}
				*matched = append(*matched, CleanupPlan{Path: childRel})
				continue
			}
			files, err := countUnder(root, childPath, child.IsDir())
			if err != nil {
				return err
			}
			*matched = append(*matched, CleanupPlan{Path: childRel, Files: files})
			continue
		}
		info, readable := lookAt(root, childPath)
		if !readable {
			continue
		}
		if !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			continue
		}
		if err := legacyCleanDir(root, childPath, childRel, cleanup, matched, remove, visits); err != nil {
			return err
		}
	}
	return nil
}

// sortedPlanPaths is a table's plan list as a sorted path list, so a
// comparison can say "the same matches" without leaning on the order two
// walkers over one tree produce anyway.
func sortedPlanPaths(plans []CleanupPlan) []string {
	out := make([]string, len(plans))
	for i, p := range plans {
		out[i] = p.Path
	}
	sort.Strings(out)
	return out
}

// countWalk holds every directory the production walk enumerates, through
// the same seam the measurement reads, and hands the count back with the
// seam restored.
func countWalk(count *int) (restore func()) {
	previous := cleanDirVisit
	cleanDirVisit = func(string) { *count++ }
	return func() { cleanDirVisit = previous }
}

// TestCleanupSkipsBranchesNoGlobCanReach is the P3-1 close test's counter.
// Over one constructed tree, a cleanup rule scoped to one cache folder
// costs the old walk -- kept above -- an enumeration of every directory in
// the profile, and costs the new walk only the branch the glob can reach.
// The matches the two walks report have to be the same plans, file counts
// and order included, or the counter would be certifying a cheaper way of
// answering differently.
func TestCleanupSkipsBranchesNoGlobCanReach(t *testing.T) {
	cases := []struct {
		name      string
		masks     []config.Mask
		oldVisits int
		newVisits int
		paths     []string
	}{
		{
			name:      "a glob scoped to one cache folder",
			masks:     config.Masks([]string{"cache/entries/*.tmp"}),
			oldVisits: 17,
			newVisits: 3,
			paths:     []string{"cache/entries/alpha.tmp", "cache/entries/beta.tmp"},
		},
		{
			name:      "a name-only glob held to two levels",
			masks:     []config.Mask{{Pattern: "*.tmp", Depth: atDepth(2)}},
			oldVisits: 17,
			newVisits: 13,
			paths:     []string{"cache/entries/alpha.tmp", "cache/entries/beta.tmp"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dest := t.TempDir()
			skipTree(t, dest)
			root, err := os.OpenRoot(dest)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()

			var oldPlans []CleanupPlan
			var oldVisits int
			if err := legacyCleanDir(root, ".", "", tc.masks, &oldPlans, false, &oldVisits); err != nil {
				t.Fatal(err)
			}

			var newVisits int
			restore := countWalk(&newVisits)
			newPlans, err := previewCleanup(root, tc.masks)
			restore()
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(oldPlans, newPlans) {
				t.Errorf("the full walk reported %v, the skipping walk %v -- the plans must be identical", oldPlans, newPlans)
			}
			if oldVisits != tc.oldVisits || newVisits != tc.newVisits {
				t.Errorf("the full walk enumerated %d directories and the skipping walk %d, want %d and %d over this tree",
					oldVisits, newVisits, tc.oldVisits, tc.newVisits)
			}
			if got := sortedPlanPaths(newPlans); !reflect.DeepEqual(got, tc.paths) {
				t.Errorf("the skipping walk matched %v, want %v", got, tc.paths)
			}
		})
	}

	// The same question at the real entry point, removal included: two
	// identical trees, the old walk on one and clearCleanup on the other.
	// The removed paths come back in the same order, what survives is the
	// same set of files on both sides, and the registry hive is still
	// there holding what the profile service wrote.
	legacyDest, newDest := t.TempDir(), t.TempDir()
	skipTree(t, legacyDest)
	skipTree(t, newDest)
	masks := config.Masks([]string{"cache/entries/*.tmp"})

	legacyRoot, err := os.OpenRoot(legacyDest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = legacyRoot.Close() }()
	var legacyPlans []CleanupPlan
	var legacyVisits int
	if err := legacyCleanDir(legacyRoot, ".", "", masks, &legacyPlans, true, &legacyVisits); err != nil {
		t.Fatal(err)
	}

	newRoot, err := os.OpenRoot(newDest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = newRoot.Close() }()
	var removedVisits int
	restore := countWalk(&removedVisits)
	removed, err := clearCleanup(newRoot, masks)
	restore()
	if err != nil {
		t.Fatal(err)
	}

	var legacyRemoved []string
	for _, p := range legacyPlans {
		legacyRemoved = append(legacyRemoved, p.Path)
	}
	if !reflect.DeepEqual(removed, legacyRemoved) {
		t.Errorf("clearCleanup removed %v, the full walk %v", removed, legacyRemoved)
	}
	if removedVisits >= legacyVisits {
		t.Errorf("the skipping removal enumerated %d directories against the full walk's %d and saved nothing", removedVisits, legacyVisits)
	}

	legacyFiles, newFiles := treeFiles(t, legacyDest), treeFiles(t, newDest)
	if !reflect.DeepEqual(legacyFiles, newFiles) {
		t.Errorf("the two trees disagree after their cleanups: %v against %v", legacyFiles, newFiles)
	}
	for _, hive := range []string{"NTUSER.DAT", "AppData/Local/Microsoft/Windows/UsrClass.dat"} {
		want := read(t, filepath.Join(legacyDest, filepath.FromSlash(hive)))
		if got := read(t, filepath.Join(newDest, filepath.FromSlash(hive))); got != want {
			t.Errorf("%s does not hold the same content on both sides: %q against %q", hive, got, want)
		}
	}
}

// treeFiles lists every regular file under root as a slash-spelled path
// relative to it, sorted, so two trees can be held against each other by
// what survived in them.
func treeFiles(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

// TestCleanupWalkAnswersExactlyAsTheFullWalkAcrossTheGlobClasses runs the
// old walk and the skipping walk over the same tree for every class of
// glob the review named -- ** patterns, depth limits, globs whose interest
// leaves most of the tree alone, and globs reaching next to the registry
// families -- and holds the two answers against each other: the same
// plans, file counts and order, every time. The visit counts are pinned
// per class so the table says which side of the line each glob lands on:
// a glob whose reach no branch can be ruled out of walks everything, the
// way it always did, and a glob with a literal disagreement at a shared
// segment skips what it provably cannot match -- "sessions/**" among them,
// whose ** never makes the other top-level branches reachable.
func TestCleanupWalkAnswersExactlyAsTheFullWalkAcrossTheGlobClasses(t *testing.T) {
	cases := []struct {
		name      string
		masks     []config.Mask
		oldVisits int
		newVisits int
		paths     []string
	}{
		{
			name:      "a ** over the whole profile walks everything",
			masks:     config.Masks([]string{"**/*.log"}),
			oldVisits: 17,
			newVisits: 17,
			paths: []string{
				"AppData/Local/Microsoft/Windows/stale.log",
				"history/2024/session-one.log",
				"logs/agent/debug.log",
				"logs/scan.log",
				"root.log",
				"sessions/old/x.log",
			},
		},
		{
			name:      "a ** behind a literal disagreement still skips",
			masks:     config.Masks([]string{"sessions/**"}),
			oldVisits: 15,
			newVisits: 1,
			paths:     []string{"sessions"},
		},
		{
			name:      "a ** in the middle walks its own branch and skips the rest",
			masks:     config.Masks([]string{"cache/**/*.tmp"}),
			oldVisits: 17,
			newVisits: 4,
			paths: []string{
				"cache/entries/alpha.tmp",
				"cache/entries/beta.tmp",
				"cache/entries/nested/gamma.tmp",
			},
		},
		{
			name:      "an anchored glob one level deep skips its siblings",
			masks:     config.Masks([]string{"logs/*.log"}),
			oldVisits: 17,
			newVisits: 2,
			paths:     []string{"logs/scan.log"},
		},
		{
			name:      "a name-only glob with no depth walks everything",
			masks:     config.Masks([]string{"*.tmp"}),
			oldVisits: 17,
			newVisits: 17,
			paths: []string{
				"cache/entries/alpha.tmp",
				"cache/entries/beta.tmp",
				"cache/entries/nested/gamma.tmp",
			},
		},
		{
			name:      "the same glob held to two levels skips below them",
			masks:     []config.Mask{{Pattern: "*.tmp", Depth: atDepth(2)}},
			oldVisits: 17,
			newVisits: 13,
			paths: []string{
				"cache/entries/alpha.tmp",
				"cache/entries/beta.tmp",
			},
		},
		{
			name:      "a glob whose branch does not exist matches nothing on either side",
			masks:     config.Masks([]string{"cache/entries/deep/x.tmp"}),
			oldVisits: 17,
			newVisits: 3,
			paths:     nil,
		},
		{
			name:      "a glob held to the root level skips every branch",
			masks:     []config.Mask{{Pattern: "*.log", Depth: atDepth(0)}},
			oldVisits: 17,
			newVisits: 1,
			paths:     []string{"root.log"},
		},
		{
			name:      "a glob reaching beside the class hive finds its match there and nowhere else",
			masks:     config.Masks([]string{"AppData/Local/Microsoft/Windows/*.log"}),
			oldVisits: 17,
			newVisits: 5,
			paths:     []string{"AppData/Local/Microsoft/Windows/stale.log"},
		},
		{
			name:      "a glob spelled in the other case asks the matcher's own fold",
			masks:     config.Masks([]string{"CACHE/ENTRIES/*.TMP"}),
			oldVisits: 17,
			newVisits: 3,
			paths: []string{
				"cache/entries/alpha.tmp",
				"cache/entries/beta.tmp",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dest := t.TempDir()
			skipTree(t, dest)
			root, err := os.OpenRoot(dest)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()

			var oldPlans []CleanupPlan
			var oldVisits int
			if err := legacyCleanDir(root, ".", "", tc.masks, &oldPlans, false, &oldVisits); err != nil {
				t.Fatal(err)
			}

			var newVisits int
			restore := countWalk(&newVisits)
			newPlans, err := previewCleanup(root, tc.masks)
			restore()
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(oldPlans, newPlans) {
				t.Errorf("the full walk reported %v, the skipping walk %v -- the plans must be identical", oldPlans, newPlans)
			}
			if oldVisits != tc.oldVisits || newVisits != tc.newVisits {
				t.Errorf("the full walk enumerated %d directories and the skipping walk %d, want %d and %d over this tree",
					oldVisits, newVisits, tc.oldVisits, tc.newVisits)
			}
			if got, want := sortedPlanPaths(newPlans), tc.paths; len(got) != 0 || len(want) != 0 {
				if !reflect.DeepEqual(got, want) {
					t.Errorf("both walks matched %v, want %v", got, want)
				}
			}
		})
	}
}

// TestTheSkipNeverRulesOutWhatTheMatcherCanMatch is the property the one
// failure mode rests on: whenever mayMatchDescendant answers no for a
// branch, the matcher answers no for every path that branch could ever
// hold. The universe below is every path of up to three segments over six
// names, the prefixes every path of up to two plus the root, and the masks
// every shape the rules file can write -- ** at the head, in the middle
// and alone, name-only globs, anchored literals, wildcards, question
// marks, the fold's other case, a trailing separator, an empty middle
// segment, and depth limits at every level -- so a no the matcher could
// contradict has somewhere to show itself. A no is then checked against
// the whole universe below the prefix, one matcher call per path.
func TestTheSkipNeverRulesOutWhatTheMatcherCanMatch(t *testing.T) {
	segments := []string{"a", "b", "cache", "logs", "x.tmp", "a.log"}
	var universe []string
	for _, one := range segments {
		universe = append(universe, one)
		for _, two := range segments {
			universe = append(universe, one+"/"+two)
			for _, three := range segments {
				universe = append(universe, one+"/"+two+"/"+three)
			}
		}
	}
	prefixes := []string{""}
	for _, one := range segments {
		prefixes = append(prefixes, one)
		for _, two := range segments {
			prefixes = append(prefixes, one+"/"+two)
		}
	}
	lists := [][]config.Mask{
		config.Masks([]string{
			"**", "**/*.tmp", "**/*.log", "cache/**", "cache/**/*.tmp", "a/**/b",
			"*.tmp", "a.log", "x.tmp", "cache", "cache/x.tmp", "*/x.tmp", "a/b",
			"?.tmp", "?a.log", "CACHE/X.TMP", "a/", "a//b", "*.blf",
		}),
		{{Pattern: "*.tmp", Depth: atDepth(0)}},
		{{Pattern: "*.tmp", Depth: atDepth(1)}},
		{{Pattern: "*.tmp", Depth: atDepth(2)}},
		{{Pattern: "*.tmp", Depth: atDepth(3)}},
		{{Pattern: "cache/x.tmp", Depth: atDepth(1)}},
		{{Pattern: "cache/x.tmp", Depth: atDepth(2)}},
		{{Pattern: "**/*.tmp", Depth: atDepth(1)}},
		{{Pattern: "**/*.tmp", Depth: atDepth(2)}},
		{{Pattern: "a/b", Depth: atDepth(1)}},
		{config.Mask{Pattern: "cache/x.tmp"}, config.Mask{Pattern: "*.log"}},
		{config.Mask{Pattern: "a/b"}, config.Mask{Pattern: "*.tmp", Depth: atDepth(1)}},
	}
	proved := 0
	for _, list := range lists {
		for _, prefix := range prefixes {
			if mayMatchDescendant(list, prefix) {
				continue
			}
			proved++
			for _, candidate := range universe {
				below := strings.HasPrefix(candidate, prefix+"/")
				if below && matchesCleanup(list, candidate) {
					t.Fatalf("the skip ruled out %q for %v, but the matcher matches %q",
						prefix, list, candidate)
				}
			}
		}
	}
	if proved == 0 {
		t.Fatal("the skip never answered no over the whole universe, so this test holds it to nothing")
	}
	if !mayMatchDescendant(config.Masks([]string{"**"}), "") {
		t.Error("the profile root itself was ruled out; the walk starts there whatever the globs say")
	}
	if mayMatchDescendant(config.Masks([]string{"cache/x.tmp"}), "logs") {
		t.Error(`the skip could not rule "logs" out of "cache/x.tmp"'s reach, though the branch does not share one segment with it`)
	}
}
