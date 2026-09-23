package profile

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
)

// CleanupPlan is one cleanup glob's match: the path relative to the profile
// root, and how many files that comes to -- 1 for a matched file, a whole
// directory's count for a matched directory. Files is left at 0 by a real
// cleanup, which has no use for the number and would pay an extra walk of
// whatever it is about to remove whole just to produce it; only a preview,
// through previewCleanup, fills it in.
type CleanupPlan struct {
	Path  string
	Files int
}

// clearCleanup removes what the rules file's cleanup globs match from dest,
// before anything else in a fill runs -- a rule about what should not be
// there is applied before anything decides what to bring in.
//
// An empty list returns without opening the profile at all: no glob named,
// nothing to look for, and a rules file that never mentions cleanup must not
// pay for a walk of a sandbox's whole profile on every run.
func clearCleanup(root *os.Root, cleanup []config.Mask) ([]string, error) {
	if len(cleanup) == 0 {
		return nil, nil
	}
	if err := refuseReservedCleanup(cleanup); err != nil {
		return nil, err
	}
	var matched []CleanupPlan
	if err := cleanDir(root, ".", "", cleanup, &matched, true); err != nil {
		return cleanupPaths(matched), err
	}
	return cleanupPaths(matched), nil
}

// previewCleanup answers what clearCleanup would remove, without removing
// it. It walks the same cleanDir clearCleanup does, matching each path the
// same matchesCleanup call decides on -- so a preview can never name a glob
// a real cleanup would not also match, or miss one it would.
//
// A nil root -- dest does not exist yet -- answers no matches rather than
// failing: a profile that is not there yet has nothing for a glob to reach.
func previewCleanup(root *os.Root, cleanup []config.Mask) ([]CleanupPlan, error) {
	if len(cleanup) == 0 {
		return nil, nil
	}
	if err := refuseReservedCleanup(cleanup); err != nil {
		return nil, err
	}
	if root == nil {
		return nil, nil
	}
	var matched []CleanupPlan
	if err := cleanDir(root, ".", "", cleanup, &matched, false); err != nil {
		return nil, err
	}
	return matched, nil
}

// cleanupPaths keeps clearCleanup's own return type -- []string, not
// []CleanupPlan -- the shape its one caller inside Copy and its tests have
// always had, since nothing there has ever needed a file count.
func cleanupPaths(plans []CleanupPlan) []string {
	if plans == nil {
		return nil
	}
	out := make([]string, len(plans))
	for i, p := range plans {
		out[i] = p.Path
	}
	return out
}

// cleanDir walks one directory of the destination profile, through root, and
// either removes what a cleanup glob matches (remove true) or only counts it
// (remove false, a preview). A match is not descended into -- there is
// nothing left to decide inside something already taken whole -- and a
// directory not descended into is not recursed at all, exactly as walkDir
// and clearEntry already treat the same shape.
func cleanDir(root *os.Root, dir, rel string, cleanup []config.Mask, matched *[]CleanupPlan, remove bool) error {
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
	cleanDirVisit(rel)
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
			// Counted only for a preview: a real cleanup does not need the
			// number, and counting a directory's files before removing it
			// whole would pay the very cost this walk exists to avoid --
			// exactly on the session histories and caches cleanup is most
			// likely to be pointed at.
			files, err := countUnder(root, childPath, child.IsDir())
			if err != nil {
				return err
			}
			*matched = append(*matched, CleanupPlan{Path: childRel, Files: files})
			continue
		}
		// The relevance question comes first, before the volume is asked
		// anything about the child: a branch no glob can reach is skipped
		// whole, its directories never opened and its names never looked
		// at, which is mayMatchDescendant's own contract. Asking it first
		// is also what keeps another program's hold from stopping a
		// cleanup it has nothing to do with -- a directory the globs
		// cannot reach that a running process keeps shut refuses the look
		// below with a sharing violation, and a walk that looked before
		// asking the globs would fail a run over a branch no glob ever
		// named.
		if !mayMatchDescendant(cleanup, childRel) {
			continue
		}
		// Lstat, not the ReadDir entry's own type bit: a junction the
		// sandbox planted has to be recognized here the same defensive way
		// clearWhatIsNotADirectory recognizes one, rather than trusted to
		// report itself honestly. Walking into a link the root refuses to
		// open would not leak anything -- the root still stops that -- but
		// it would fail the whole cleanup over an artifact the sandbox is
		// entitled to leave lying around, which is worse than leaving it
		// alone. Measured: skipping this check turns the junction test
		// above into a hard failure of the run, "path escapes from
		// parent", instead of a link cleanup quietly does not follow.
		//
		// This is the branch the globs can reach, so the error is asked
		// rather than folded into a skip: what stands under this name, or
		// would stand under it had it been a directory, is exactly what
		// the rules file asked cleared, and a look that cannot finish is
		// not an answer that nothing is there. The volume's own nothing --
		// the branch gone between the listing above and this look -- is
		// still the nothing to walk past; any other refusal, an ordinary
		// program's exclusive hold most commonly, stops the run with the
		// error it got. The globs are read again by every run, so the next
		// one asks again, where folding the refusal into a skip reported a
		// whole cleanup over a match this walk never saw.
		info, err := root.Lstat(childPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		if !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			continue
		}
		if err := cleanDir(root, childPath, childRel, cleanup, matched, remove); err != nil {
			return err
		}
	}
	return nil
}

// cleanDirVisit is a variable so the counting test can hold every directory
// the walk enumerates without the production path knowing it is measured --
// the seam newPlaceResolver gives the dedupe close test, for the same
// reason. The number is read, never used to decide.
var cleanDirVisit = func(rel string) {}

// mayMatchDescendant answers whether anything at or below one directory of
// the profile could match a cleanup glob, from what the globs say on their
// own and before the volume is asked to list what is inside. A branch the
// answer is no for is skipped whole: its directories are never opened, its
// files never looked at, the masks never asked about anything under it --
// because no path under it could ever come out of matchesCleanup a match.
// A warm startup with a cleanup rule scoped to one cache folder no longer
// pays for listing every other program's histories and logs in the same
// profile.
//
// The answer errs the only safe way, toward perhaps. Every skip rests on
// the two facts the matcher itself runs on -- a glob carrying a separator
// is anchored at the profile root, and a mask's depth bounds the depth of
// what it matches -- and the segment question is matchSegment's own, asked
// of the directory's names on both folded sides, so what the skip believes
// about a segment is exactly what matching it would believe. A glob with
// ** in it is answered perhaps wherever the star stands between the branch
// and the match -- what it absorbs depends on names only the walk has -- so
// such a branch is walked as always. The one thing this may never do is
// answer no over a branch a glob could reach: a skipped match is a file the
// rules file asked to clear, quietly kept.
//
// The profile root itself is always a perhaps: the walk starts there
// whatever the globs say, and its descendants are everything.
func mayMatchDescendant(cleanup []config.Mask, dirRel string) bool {
	if dirRel == "" {
		return true
	}
	for _, mask := range cleanup {
		if maskMayReachBelow(mask, dirRel) {
			return true
		}
	}
	return false
}

// maskMayReachBelow is mayMatchDescendant's question for one mask: false
// only where no descendant of dirRel could match it, and perhaps everywhere
// else. The three provable noes are the reach -- everything below sits
// deeper than the mask looks -- the shared segment, where the branch and
// the pattern disagree at a name every descendant carries, and the pattern
// exhausted inside the branch, where a match would need more segments than
// a **-free pattern has. Everything else is perhaps.
func maskMayReachBelow(mask config.Mask, dirRel string) bool {
	var noEntry config.Entry
	reach := noEntry.DepthFor(mask)
	if reach != nil && *reach <= depthBelow(dirRel) {
		// Everything below dirRel sits deeper than the mask reaches.
		return false
	}
	segs := strings.Split(dirRel, "/")
	psegs := strings.Split(mask.Pattern, "/")
	if len(psegs) == 1 {
		// No separator: the matcher tests the last segment only, so the
		// question is whether the branch could hold a file of that name,
		// and one cannot be ruled out -- only the reach above did.
		return true
	}
	for i, seg := range segs {
		if i >= len(psegs) {
			// The pattern ended inside dirRel. No ** was met on the way
			// here -- it would have answered perhaps below -- so a match
			// needs exactly the pattern's segments, and everything under
			// the branch has more.
			return false
		}
		if psegs[i] == "**" {
			// The star absorbs any number of segments from here down,
			// and where it stops is not decidable without the names the
			// branch holds: perhaps.
			return true
		}
		if !matchSegment(foldedName(psegs[i]), foldedName(seg)) {
			// The branch and the pattern disagree at a segment every
			// descendant shares; no name below can mend it.
			return false
		}
	}
	// dirRel is a literal prefix of the pattern; what remains names what
	// would sit below it.
	for _, seg := range psegs[len(segs):] {
		if seg == "**" {
			return true
		}
	}
	if len(psegs) == len(segs) {
		// The pattern names dirRel itself and nothing deeper. The matcher
		// was asked about the branch and did not match it, and with no **
		// left, nothing below can match either.
		return false
	}
	if reach != nil && len(psegs)-1 > *reach {
		// Without a ** a match sits at exactly the pattern's depth, and
		// the reach stops above it.
		return false
	}
	return true
}

// countUnder counts what a cleanup match at path would take with it, for a
// preview: 1 for a matched file, and every plain file below a matched
// directory, read through root so a junction sitting inside it is counted
// as the one entry it is and never followed into counting something outside
// the profile.
func countUnder(root *os.Root, path string, isDir bool) (int, error) {
	if !isDir {
		return 1, nil
	}
	d, err := root.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	children, err := d.ReadDir(-1)
	_ = d.Close()
	if err != nil {
		return 0, err
	}
	var n int
	for _, c := range children {
		info, err := c.Info()
		if err != nil {
			return 0, err
		}
		if info.IsDir() && info.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0 {
			sub, err := countUnder(root, filepath.Join(path, c.Name()), true)
			if err != nil {
				return 0, err
			}
			n += sub
			continue
		}
		n++
	}
	return n, nil
}

// matchesCleanup asks whether any cleanup glob matches one path relative to
// the profile root. Reuses reachesWithin and matchMask against a zero-value
// Entry: cleanup has no depth of its own to fall back to, so a bare glob
// reaches every depth and only a glob naming one of its own is bounded --
// the same rule an include or exclude mask follows when its entry sets no
// depth either.
func matchesCleanup(cleanup []config.Mask, rel string) bool {
	var noEntry config.Entry
	for _, mask := range cleanup {
		if reachesWithin(noEntry, mask, rel) && matchMask(mask.Pattern, rel) {
			return true
		}
	}
	return false
}
