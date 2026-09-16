package profile

import (
	"os"
	"path/filepath"

	"github.com/PHPCraftdream/wuserbox/internal/base/exit"
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
	if len(cleanup) == 0 || root == nil {
		return nil, nil
	}
	if err := refuseReservedCleanup(cleanup); err != nil {
		return nil, err
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
		info, readable := lookAt(root, childPath)
		if !readable {
			continue
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

// reservedProfileNames are what refuseReservedCleanup tests every glob
// against: the registry hive's own file, and one representative of each kind
// of companion it keeps beside it. NTUSER.DAT's transaction files carry a
// GUID and a counter that differ machine to machine and run to run, so a
// representative name stands in for the whole family -- a glob that matches
// this one matches every other member of it too, since nothing about the
// varying part of the name changes what pattern would have to reach it.
var reservedProfileNames = []string{
	"NTUSER.DAT",
	"NTUSER.DAT.LOG1",
	"NTUSER.DAT.LOG2",
	"ntuser.ini",
	"NTUSER.DAT{a0876e4c-1cb1-11d9-9669-0800200c9a66}.TM.blf",
	"NTUSER.DAT{a0876e4c-1cb1-11d9-9669-0800200c9a66}.TMContainer00000000000000000001.regtrans-ms",
}

// refuseReservedCleanup refuses the whole run if any cleanup glob can match
// the registry hive or the profile root itself, checked against the glob as
// written rather than waiting for the walk to reach the file. A glob that
// says ** is refused for the same reason a glob naming NTUSER.DAT outright
// would be: it is asking for something that cannot be granted, and saying so
// plainly is kinder than clearing everything else and quietly skipping the
// one name that cannot go.
//
// This is enforced here, when the rules are read, rather than by skipping
// the reserved names during the walk below. Skipping would make "cleanup:
// [**]" appear to succeed while doing something quite different from what it
// says -- clearing an entire profile apart from one file nobody who wrote
// that line was thinking about -- and that is a worse outcome than refusing
// the run.
// CleanupNamesSomethingReserved answers whether any cleanup glob in the list
// would be refused for reaching the registry hive or the profile root
// itself, and if so, the exact message a run would give when the same check
// stopped it. Exported so validation asks this package the question rather
// than re-deciding it with a copy of the reserved names and the matching
// rules: two answers to "would this cleanup line be refused" are exactly how
// a rules file comes to pass validation and then fail the run.
func CleanupNamesSomethingReserved(cleanup []config.Mask) error {
	return refuseReservedCleanup(cleanup)
}

func refuseReservedCleanup(cleanup []config.Mask) error {
	for _, mask := range cleanup {
		if namesTheProfileRootItself(mask.Pattern) {
			return exit.Errorf(exit.BadConfig,
				"cleanup glob %q names the profile root itself, which cleanup may never remove -- "+
					"name what to clear inside it instead", mask.Pattern)
		}
		for _, name := range reservedProfileNames {
			if matchMask(mask.Pattern, name) {
				return exit.Errorf(exit.BadConfig,
					"cleanup glob %q matches %s, which is the sandbox's own registry hive -- "+
						"deleting it does not clear a cache, it destroys HKEY_CURRENT_USER "+
						"and the sandbox will not start again", mask.Pattern, name)
			}
		}
	}
	return nil
}

// namesTheProfileRootItself reports whether a glob, cleaned as a path, comes
// to the profile root and not anything inside it -- "." or an empty pattern,
// the two ways of writing "here" rather than naming something in it. Neither
// wildcard nor a separator lets a glob reach further up than the root cleanup
// is already anchored to, so this is the whole of what could ever name it.
func namesTheProfileRootItself(pattern string) bool {
	return filepath.Clean(filepath.FromSlash(pattern)) == "."
}
