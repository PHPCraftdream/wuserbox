package profile

import (
	"os"
	"path/filepath"
	"strings"

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
		if !mayMatchDescendant(cleanup, childRel) {
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

// What cleanup may never take is described once, in families.go: the two
// hives and the transaction families Windows builds beside them, shapes
// rather than examples. refuseReservedCleanup below is one of that
// description's two readers -- the glob question -- and reserved.go's
// guards are the other.

// CleanupNamesSomethingReserved answers whether any cleanup glob in the list
// would be refused for reaching the registry hive, what the profile service
// keeps beside it, or the profile root itself, and if so, the exact message
// a run would give when the same check stopped it. Exported so validation
// asks this package the question rather than re-deciding it with a copy of
// the reserved names and the matching rules: two answers to "would this
// cleanup line be refused" are exactly how a rules file comes to pass
// validation and then fail the run.
func CleanupNamesSomethingReserved(cleanup []config.Mask) error {
	return refuseReservedCleanup(cleanup)
}

// refuseReservedCleanup refuses the whole run if any cleanup glob can match
// the registry hive, what the profile service keeps beside it, or the
// profile root itself, checked against the glob as written rather than
// waiting for the walk to reach the file. The glob is answered against the
// reserved families' whole language -- reservedFamilyReachedBy -- so a glob
// reaches nothing by spelling a member the old examples never carried: the
// TxR set, a container past its first counter, a GUID some other machine's
// hive left. A glob that says ** is refused for
// the same reason a glob naming NTUSER.DAT outright would be: it is asking
// for something that cannot be granted, and saying so plainly is kinder than
// clearing everything else and quietly skipping the one name that cannot go.
//
// This is enforced here, when the rules are read, rather than by skipping
// the reserved names during the walk below. Skipping would make "cleanup:
// [**]" appear to succeed while doing something quite different from what it
// says -- clearing an entire profile apart from one file nobody who wrote
// that line was thinking about -- and that is a worse outcome than refusing
// the run.
//
// A glob naming a directory a reserved file sits under is refused the same
// way, though it matches none of the reserved paths: matchMask tests a
// name-only glob against the last segment, so "AppData" never matches
// AppData\Local\Microsoft\Windows\UsrClass.dat -- that path ends in
// UsrClass.dat -- and yet the walk removes the AppData directory whole,
// hive and all, with Copy reporting success. Removing the directory is the
// same destruction with one name fewer, so every ancestor of a reserved
// path is tested exactly as the path itself is.
//
// The questions are asked of the spelling the volume would act on as well
// as the one written, and the message still names the pattern as written.
// A cleanup glob is refused for what it asks for, and "NTUSER.DAT." asks
// for the hive as surely as "NTUSER.DAT" does -- Windows strips trailing
// dots and spaces per segment before it opens or creates a name, so the
// volume opens them onto the same file, measured. A segment spelled like
// an 8.3 alias is asked the same way through the wildcard the alias really
// stands for: the volume resolves the short spelling onto whatever long
// name it aliases, and the glob would ride along. A normalized spelling
// that reaches no reserved family refuses nothing -- the as-written check
// is the one that has always run, and a glob that names nothing reserved
// under either reading is exactly what cleanup is for.
func refuseReservedCleanup(cleanup []config.Mask) error {
	for _, mask := range cleanup {
		if err := refuseReservedGlobSpelling(mask.Pattern); err != nil {
			return err
		}
		// The same questions asked of the spelling the volume would read,
		// which exists only where the written one is one the volume
		// improves on -- a glob stored exactly as it is spelled pays
		// nothing here. The error is wrapped rather than returned so the
		// message keeps naming the pattern as written: that is the line
		// the person reading it can find in the rules file.
		if stripped := paddedGlobStripped(mask.Pattern); stripped != mask.Pattern {
			if err := refuseReservedGlobSpelling(stripped); err != nil {
				return exit.Errorf(exit.BadConfig,
					"cleanup glob %q ends a segment in dots or spaces, and Windows strips those "+
						"before it opens or creates anything -- the glob asks for the same thing "+
						"its stripped spelling does, as surely: %s",
					mask.Pattern, err)
			}
		}
		if dealiased := shortNameGlobDealiased(mask.Pattern); dealiased != mask.Pattern {
			if err := reachedReservedGlob(dealiased); err != nil {
				return exit.Errorf(exit.BadConfig,
					"cleanup glob %q is spelled the way Windows spells an 8.3 alias, and the volume "+
						"resolves such a spelling onto the long name it aliases -- the star in what "+
						"follows stands for the truncation the alias does not show: %s",
					mask.Pattern, err)
			}
		}
	}
	return nil
}

// refuseReservedGlobSpelling is the whole of what one spelling of a
// cleanup glob is refused for: naming the profile root itself, reaching a
// reserved family's language, or matching a directory a family sits under.
// Kept as one question so the as-written and volume-read spellings are
// asked exactly the same three things -- refuseReservedCleanup asks it
// twice per glob where the two spellings differ.
func refuseReservedGlobSpelling(pattern string) error {
	if namesTheProfileRootItself(pattern) {
		return exit.Errorf(exit.BadConfig,
			"cleanup glob %q names the profile root itself, which cleanup may never remove -- "+
				"name what to clear inside it instead", pattern)
	}
	return reachedReservedGlob(pattern)
}

// reachedReservedGlob is refuseReservedGlobSpelling without the root-itself
// check -- the two questions about what a glob's language reaches. The
// volume-read spellings are asked these two only: a root-itself glob is "."
// or empty in whatever spelling, and no spelling the volume would improve on
// is part of writing one.
func reachedReservedGlob(pattern string) error {
	if fam, reached := reservedFamilyReachedBy(pattern); reached {
		if fam.hive {
			return exit.Errorf(exit.BadConfig,
				"cleanup glob %q matches %s, which is the sandbox's own registry hive -- "+
					"deleting it does not clear a cache, it destroys HKEY_CURRENT_USER "+
					"and the sandbox will not start again", pattern, fam.example)
		}
		return exit.Errorf(exit.BadConfig,
			"cleanup glob %q reaches %s -- one of the transaction files Windows keeps beside "+
				"the sandbox's registry, whose GUID and counter differ machine to machine and "+
				"run to run, so the family stands or falls as one. The profile service built "+
				"it, not the sandbox: cleanup clears what the sandbox wrote, not what Windows "+
				"keeps beside its registry", pattern, fam.example)
	}
	for _, fam := range reservedFamilies {
		for _, dir := range familyAncestors(fam) {
			if matchMask(pattern, dir) {
				return exit.Errorf(exit.BadConfig,
					"cleanup glob %q matches %s, the directory %s sits under -- clearing the "+
						"directory clears the hive with it, which is the same destruction with "+
						"one name fewer. Name what the sandbox wrote instead",
					pattern, dir, fam.example)
			}
		}
	}
	return nil
}

// paddedGlobStripped spells a cleanup glob the way the volume reads it:
// each segment loses the trailing dots and spaces Win32 strips per segment
// before it opens or creates a name. Pure string work on the forward-slash
// form globs are written in -- the volume never stores a name carrying
// them, so nothing the walk could ever match does either.
func paddedGlobStripped(pattern string) string {
	segs := strings.Split(pattern, "/")
	for i, seg := range segs {
		segs[i] = strings.TrimRight(seg, ". ")
	}
	return strings.Join(segs, "/")
}

// shortNameGlobDealiased spells a cleanup glob with every segment shaped
// like an 8.3 alias opened into the wildcard the alias really stands for:
// the trailing tilde-and-digits becomes *, the extension stays --
// "NTUSER~1.BLF" becomes "NTUSER*.BLF" -- because the volume resolves the
// short spelling onto whatever long name it aliases, and the truncation is
// the part the alias does not show. Segments that are not short-name
// shaped are left alone, and a glob with none of them comes back as it
// went in.
func shortNameGlobDealiased(pattern string) string {
	segs := strings.Split(pattern, "/")
	for i, seg := range segs {
		if !looksLikeShortName(seg) {
			continue
		}
		ext := ""
		base := seg
		if j := strings.LastIndexByte(seg, '.'); j >= 0 {
			base, ext = seg[:j], seg[j:]
		}
		j := strings.LastIndexByte(base, '~')
		segs[i] = base[:j] + "*" + ext
	}
	return strings.Join(segs, "/")
}

// familyAncestors lists the directories a family's files sit under and in,
// nearest the family's directory first, as forward-slash paths relative to
// the profile root -- the question ancestorsOf answered of a concrete
// reserved path, asked of the one directory a whole family shares. A
// family at the profile root has none: a bare name is the whole of its
// path, and no directory is taken with it.
func familyAncestors(fam reservedShape) []string {
	if fam.dir == "" {
		return nil
	}
	return append(ancestorsOf(fam.dir), fam.dir)
}

// namesTheProfileRootItself reports whether a glob, cleaned as a path, comes
// to the profile root and not anything inside it -- "." or an empty pattern,
// the two ways of writing "here" rather than naming something in it. Neither
// wildcard nor a separator lets a glob reach further up than the root cleanup
// is already anchored to, so this is the whole of what could ever name it.
func namesTheProfileRootItself(pattern string) bool {
	return filepath.Clean(filepath.FromSlash(pattern)) == "."
}

// ancestorsOf lists the directories a reserved path sits under, nearest the
// reserved file first, as forward-slash paths relative to the profile root.
// Pure string work on the forward-slash form the reserved paths are written
// in: filepath.Dir would swap the separators under this platform's rules,
// and matchMask reads forward slashes only.
func ancestorsOf(path string) []string {
	var dirs []string
	for i := strings.LastIndexByte(path, '/'); i >= 0; i = strings.LastIndexByte(path[:i], '/') {
		dirs = append(dirs, path[:i])
	}
	return dirs
}
