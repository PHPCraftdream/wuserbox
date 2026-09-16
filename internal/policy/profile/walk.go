package profile

import (
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
)

// walk carries one entry's limits through a mirror: which files its include
// list copies, which paths its exclude list protects, and how far below the
// entry's path the copier may reach.
//
// Depth and the pattern are separate limits and both apply, so neither is
// derived from the other: a generous depth does not let "*.json" cross a
// separator, and a tight depth does not stop "sessions/**" matching what is
// within its reach. How deep a mask reaches is asked of the config package
// rather than read off the mask, because the fallback from a bare mask to
// the entry's depth is a rule about what the file means, and is already
// written there.
type walk struct {
	entry config.Entry
	// bound is how many directories below the entry's path the walk may
	// descend into, or nil for no limit. It is worked out once, so every
	// file and directory on the way down reads the same answer.
	bound *int
}

// newWalk works out how far the walk reaches. With no include list the
// entry's own depth is the bound, which is what bounds a bare entry's copy.
// With one, the deepest any include mask reaches is: the walk exists to find
// files the include list will copy, and an exclusion only ever narrows what
// is found, so exclusions do not extend the walk.
func newWalk(entry config.Entry) *walk {
	return &walk{entry: entry, bound: walkBound(entry)}
}

func walkBound(entry config.Entry) *int {
	if len(entry.Include) == 0 {
		return entry.Depth
	}
	var deepest *int
	for _, mask := range entry.Include {
		reach := entry.DepthFor(mask)
		if reach == nil {
			return nil
		}
		if deepest == nil || *reach > *deepest {
			deep := *reach
			deepest = &deep
		}
	}
	return deepest
}

// depthBelow counts how many directories below the entry's path a relative
// path sits at: a file directly in it counts 0, a file one level down 1.
// This is the unit the entry's depth and every mask's depth are written in.
func depthBelow(rel string) int {
	return strings.Count(rel, "/")
}

// copiesFile decides whether one file, at rel below the entry's path, is
// copied. Exclude is checked first, because exclude wins over include: a
// path matching both is excluded, the narrower statement being the one
// somebody wrote on purpose. With no include list the entry's depth is the
// only limit left, which is what a bare entry with a depth means. With one,
// a file is copied only if it matches at least one mask, each within its own
// reach -- include filters files only, never directories, so a directory is
// still walked and the masks get their chance at whatever is filed in it.
func (w *walk) copiesFile(rel string) bool {
	if w.excludes(rel) {
		return false
	}
	if len(w.entry.Include) == 0 {
		return w.bound == nil || depthBelow(rel) <= *w.bound
	}
	for _, mask := range w.entry.Include {
		if reachesWithin(w.entry, mask, rel) && matchMask(mask.Pattern, rel) {
			return true
		}
	}
	return false
}

// descends decides whether the walk goes into one directory, at rel below
// the entry's path. A directory an exclude mask matches is not descended
// into at all -- that is the whole of what an exclusion means to the walk,
// and merely skipping the files found inside it would still cost the walk.
// Otherwise the question is whether anything inside can be copied: files
// directly in that directory sit one level deeper than the directory, so
// depth 0 means no subdirectories at all rather than empty ones.
func (w *walk) descends(rel string) bool {
	if w.excludes(rel) {
		return false
	}
	return w.bound == nil || depthBelow(rel) < *w.bound
}

// excludes asks the entry's exclude masks about one path relative to it.
// The same question is asked twice on a run: once by the walk, to decide
// what not to bring in, and once by the mirroring, to decide what already in
// the destination is the sandbox's to keep. Both read one answer, or
// excluding a path would skip the copy and then delete it for not being in
// the source.
func (w *walk) excludes(rel string) bool {
	return protectedBy(w.entry, rel)
}

// protectedBy answers the exclude question for an entry that no longer has a
// walk to carry it, when a recorded entry is being taken back and its
// exclusions have to go on protecting what they named.
func protectedBy(entry config.Entry, rel string) bool {
	for _, mask := range entry.Exclude {
		if reachesWithin(entry, mask, rel) && matchMask(mask.Pattern, rel) {
			return true
		}
	}
	return false
}

// reachesWithin answers whether one mask's reach covers a path at rel below
// the entry: the mask's own depth where it names one, the entry's where it
// does not, and no limit where neither does. Asked of the entry rather than
// inlined so the copier reads the config package's answer instead of
// deciding it.
func reachesWithin(entry config.Entry, mask config.Mask, rel string) bool {
	reach := entry.DepthFor(mask)
	return reach == nil || depthBelow(rel) <= *reach
}
