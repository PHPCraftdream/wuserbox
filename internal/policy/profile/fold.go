package profile

import (
	"os"
	"path/filepath"
	"strings"
)

// Two instruments answer "are these two spellings one thing" here, because
// there are two questions. Comparisons that can only afford to be wrong by
// joining -- the mirroring's present list, the reserved tables' sparing,
// the masks, the record's dedupe, the duplicate refusal, the preview's
// gone-set -- fold, and what was measured to settle the fold is written at
// foldedName. FoldedEntryPath is its path-sized form, exported and
// foldedName not: the record and the rules file are compared outside this
// package too, and two answers to "is this the same entry" -- one here,
// one in the caller -- are how a path comes to be copied twice or cleared
// twice.
//
// The comparisons that decide a deletion -- forget's keep, copyEntries'
// vouch for the record -- are not among them, and they are why this file
// no longer says the folds are one question. A fold deletes in both wrong
// directions: joining two places the volume holds apart makes the record
// claim files this tool never copied, and Clear takes them; holding apart
// two spellings of one place makes forget read a recorded entry as a name
// the list no longer holds, and its copy is deleted. Once a volume
// disagrees with the fold -- i and U+0131, measured below -- no fold
// survives both, so those two do not fold at all: sameEntryPlace asks the
// volume.

// foldedName is the form one child's name is carried in on the present
// list, and the fold of every comparison in this package that errs by
// joining: the file system's, not Unicode's lowercase.
//
// The list is written from the source's directory entries and read against
// the destination's, and Windows opens either spelling onto the same file --
// a copy over AUTH.JSON lands in the file the source calls auth.json and
// the entry keeps the capitals it had -- so a map keyed by the bytes of one
// spelling reads the other as a stranger and removeStrayChildren takes what
// the run just put there. matchMask folds both of its sides with it too: a
// mask is asked under whatever spelling the destination's directory entry
// carries, and answering by a different fold than the volume opens names by
// is how an exclusion misses the file it was written to spare -- measured,
// Σ.json against the ς.json a sandbox held. It is a comparison key and
// nothing else: the paths handed to the root keep the spelling they were
// read with.
//
// The fold is ToUpper because that is the operation the file system itself
// performs: NTFS keeps a per-volume uppercase table and answers "are these
// the same name" by putting both sides through it, char for char -- which
// is also how CompareStringOrdinal with bIgnoreCase compares. ToLower was
// the old answer and is measured wrong: it maps capital sigma U+03A3 to
// U+03C3 and leaves final sigma U+03C2 alone, while this machine's NTFS
// opens Σ.txt, σ.txt and ς.txt onto one and the same file -- measured by
// writing through one spelling and reading through another, and by
// GetFileInformationByHandle's volume serial and file index agreeing for
// all three. Microsoft documents that the naming rules are the file
// system's, not Unicode's, and they differ one file system to the next.
// The same measurement settled the neighbors: NTFS keeps U+212A, the Kelvin
// sign, distinct from k; keeps U+0131, dotless i, distinct from i; keeps
// U+0130 distinct from both; keeps ß distinct from ss. The fold below
// agrees with all of that but one pair, and the one is on the safe side:
//
// What this fold still gets wrong, said plainly: it folds U+0131 to I, and
// NTFS does not -- measured, a directory can hold i.txt and ı.txt side by
// side. On the present list the join can only spare a stray from the
// mirroring, never take a live file for one, and the reserved tables err
// the same way. That was read too broadly once: the same fold carried the
// record's ownership key, and there the join let the record claim a place
// this machine never copied, whose next Clear took the sandbox's own file.
// The direction that deletes is a pair the file system equates that the
// fold holds apart, and none was found among the pairs measured -- but a
// deletion decided on a join the volume disagrees with is a deletion all
// the same, so the record's two deletion questions no longer go through
// any fold: sameEntryPlace answers them.
//
// "Per-volume" is not a figure of speech, and it cost a red build to learn.
// The table is built when a volume is formatted, from the Unicode version in
// use then, so it is not even one answer per machine. The measurements above
// are this desk's; a GitHub runner's volume holds the two sigmas apart and
// keeps Σ.json and ς.json side by side, which is the same disagreement in
// the other direction. The fold is right on both, because it errs only
// toward joining, and joining more than the volume does costs a spared stray
// rather than a file. What cannot be written down anywhere is a fixed list
// of which pairs are one name: TestTheFoldNeverHoldsApartWhatTheFileSystemJoins
// therefore asks the volume it is running on, and says in its log where the
// answer left it with nothing to check.
func foldedName(name string) string {
	return strings.ToUpper(name)
}

// FoldedEntryPath is the key under which two spellings of one profile path
// count as the same entry: cleaned the way within cleans, then folded the
// way foldedName folds a name -- the file system's own fold, Windows
// matching names case-insensitively -- and spelled with forward slashes,
// because the rules file and the record are free to spell the separator
// either way. The caller dedupes the record it writes down by it, the
// duplicate refusal and the preview's gone-set fold by it, and diagnose
// reports duplicate paths by it. forget and copyEntries once matched by it
// too, and do not any more: both decide deletions, and both ask the volume
// at sameEntryPlace instead. Measured, before the clean went in: a rules
// file respelling "agent" as "./agent" between runs made forget read the
// recorded entry as a name the list no longer held and delete the copy,
// and with the source gone -- a drive not mounted, a tool uninstalled --
// copyEntries could not put it back, and the run reported success.
//
// The clean is cleanEntryPath, the one within starts from, rather than a
// second copy of it: the key answers "where does this entry land", and two
// answers to that are how the key and the copier part ways again. The
// order is the order within uses -- FromSlash, then Clean on the native
// spelling, then ToSlash, then the fold. Clean is separator-aware, so
// cleaning a path already converted to slashes is not the operation
// cleaning the native spelling is. Exported for the same reason
// EntryEscapesProfile is: the record's dedupe in internal/cli/setup asks
// this package the question rather than keeping a second copy of the rule.
//
// within's refusals are deliberately not part of the key: a key has to
// answer for every spelling a record or a rules file can hold, and a path
// within refuses -- absolute, out of the profile, the root itself -- lands
// nowhere but still needs a stable spelling to be compared by. The
// refusals happen where the acting is: forget asks within about every
// recorded path it is about to clear, copyEntries about every entry it is
// about to copy, and validation asks EntryEscapesProfile, so a refused
// spelling is no more acted on for having a key.
func FoldedEntryPath(path string) string {
	return foldedName(filepath.ToSlash(cleanEntryPath(path)))
}

// sameEntryPlace answers whether two spellings of a profile entry name one
// and the same directory entry, and it is the ownership comparison: forget
// keeps a recorded entry by it and copyEntries vouches a missing source by it,
// and both decide deletions, which is why no fold answers here. The volume is
// asked for the stored spelling of every component. That joins i and I, but
// keeps two hard-link names apart: file identity is not the directory entry
// whose name Clear must remove.
//
// A spelling that opens nothing names no place, and no place is not
// another spelling's place: false, and deliberately not a guess. Which way
// that false cuts belongs to the caller -- forget falls back to the
// spellings themselves for a recorded entry whose place the disk cannot
// witness, because "does the list still name it" has to outlive the copy;
// the vouch does not fall back at all, because a claim about a copy has to
// be witnessed by the copy. The cost is one directory enumeration per path
// component, asked once per recorded entry per run, on lists the size of the
// rules file's.
func sameEntryPlace(root *os.Root, first, second string) bool {
	opened, ok := canonicalEntryPath(root, first)
	if !ok {
		return false
	}
	other, ok := canonicalEntryPath(root, second)
	return ok && opened == other
}

// canonicalEntryPath resolves the stored directory-entry spelling without
// collapsing hard links. A path within refuses -- absolute, or climbing out
// -- and a missing component has no witnessed place.
func canonicalEntryPath(root *os.Root, path string) (string, bool) {
	clean := cleanEntryPath(path)
	if clean == "." || filepath.IsAbs(clean) || clean == ".." ||
		strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", false
	}
	current := "."
	for _, component := range strings.Split(clean, string(filepath.Separator)) {
		dir, err := root.Open(current)
		if err != nil {
			return "", false
		}
		children, err := dir.ReadDir(-1)
		_ = dir.Close()
		if err != nil {
			return "", false
		}
		chosen := ""
		for _, child := range children {
			if child.Name() == component {
				chosen = child.Name()
				break
			}
		}
		if chosen == "" {
			// Go's Unicode fold is only a candidate. NTFS has a
			// per-volume table, so open the spelling itself before
			// accepting a case-insensitive directory entry.
			opened, err := root.Open(filepath.Join(current, component))
			if err != nil {
				return "", false
			}
			openedInfo, err := opened.Stat()
			_ = opened.Close()
			if err != nil {
				return "", false
			}
			for _, child := range children {
				childFile, err := root.Open(filepath.Join(current, child.Name()))
				if err != nil {
					continue
				}
				childInfo, childErr := childFile.Stat()
				_ = childFile.Close()
				if childErr == nil && os.SameFile(openedInfo, childInfo) {
					chosen = child.Name()
					break
				}
			}
		}
		if chosen == "" {
			return "", false
		}
		current = filepath.Join(current, chosen)
	}
	return current, true
}
