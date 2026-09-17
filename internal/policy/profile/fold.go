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
// and the same place under the profile root, and it is the ownership
// comparison: forget keeps a recorded entry by it and copyEntries vouches
// a missing source by it, and both decide deletions, which is why no fold
// answers here. The question goes to the volume instead of to a spelling:
// both sides are opened through the root -- which resolves each component
// the way the file system does, so i and I open the one directory -- and
// os.SameFile compares the two handles by volume serial and file index,
// the answer GetFileInformationByHandle gives. Measured on this desk's
// NTFS: i and I open one directory and SameFile says so; i and U+0131 open
// two and SameFile holds them apart, where foldedName joins them.
//
// A spelling that opens nothing names no place, and no place is not
// another spelling's place: false, and deliberately not a guess. Which way
// that false cuts belongs to the caller -- forget falls back to the
// spellings themselves for a recorded entry whose place the disk cannot
// witness, because "does the list still name it" has to outlive the copy;
// the vouch does not fall back at all, because a claim about a copy has to
// be witnessed by the copy. The cost is two opens per question, asked once
// per recorded entry per run, on lists the size of the rules file's.
func sameEntryPlace(root *os.Root, first, second string) bool {
	opened, ok := entryPlace(root, first)
	if !ok {
		return false
	}
	other, ok := entryPlace(root, second)
	return ok && os.SameFile(opened, other)
}

// entryPlace opens one entry spelling through the root and hands back the
// handle's stat, whose volume serial and file index are what os.SameFile
// reads. A path within refuses -- absolute, or climbing out -- opens
// nothing, which is the right answer for a key that is only ever asked
// about spellings forget and copyEntries are about to act inside.
func entryPlace(root *os.Root, path string) (os.FileInfo, bool) {
	f, err := root.Open(cleanEntryPath(path))
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, false
	}
	return info, true
}
