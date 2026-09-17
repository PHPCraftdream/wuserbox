package profile

import (
	"path/filepath"
	"strings"
)

// The two folds of this package, kept in one file because they are one
// question: under what form do two spellings of a name count as the same
// name? The answer has to be the file system's, because the spellings come
// off disk -- a directory entry read here, an entry path a rules file
// spelled there -- and Windows opens any capitals onto the one file. What
// was measured to settle it is written at foldedName, which both call.
//
// FoldedEntryPath is exported and foldedName is not: the record and the
// rules file are compared outside this package too, and two answers to "is
// this the same entry" -- one here, one in the caller -- are how a path
// comes to be copied twice or cleared twice.

// foldedName is the form one child's name is carried in on the present
// list, and the one fold every comparison of two spellings of a name in
// this package goes through: the file system's, not Unicode's lowercase.
//
// The list is written from the source's directory entries and read against
// the destination's, and Windows opens either spelling onto the same file --
// a copy over AUTH.JSON lands in the file the source calls auth.json and
// the entry keeps the capitals it had -- so a map keyed by the bytes of one
// spelling reads the other as a stranger and removeStrayChildren takes what
// the run just put there. matchMask folds its own two sides, which is why
// the mask questions asked beside this one need no help; a map lookup is
// not a mask match, and the fold has to happen before the key goes in. It
// is a comparison key and nothing else: the paths handed to the root keep
// the spelling they were read with.
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
// side. Collapsing two names the file system holds apart into one
// present-list key can only spare a stray from the mirroring, never take a
// live file for one; the direction that deletes is a pair the file system
// equates that the fold holds apart, and none was found among the pairs
// measured.
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
// either way. forget matches what it keeps by it, copyEntries matches a
// missing source against the record by it, and the caller dedupes the
// record it writes down by it. Measured, before the clean went in: a rules
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
