package profile

import (
	"os"
	"path/filepath"
	"strings"
)

// The registry the profile service builds into every sandbox's profile --
// NTUSER.DAT and its transaction family at the root, UsrClass.dat and its
// own family under AppData -- is Windows' work and the sandbox's life. The
// families that describe it are built once in families.go, and the two
// questions asked of them live apart: refuseReservedCleanup's, which has
// read the description longest, and this file's -- the name question the
// old exact-name tables only half carried.
//
// A cleanup: glob naming a reserved path is refused outright, because a glob
// that says NTUSER.DAT is someone asking for the hive and cannot be granted
// it. Everywhere else the rule is to spare, not to refuse, because the asks
// are different in kind: an entry over AppData -- bare, or with an include
// list that never names the hive -- is asking for something that can be
// granted, everything around one file that cannot, and refusing the run
// would hold the user's whole settings copy hostage to a file the rules
// file never named. Refused, the user edits the glob; spared, the user
// never has to know. The doors this closes, all found by test rather than
// by reading alone:
//
//   - the mirroring: an include list that leaves UsrClass.dat off the
//     present list makes removeStrayChildren read it as a stray and take
//     it, reporting success;
//   - the same walk, shallower: a source that has lost its Windows
//     directory leaves the destination's a stray directory, and a bare
//     entry's RemoveAll takes it whole;
//   - the take-back: forget's bare-entry RemoveAll pulls AppData up by the
//     roots when the list stops naming it, hive and all, and clearKeeping's
//     walk deletes whatever its entry's limits would have copied -- which
//     any depth past four includes the hive under AppData;
//   - a record naming a reserved path outright, which clearEntry would
//     honor to the letter;
//   - the copying itself: an entry over AppData with no include list walks
//     the user's real profile, whose UsrClass.dat is the user's own class
//     hive, and lays it over the empty one the profile service built the
//     sandbox -- handing a sandbox the user's registry.
//
// What the run says about a spared path is nothing, and that is a decision,
// not an oversight. Copy's only voices are its returned record, its error,
// and Plan; a spared file is not an error, and the guard below sits in the
// walk above the sinks precisely so Plan -- which counts through the same
// walk -- reports the spared file the same way the run spares it, making a
// --dry-run show a profile one file short of the mirror rather than a
// description the run would contradict. A warnings channel would give the
// run a sentence about it; it would also reach for signatures outside this
// package, and its absence is the named cost of this choice, recorded here
// rather than buried.
//
// The trap this file exists to keep straight: the paths in the reserved
// families are relative to the profile ROOT, and the walks' rel is relative
// to the ENTRY. Under an entry over AppData the hive's entry-relative path
// is Local/Microsoft/Windows/UsrClass.dat, and a guard that compared that
// against the table would silently protect nothing -- worse than no guard,
// because it reads as one. Every question below is therefore asked of a
// path rebuilt relative to the root, spelled with forward slashes the way
// the families are, and folded the way foldedName folds a name -- the file
// system's answer for any capitals -- so a hive planted or spelled under
// other capitals is still the hive.

// reservedAt answers whether one path, relative to the profile root and
// spelled with forward slashes, names a member of a reserved family. The
// comparison goes through foldedName, not bytes: a rules file or a
// directory entry may spell the hive in any capitals, and Windows opens
// them all onto it. And it goes through the shapes, not a list of names:
// the transaction files carry a GUID and a counter that differ machine to
// machine and run to run, and the TxR files an index that grows, so the
// family -- not one example of it -- is what is matched. That is the
// sentence the old table comment got wrong: a representative name stood
// in for the glob question, where the argument held, and was read as this
// question's answer, where it never did.
func reservedAt(rootRel string) bool {
	folded := foldedName(rootRel)
	for _, fam := range reservedFamilies {
		if fam.matches(folded) {
			return true
		}
	}
	return false
}

// reservedWithin adds to reservedAt the directories the reserved files sit
// under: removing such a directory whole is the same destruction with one
// name fewer, the lesson refuseReservedCleanup already drew about cleanup
// globs naming an ancestor. A family sits in one fixed directory, so the
// directories are that directory and its ancestors; the root families'
// bare names have none, and no prefix test can fire on them. The question
// is asked in one direction only, what this deletion takes with it -- the
// reserved paths are files, and a file has nothing under it.
func reservedWithin(rootRel string) bool {
	if reservedAt(rootRel) {
		return true
	}
	folded := foldedName(rootRel)
	for _, fam := range reservedFamilies {
		if fam.dir != "" && (fam.dir == folded || strings.HasPrefix(fam.dir, folded+"/")) {
			return true
		}
	}
	return false
}

// clearKeepingReserved removes from one directory what a deletion that must
// spare the registry may still take: every child the reserved tables do not
// name, links removed as the links they are -- the same defensive Lstat
// cleanDir and clearKeeping make, the root refusing to follow one that
// leads out of the profile -- directories kept only while they are the way
// to something spared, and an emptied frame taken down with its children.
// It answers through spared whether anything was left standing, the shape
// clearKeeping reports kept in, so a caller that must not go on to a
// RemoveAll over the hive can ask rather than guess.
func clearKeepingReserved(root *os.Root, dir string) (spared bool, err error) {
	d, err := root.Open(dir)
	if err != nil {
		// The tree may already be gone; that is an answer, not a failure.
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	children, err := d.ReadDir(-1)
	_ = d.Close()
	if err != nil {
		return false, err
	}
	for _, child := range children {
		childPath := filepath.Join(dir, child.Name())
		if reservedAt(filepath.ToSlash(childPath)) {
			spared = true
			continue
		}
		if info, readable := lookAt(root, childPath); readable &&
			info.IsDir() && info.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0 {
			under, err := clearKeepingReserved(root, childPath)
			if err != nil {
				return spared, err
			}
			spared = spared || under
			if under {
				continue
			}
		}
		if err := root.Remove(childPath); err != nil && !os.IsNotExist(err) {
			return spared, err
		}
	}
	return spared, nil
}
