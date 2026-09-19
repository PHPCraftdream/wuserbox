package profile

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/win/pathid"
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

// stripsTrailingPad reports whether a Win32 name-spelling loses characters
// before the volume looks: trailing dots and spaces are stripped per segment
// by Win32 path normalization (GetFullPathName), both when the volume resolves
// the name and when it creates it -- measured, os.WriteFile spells "made.DAT."
// and the directory entry reads "made.DAT". A segment this true of is never
// the name the volume stores, so a rules file or a record carrying it is
// naming something else under its own spelling.
func stripsTrailingPad(segment string) bool {
	return segment != strings.TrimRight(segment, ". ")
}

// looksLikeShortName reports whether a segment is spelled the way Windows
// spells an 8.3 alias: a base that ends in a tilde and a run of digits, with
// an extension no longer than the three characters an alias keeps ("NTUSER~1",
// "NTUSER~1.BLF"). The alias itself is the volume's work -- assigned to long
// names too long for 8.3, resolved by the volume wherever the long name was
// meant -- and never appears in a directory enumeration, which reports stored
// long names only. A hand-written spelling shaped like one is either a file
// with an unlucky literal name or an alias for something else, and only the
// volume can say which.
func looksLikeShortName(segment string) bool {
	base := segment
	if i := strings.LastIndexByte(segment, '.'); i >= 0 {
		if len(segment)-i-1 > 3 {
			return false
		}
		base = segment[:i]
	}
	i := strings.LastIndexByte(base, '~')
	if i < 0 || i+1 == len(base) {
		return false
	}
	for _, c := range base[i+1:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// resolvedRootRel answers with the path the volume actually resolved rootRel
// to, relative to the profile root and spelled with forward slashes -- the
// frame the reserved tables are written in. It opens the name through the
// root (which refuses a reparse point leading out of the profile) and asks
// GetFinalPathNameByHandle -- pathid.Canonical -- for the final path, the
// same question canonicalEntryPath asks one component at a time. A name that
// opens nothing is not another name for something: false, and the caller
// falls back to the spelling as written. A nil root is the same answer: a
// preview asked about a sandbox that does not exist yet has nothing to
// open, so there is nothing to resolve and the as-written question stands.
func resolvedRootRel(root *os.Root, rootRel string) (string, bool) {
	if root == nil {
		// A preview asked about a sandbox that does not exist yet has
		// nothing to open -- planSink's own contract, the same answer
		// from the other side. Nothing resolves, and the as-written
		// question stands.
		return "", false
	}
	f, err := root.Open(rootRel)
	if err != nil {
		return "", false
	}
	full, err := pathid.Canonical(f.Name())
	_ = f.Close()
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(root.Name(), full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		// root.Name() and the resolved spelling can disagree about the
		// case of the directories between them; a relative path that
		// climbs says the two could not be lined up lexically, and the
		// as-written question stands.
		return "", false
	}
	return filepath.ToSlash(rel), true
}

// leafSuspicious answers whether a root-relative path's own name is one the
// volume may resolve under a different spelling: trailing dots or spaces
// Win32 strips, or a shape an 8.3 alias carries. It is the gate on the
// resolved questions below -- a spelling that names itself exactly never
// resolves to anything else (the fold already answers for case), so the
// walks pay for an open and a final-path question only where the spelling
// itself says the volume may know better.
func leafSuspicious(rootRel string) bool {
	segment := rootRel
	if i := strings.LastIndexByte(rootRel, '/'); i >= 0 {
		segment = rootRel[i+1:]
	}
	return stripsTrailingPad(segment) || looksLikeShortName(segment)
}

// reservedAtResolved adds to reservedAt the answer for what the name the
// volume resolves it to is called: "NTUSER.DAT." and "NTUSER.DAT " open the
// hive "NTUSER.DAT" names, and a family member's 8.3 alias -- NTUSER~1.BLF
// beside a real .TM.blf, measured -- opens the member. Measured with a plain
// Open through an os.Root: the handle's final path is the plain spelling's,
// file identity and all. The as-written question is asked first, as it always
// was; only a leaf the spelling itself marks suspicious pays for the
// resolution. Unresolvable is not reserved: a name that opens nothing is
// spared or taken exactly as the tables read it.
func reservedAtResolved(root *os.Root, rootRel string) bool {
	if reservedAt(rootRel) {
		return true
	}
	if !leafSuspicious(rootRel) {
		return false
	}
	resolved, ok := resolvedRootRel(root, rootRel)
	return ok && reservedAt(resolved)
}

// reservedWithinResolved is reservedWithin's resolved twin, asked where a
// deletion would take a directory whole: a directory the record or the
// cleanup reaches under an alias spelling takes the reserved files under its
// resolved name with it, which is the same destruction with one alias more.
func reservedWithinResolved(root *os.Root, rootRel string) bool {
	if reservedWithin(rootRel) {
		return true
	}
	if !leafSuspicious(rootRel) {
		return false
	}
	resolved, ok := resolvedRootRel(root, rootRel)
	return ok && reservedWithin(resolved)
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
		// The as-written question is asked first; a child spelling the
		// volume improves on -- a trailing dot, a short alias -- is then
		// asked again of what the name resolves to, because a child name
		// the volume resolves onto a reserved file is spared by the file
		// it reaches, not the one it spells.
		if reservedAtResolved(root, filepath.ToSlash(childPath)) {
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
