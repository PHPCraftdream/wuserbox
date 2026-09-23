package profile

import (
	"os"
	"path/filepath"
)

// placeResult is one spelling's canonical answer. Negative and alias-based
// answers carry the generation of the directory listing they depended on,
// so a mirror can invalidate them without walking every cached spelling.
type placeResult struct {
	canonical string
	ok        bool
	// unknown records that the question about this spelling did not
	// finish: an open or a ReadDir failed for a reason that is not the
	// volume's own nothing. It is never to be read as !ok's usual
	// absence, and err carries the failure for the message of the
	// caller that has to stop on it.
	unknown   bool
	err       error
	directory string
	version   uint64
}

// dirSnapshot is one directory's children as this operation first read
// them. Every walk after the first through the same directory reads this
// list rather than opening the directory and enumerating it again.
//
// byName is that list as a map, so a component's exact-spelling question
// is one lookup instead of a scan over every child for every question. A
// directory's exact names are unique, so the map cannot answer differently
// than the scan did -- it only stops the scan from being repeated.
//
// canonical holds, per child name, the pathid.Canonical answer the alias
// branch computed for it. That branch's scan opens every sibling and asks
// the volume for its canonical spelling, and those answers cannot go stale
// while the resolver lives -- nothing under the root moves -- so the first
// scan in a directory fills this in and every later scan in the same
// directory, this query or a later one, reads it instead of re-opening the
// siblings one by one. Only successful answers are kept: a sibling that
// would not open or canonicalize is asked again next time, exactly as the
// scan without the cache would have asked.
//
// byCanonical is the same scan's other product, indexed the way the next
// alias question asks: per canonical path, the one stored directory-entry
// name that carries it. The scan walks every child whether the asking
// spelling's match is the first child or the last, so the index falls out
// of it for nothing -- and it is what keeps a directory's second alias
// spelling, one the alias memo has never heard of because no earlier
// question spelled it that way, from opening the siblings all over again.
// A canonical path two names carry -- hard links -- is kept marked not
// unique and refused, exactly as the scan's own matches != 1 refused.
// The index is rebuilt from the snapshot's canonical answers after every
// scan rather than extended across them, so re-walking children an
// earlier partial scan already answered cannot mark them ambiguous: only
// a second stored name carrying one canonical path does that. Like
// canonical, it keeps what the scan managed: a sibling the scan could not
// canonicalize has no entry here, and the next alias question about that
// spelling asks the volume again.
//
// retract's point update is the one hand that amends these books after
// the fact: the taken child's rows leave byName, canonical and
// byCanonical, and what stays is what the volume still holds.
type dirSnapshot struct {
	children          []os.DirEntry
	byName            map[string]string
	canonical         map[string]string
	byCanonical       map[string]canonicalChild
	canonicalNames    map[string]map[string]bool
	canonicalComplete bool
	ok                bool
	// unknown and err are the shut directory's reason. The volume's own
	// nothing leaves unknown false -- an honest answer that the directory
	// is not there -- while every other failure sets unknown and keeps its
	// cause, so a retention decision downstream cannot read the failure
	// as absence.
	unknown bool
	err     error
}

// canonicalChild is one canonical path's answer in the snapshot's
// byCanonical index: the single stored directory-entry name that has it,
// or unique=false when two names do (hard links), which the alias branch
// refuses exactly as the scan's matches != 1 did.
type canonicalChild struct {
	name   string
	unique bool
}

// placeResolver answers the ownership question for one operation, and it
// is what keeps the answering from growing with the square of the entries
// compared. The review of 2026-09-20 (P2-5) measured the shape: resolving
// one spelling meant opening and ReadDir-ing every component's directory,
// so comparing E entries against each other re-read the same D directories
// and their B children once per comparison, and an already-copied profile
// whose bytes had not changed paid the bill on every copy. A resolver
// holds one snapshot of each directory it has read and one canonical
// answer per cleaned spelling, so a comparison after the first reads
// indexes instead of asking the volume -- each directory once per
// operation, each entry once.
//
// DedupeEntries shares one resolver across read-only comparisons. forget
// retracts answers changed by its clears; copyEntries updates the affected
// path subtree and advances the changed directory's generation after each
// structural mirror. Both keep unrelated answers and discard all state at
// the end of the operation.
//
// opens, reads, resolutions, children, scans and visits are the measurement
// the review's close tests hold the resolver to: every open of a directory
// made to enumerate it, every ReadDir, every spelling resolved that the
// places memo had not already answered, the number of children those
// ReadDirs actually processed, and the sibling scans the alias branch ran
// that its byCanonical index did not save, with visits the book entries a
// retraction pulled. The last four are the counters the earlier review's
// opens and reads could not stand in for -- a warm pass can look linear by
// those and still pay per pair -- and they are what pins the stretch shape.
// The alias branch's opens of stored spellings are resolution, not
// enumeration, and are not counted. The numbers are read, never used to
// decide.
type placeResolver struct {
	root       *os.Root
	dirs       map[string]dirSnapshot
	places     map[string]placeResult
	dirVersion map[string]uint64
	// alias remembers the alias branch's whole answer, keyed by the joined
	// path the branch opens. The branch is the one place a walk can cost
	// more than a lookup -- the spelling opened, then every sibling opened
	// and canonicalized to count the matches -- and the original paid that
	// again for every question about the same spelling. Each answer carries
	// the generation of the directory it depended on; a mirror advances that
	// generation, so stale positive and negative alias answers are retried.
	// The branch's opens are resolution, not enumeration, and stay uncounted.
	alias map[string]placeResult
	// The reverse books, retract's index into the three above: which
	// snapshot keys and witnessed canonical places -- leaf or directory
	// alike -- hang beneath which, which spellings' witnessed answers
	// name which canonical place, which alias answers were asked in
	// which directory. The scanned loops a retraction once walked --
	// every book, every real clear -- are answered out of these instead:
	// the retraction pulls the entries the books hand it, the taken
	// place's own and everything registered beneath it, and never sees
	// the rest. Every key in them is a walk product, one namespace of
	// stored names, so ancestry is recorded exactly and no fold is
	// needed to read it.
	dirChildren      map[string]map[string]bool
	placeAt          map[string]map[string]bool
	aliasIn          map[string]map[string]bool
	lastDependentDir string
	opens            int
	reads            int
	// resolutions, children, scans and visits are the stretch-shaped
	// counters the opens and reads above could not answer: how many
	// spellings were really walked rather than answered from the places
	// memo, how many directory children the enumerations processed, how
	// often the alias branch paid its sibling scan instead of reading the
	// snapshot's byCanonical index, and visits the book entries a
	// retraction pulled out of the reverse books. Like the others they
	// are read by the counting tests and used to decide nothing.
	resolutions int
	children    int
	scans       int
	// visits is the retraction-shaped counter beside scans: the book
	// entries one retraction pulled -- snapshot keys, witnessed
	// spellings, alias answers -- where the scanned loops it replaced
	// examined every entry of every book on every real clear. Like the
	// others it is read by the counting tests and used to decide
	// nothing.
	visits int
}

// newPlaceResolver is a variable so the counting test can hold the
// resolvers an operation builds without the production path knowing it is
// measured.
var newPlaceResolver = defaultPlaceResolver

func defaultPlaceResolver(root *os.Root) *placeResolver {
	return &placeResolver{
		root:        root,
		dirs:        make(map[string]dirSnapshot),
		places:      make(map[string]placeResult),
		dirVersion:  make(map[string]uint64),
		alias:       make(map[string]placeResult),
		dirChildren: make(map[string]map[string]bool),
		placeAt:     make(map[string]map[string]bool),
		aliasIn:     make(map[string]map[string]bool),
	}
}

// place resolves one spelling's canonical directory-entry path once per
// cleaned spelling: "one" and "./one" clean to the same key, and the
// second spelling is answered from the first's walk.
//
// The answer is one of three, not two: a witnessed place, the volume's own
// nothing, or a question that did not finish -- unknown, with err carrying
// why. ok is true only for the witnessed place, and a caller whose next
// step keeps or retires a recorded entry asks the question rather than
// reading !ok as absence.
func (r *placeResolver) place(path string) placeResult {
	key := cleanEntryPath(path)
	if got, ok := r.places[key]; ok {
		if got.directory == "" || got.version == r.dirVersion[got.directory] {
			return got
		}
		if got.ok {
			named := r.placeAt[got.canonical]
			delete(named, key)
			if len(named) == 0 {
				delete(r.placeAt, got.canonical)
			}
		}
		delete(r.places, key)
	}
	r.resolutions++
	r.lastDependentDir = ""
	result := r.canonicalEntryPath(path)
	if r.lastDependentDir != "" {
		result.directory = r.lastDependentDir
		result.version = r.dirVersion[r.lastDependentDir]
	}
	r.places[key] = result
	if result.ok {
		r.notePlace(key, result.canonical)
	}
	return result
}

// notePlace files a witnessed spelling under the canonical place its
// answer named, so a retraction can take back exactly the answers that
// named the taken place or something beneath it. Misses are not filed: a
// deletion never makes a name the volume once did not have, so a
// not-found answer keeps its truth through any clear.
//
// It also files the canonical place itself into dirChildren, beneath its
// parent -- registerChild, the same filing noteDir does for a snapshot.
// A leaf entry is never opened as a directory, so without this its
// canonical path never becomes a dirChildren key or value at all, and a
// retraction of an ancestor directory -- whose subtree walk only follows
// dirChildren -- never reaches it: the leaf's witnessed resolution
// outlives the clear that removed it. Filing it here, off of every
// resolved place and not only the ones a ReadDir touched, is what makes
// the subtree walk find it.
func (r *placeResolver) notePlace(spelling, canonical string) {
	named := r.placeAt[canonical]
	if named == nil {
		named = make(map[string]bool)
		r.placeAt[canonical] = named
	}
	named[spelling] = true
	r.registerChild(canonical)
}

// registerChild files key beneath its parent's list in dirChildren, the
// filing noteDir and notePlace both need: a snapshot key from the one,
// a witnessed canonical place -- leaf or directory -- from the other.
func (r *placeResolver) registerChild(key string) {
	above := filepath.Dir(key)
	below := r.dirChildren[above]
	if below == nil {
		below = make(map[string]bool)
		r.dirChildren[above] = below
	}
	below[key] = true
}

// samePlace is the comparison sameEntryPlace puts to a fresh resolver, and
// it reads the same way: false the moment either spelling names no place.
func (r *placeResolver) samePlace(first, second string) bool {
	opened := r.place(first)
	if !opened.ok {
		return false
	}
	other := r.place(second)
	return other.ok && opened.canonical == other.canonical
}

// snapshot returns one directory's snapshot, read once until a mirror or
// clear updates that directory's resolver state. The bool is whether the
// listing was enumerated; a directory this operation could not enumerate
// comes back shut, carrying unknown and its cause where the failure is
// not the volume's own nothing.
func (r *placeResolver) snapshot(dir string) (dirSnapshot, bool) {
	if snap, ok := r.dirs[dir]; ok {
		return snap, snap.ok
	}
	r.opens++
	file, err := r.root.Open(dir)
	if err != nil {
		return r.noteShut(dir, err), false
	}
	r.reads++
	children, err := file.ReadDir(-1)
	_ = file.Close()
	if err != nil {
		return r.noteShut(dir, err), false
	}
	byName := make(map[string]string, len(children))
	for _, child := range children {
		byName[child.Name()] = child.Name()
	}
	snap := dirSnapshot{
		children:       children,
		byName:         byName,
		canonical:      make(map[string]string),
		byCanonical:    make(map[string]canonicalChild),
		canonicalNames: make(map[string]map[string]bool),
		ok:             true,
	}
	r.dirs[dir] = snap
	r.noteDir(dir)
	r.children += len(children)
	return snap, true
}

// noteShut caches a directory this operation could not enumerate, and
// it keeps the distinction the round-11 review drew through the
// answer: the volume's own nothing is an honest absence, while any
// other failure -- a lock another program holds, a read that stopped
// part way -- is no answer at all, cached with its cause so nothing
// downstream reads it as the directory not being there.
func (r *placeResolver) noteShut(dir string, err error) dirSnapshot {
	snap := dirSnapshot{}
	if !os.IsNotExist(err) {
		snap.unknown = true
		snap.err = err
	}
	r.dirs[dir] = snap
	r.noteDir(dir)
	return snap
}

// noteDir files a snapshot key beneath its parent's in the reverse book,
// so a retraction can walk the keys beneath a taken place without
// scanning the snapshot table. Every key the resolver snapshots is
// filed, the shut ones included: they stand or fall with the rest.
func (r *placeResolver) noteDir(dir string) {
	r.registerChild(dir)
}

// unlinkChild takes one dirChildren key back out of the books: its seat
// beneath its own parent key, and its own now-empty child list. dropDir
// calls it for a taken snapshot; retract calls it directly for a taken
// terminal place, which owns no snapshot to drop but was filed by
// notePlace the same way.
func (r *placeResolver) unlinkChild(key string) {
	if above := r.dirChildren[filepath.Dir(key)]; above != nil {
		delete(above, key)
		if len(above) == 0 {
			delete(r.dirChildren, filepath.Dir(key))
		}
	}
	if below := r.dirChildren[key]; len(below) == 0 {
		delete(r.dirChildren, key)
	}
}

// dropDir takes one snapshot key back out of the books: the snapshot
// itself, the alias answers filed in it, and its seat beneath its own
// parent key. Its registered children are left to the caller -- retract
// walks the taken place's subtree and drops each key in turn, each
// unfiles itself here on the way out, deepest first.
func (r *placeResolver) dropDir(dir string) {
	r.visits++
	delete(r.dirs, dir)
	for opened := range r.aliasIn[dir] {
		delete(r.alias, opened)
		r.visits++
	}
	delete(r.aliasIn, dir)
	r.unlinkChild(dir)
}

// noteAlias files the alias branch's answer under the directory its walk
// stood in -- the walked key the joined path the branch opened hangs
// from -- so a retraction can take back every answer asked in the
// directory that held the taken place, and in everything beneath it,
// without reading the alias book whole.
func (r *placeResolver) noteAlias(dir, opened string, answer placeResult) {
	answer.directory = dir
	answer.version = r.dirVersion[dir]
	r.alias[opened] = answer
	asked := r.aliasIn[dir]
	if asked == nil {
		asked = make(map[string]bool)
		r.aliasIn[dir] = asked
	}
	asked[opened] = true
}
