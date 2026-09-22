package profile

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
	"github.com/PHPCraftdream/wuserbox/internal/win/pathid"
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
// keeps two hard-link names apart: their canonical paths remain different
// even though file identity is shared, and the directory entry is what Clear
// must remove.
//
// A spelling that opens nothing names no place, and no place is not
// another spelling's place: false, and deliberately not a guess. Which way
// that false cuts belongs to the caller -- forget falls back to the
// spellings themselves for a recorded entry whose place the disk cannot
// witness, because "does the list still name it" has to outlive the copy;
// the vouch does not fall back at all, because a claim about a copy has to
// be witnessed by the copy.
//
// The question is put to the volume through a placeResolver built for this
// one comparison, so the two spellings share a single look at every
// directory they touch: the second spelling is answered from what the
// first already read. sameEntryPlace stays the one-comparison convenience,
// the shape a caller with a single comparison to ask keeps; the callers
// with a whole loop of comparisons to ask -- forget over its recorded
// entries, copyEntries over its missing sources -- hold one placeIndex
// across each mutation-free stretch of the loop instead of a resolver per
// question, and the stretch still answers for what happens inside the
// loop: copyEntries ends its stretch at the mirror that made, took or
// replaced a name, and forget's clears retract the answers the cleared
// place and the directory that held it carried -- an answer kept across a
// change the operation itself made is the lie the stretch exists never to
// tell.
func sameEntryPlace(root *os.Root, first, second string) bool {
	return newPlaceResolver(root).samePlace(first, second)
}

// placeResult is one spelling's canonical answer, kept by a placeResolver
// so the same place asked about twice is walked once. A spelling that
// resolved to nothing keeps that answer too: within the stretch one
// resolver covers, nothing under the root moves, so a place that was
// missing stays missing and asking the volume again could only return the
// same nothing.
type placeResult struct {
	canonical string
	ok        bool
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
type dirSnapshot struct {
	children    []os.DirEntry
	byName      map[string]string
	canonical   map[string]string
	byCanonical map[string]canonicalChild
	ok          bool
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
// "One operation" is as long as the resolver lives, and that is a promise
// about mutation, not about time: a holder spans a mutation-free stretch
// of its caller's loop and never spans the mutation that ends it. A
// DedupeEntries call compares and writes nothing, so one resolver spans
// all of its comparisons; forget and copyEntries hold one across each
// mutation-bearing stretch of their loops -- forget over every recorded
// entry it compares against one unchanged current list, copyEntries over
// every missing source it vouches against one unchanged record.
// copyEntries throws the resolver and the presence index it serves away
// the moment its mirror makes, takes or replaces a name, building the
// next stretch's only when a question needs it; forget's clears used to
// end the stretch the same way, which made a pass that takes half the
// record back re-index the surviving half once per clear, and now retract
// the answers each clear made false instead -- the taken place's snapshot
// and every snapshot beneath it, its spellings' witnessed resolutions,
// the alias book's say in the directory that held it -- and keep the
// rest, so the stretch outlives its clears. A rewrite
// of the bytes of a file that already stood, and a clear that found
// nothing to take back, are not mutations in this sense: they change no
// name any cached answer describes, and the stretch outlives them, which
// is what keeps a mixed warm run -- missing sources between unchanged
// present ones -- linear. What
// no resolver may do is outlive the run that built it: the volume answers
// for the moment of asking, and a cache carried across CLI runs would
// answer a later question with an earlier disk.
//
// opens, reads, resolutions, children and scans are the measurement the
// review's close tests hold the resolver to: every open of a directory
// made to enumerate it, every ReadDir, every spelling resolved that the
// places memo had not already answered, the number of children those
// ReadDirs actually processed, and the sibling scans the alias branch ran
// that its byCanonical index did not save. The last three are the counters
// the earlier review's opens and reads could not stand in for -- a warm
// pass can look linear by those and still pay per pair -- and they are
// what pins the stretch shape. The alias branch's opens of stored
// spellings are resolution, not enumeration, and are not counted. The
// numbers are read, never used to decide.
type placeResolver struct {
	root   *os.Root
	dirs   map[string]dirSnapshot
	places map[string]placeResult
	// alias remembers the alias branch's whole answer, keyed by the joined
	// path the branch opens. The branch is the one place a walk can cost
	// more than a lookup -- the spelling opened, then every sibling opened
	// and canonicalized to count the matches -- and the original paid that
	// again for every question about the same spelling. The promise places
	// and dirs are kept under covers this answer too, a miss included:
	// nothing under the root moves while the resolver lives, so asking the
	// volume again could only make it repeat itself. The branch's opens are
	// resolution, not enumeration, and stay uncounted.
	alias map[string]placeResult
	opens int
	reads int
	// resolutions, children and scans are the stretch-shaped counters the
	// opens and reads above could not answer: how many spellings were
	// really walked rather than answered from the places memo, how many
	// directory children the enumerations processed, and how often the
	// alias branch paid its sibling scan instead of reading the snapshot's
	// byCanonical index. Like the two above they are read by the counting
	// tests and used to decide nothing.
	resolutions int
	children    int
	scans       int
}

// newPlaceResolver is a variable so the counting test can hold the
// resolvers an operation builds without the production path knowing it is
// measured.
var newPlaceResolver = defaultPlaceResolver

func defaultPlaceResolver(root *os.Root) *placeResolver {
	return &placeResolver{
		root:   root,
		dirs:   make(map[string]dirSnapshot),
		places: make(map[string]placeResult),
		alias:  make(map[string]placeResult),
	}
}

// place resolves one spelling's canonical directory-entry path once per
// cleaned spelling: "one" and "./one" clean to the same key, and the
// second spelling is answered from the first's walk.
func (r *placeResolver) place(path string) (string, bool) {
	key := cleanEntryPath(path)
	if got, ok := r.places[key]; ok {
		return got.canonical, got.ok
	}
	r.resolutions++
	canonical, ok := r.canonicalEntryPath(path)
	r.places[key] = placeResult{canonical: canonical, ok: ok}
	return canonical, ok
}

// samePlace is the comparison sameEntryPlace puts to a fresh resolver, and
// it reads the same way: false the moment either spelling names no place.
func (r *placeResolver) samePlace(first, second string) bool {
	opened, ok := r.place(first)
	if !ok {
		return false
	}
	other, ok := r.place(second)
	return ok && opened == other
}

// snapshot returns one directory's snapshot, read from the volume once per
// resolver. A directory that would not open is remembered shut for the
// same stretch -- nothing under the root moves while the resolver lives,
// so the second question would only be refused again.
func (r *placeResolver) snapshot(dir string) (dirSnapshot, bool) {
	if snap, ok := r.dirs[dir]; ok {
		return snap, snap.ok
	}
	r.opens++
	file, err := r.root.Open(dir)
	if err != nil {
		r.dirs[dir] = dirSnapshot{}
		return dirSnapshot{}, false
	}
	r.reads++
	children, err := file.ReadDir(-1)
	_ = file.Close()
	if err != nil {
		r.dirs[dir] = dirSnapshot{}
		return dirSnapshot{}, false
	}
	byName := make(map[string]string, len(children))
	for _, child := range children {
		byName[child.Name()] = child.Name()
	}
	snap := dirSnapshot{
		children:    children,
		byName:      byName,
		canonical:   make(map[string]string),
		byCanonical: make(map[string]canonicalChild),
		ok:          true,
	}
	r.dirs[dir] = snap
	r.children += len(children)
	return snap, true
}

// canonicalEntryPath resolves the stored directory-entry spelling without
// collapsing hard links. A path within refuses -- absolute, or climbing out
// -- and a missing component has no witnessed place. The walk reads each
// directory from the resolver's snapshot; the one opening left in an exact
// match's absence is the alias branch below, where the volume itself has
// to say which stored spelling a name resolves onto. That branch's whole
// answer is kept in the resolver's alias memo and its siblings' canonical
// spellings in the snapshot, and the snapshot's byCanonical index holds
// the same scan's answers for every other spelling of the same place, so
// a second question about one spelling -- or a first question about a
// different spelling of it -- in a directory this resolver has already
// scanned opens nothing at all.
func (r *placeResolver) canonicalEntryPath(path string) (string, bool) {
	clean := cleanEntryPath(path)
	if clean == "." || filepath.IsAbs(clean) || clean == ".." ||
		strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", false
	}
	current := "."
	for _, component := range strings.Split(clean, string(filepath.Separator)) {
		snap, ok := r.snapshot(current)
		if !ok {
			return "", false
		}
		chosen := snap.byName[component]
		if chosen == "" {
			// Go's Unicode fold is only a candidate. NTFS has a
			// per-volume table, so open the spelling itself before
			// accepting a case-insensitive directory entry.
			aliasPath := filepath.Join(current, component)
			if memo, seen := r.alias[aliasPath]; seen {
				chosen = memo.canonical
			} else {
				opened, err := r.root.Open(aliasPath)
				if err != nil {
					r.alias[aliasPath] = placeResult{}
					return "", false
				}
				openedPath, err := pathid.Canonical(opened.Name())
				_ = opened.Close()
				if err != nil {
					r.alias[aliasPath] = placeResult{}
					return "", false
				}
				// A sibling scan here already ran for an earlier alias
				// spelling and canonicalized every child on its way
				// past, so this spelling's answer is in the snapshot's
				// index whether or not the alias memo has heard of it;
				// only a canonical path the index has never seen asks
				// the volume for the siblings again.
				if indexed, seen := snap.byCanonical[openedPath]; seen {
					if indexed.unique {
						chosen = indexed.name
						r.alias[aliasPath] = placeResult{canonical: chosen, ok: true}
					} else {
						r.alias[aliasPath] = placeResult{}
						return "", false
					}
				} else {
					r.scans++
					for _, child := range snap.children {
						if _, known := snap.canonical[child.Name()]; known {
							continue
						}
						childFile, err := r.root.Open(filepath.Join(current, child.Name()))
						if err != nil {
							continue
						}
						var childErr error
						childPath, childErr := pathid.Canonical(childFile.Name())
						_ = childFile.Close()
						if childErr != nil {
							continue
						}
						snap.canonical[child.Name()] = childPath
					}
					// The index is rebuilt out of the canonical answers this
					// snapshot keeps, after every scan, rather than extended
					// in place: a scan only starts because some spelling's
					// answer was missing, and the children an earlier
					// partial scan already answered -- a sibling whose open
					// or canonicalization failed once and succeeds now --
					// are seen again on the way past. Re-observing one
					// child is not two names for one path, and marking it
					// so made the index refuse spellings this resolver had
					// itself resolved a moment before. The rebuild keeps
					// the index exactly the fold of the snapshot's answers
					// at every scan: one stored name per canonical path,
					// not unique once two names carry it -- hard links --
					// however many scans it took to see them.
					clear(snap.byCanonical)
					for name, childPath := range snap.canonical {
						if prior, seen := snap.byCanonical[childPath]; seen {
							prior.unique = false
							snap.byCanonical[childPath] = prior
						} else {
							snap.byCanonical[childPath] = canonicalChild{name: name, unique: true}
						}
					}
					// Canonical paths retain the stored directory-entry spelling. Hard
					// links therefore match only the name Windows actually resolved,
					// rather than merging every name for the same file identity.
					if answer, seen := snap.byCanonical[openedPath]; !seen || !answer.unique {
						r.alias[aliasPath] = placeResult{}
						return "", false
					}
					chosen = snap.byCanonical[openedPath].name
					r.alias[aliasPath] = placeResult{canonical: chosen, ok: true}
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

// retract takes back the answers a resolver holds about one place the
// operation has itself taken away, and it is how forget's stretch survives
// its own clears. A clear that took something back used to end the whole
// stretch: every cached answer was suspect, so the next question rebuilt
// the lot -- the place index, every spelling's resolution, every snapshot
// -- and a pass that took half the record back indexed the surviving half
// once per clear, the square the review of 2026-09-26 (P3-1) measured. The
// square was the wrong price for the wrong scope: a clear changes the
// answers about the place it worked on and the directory that held it, and
// about nothing else -- the surviving names are exactly where they were.
// retract drops what the clear made into lies -- the taken place's
// snapshot and every snapshot beneath it, the witnessed resolutions that
// landed within it, the alias book's entries in the directory that held it
// and under the place -- and keeps the rest, so the stretch outlives its
// clears and the next stale entry is answered out of the index the build
// already paid for.
//
// The spelling is answered out of the memo a question asked a moment ago
// filled: holds resolved the recorded entry to ask the volume about it,
// and the canonical path the answer kept is the path the clear worked on.
// A spelling the resolver never walked has no answer to retract -- false,
// and the caller ends the stretch the old way, the answer that stays
// correct whatever the clear did. The comparisons run folded, the way
// foldedName folds: a fold errs toward joining, and an answer dropped that
// could have kept costs one question asked again, where an answer kept
// that the volume has since revoked costs the lie the stretch exists never
// to tell. The presence set the place index serves is left as it stands:
// membership needs a fresh witnessed resolution naming the place, and a
// place the clear took answers nothing, so a stale member there can spare
// nothing that is not there.
func (r *placeResolver) retract(spelling string) bool {
	got, memoed := r.places[cleanEntryPath(spelling)]
	if !memoed || !got.ok {
		return false
	}
	removed := got.canonical
	parent := filepath.Dir(removed)
	removedFolded := foldedName(removed)
	removedUnder := removedFolded + string(filepath.Separator)
	parentFolded := foldedName(parent)
	under := func(path string) bool {
		folded := foldedName(path)
		return folded == removedFolded || strings.HasPrefix(folded, removedUnder)
	}
	for dir := range r.dirs {
		// The dirs keys are built out of the stored names the walks
		// chose, so the parent's own key is the parent; the fold is for
		// everything beneath the taken place.
		if dir == parent || under(dir) {
			delete(r.dirs, dir)
		}
	}
	for asked, answer := range r.places {
		// A miss stays: a deletion never makes a name the volume once
		// did not have, so the not-found answers keep their truth.
		if answer.ok && under(answer.canonical) {
			delete(r.places, asked)
		}
	}
	for opened := range r.alias {
		// The alias keys spell the path the branch opened, in whatever
		// spelling asked the question, so both comparisons fold: the
		// spellings under the taken place, and every spelling asked in
		// the directory that held it -- any of those may have been
		// answered with the name the clear removed.
		if under(opened) || foldedName(filepath.Dir(opened)) == parentFolded {
			delete(r.alias, opened)
		}
	}
	return true
}

// placeIndex is one mutation-free stretch's instruments: one resolver and
// the canonical-presence set of the names every question in the stretch is
// asked against. forget builds one stretch for its whole loop when the run
// has something to answer and nothing to clear, copyEntries one for the
// missing sources it meets between two mirrors, and both answer every
// question of the stretch out of the set and the resolver's memos rather
// than out of a fresh walk per question -- that is what makes the unchanged
// run linear where the shapes before it paid once per pair. copyEntries'
// stretch dies with its last real mutation -- the mirror that made, took,
// or replaced a name -- because a cached answer held across one of those
// would describe directories the operation has since changed; the next
// question that needs the volume builds a fresh stretch rather than asking
// a stale instrument, and a stretch that never meets a mutation is never
// rebuilt. forget's stretch no longer dies at its clears: retract takes
// back the answers each clear made false -- the cleared place's, and the
// directory that held it -- and keeps the index of the names the list
// still holds, so a pass that takes half the record back answers the
// other half out of the one build.
// The mutation is the name's, not the byte's: a mirror that rewrote a
// standing file's bytes changed no listing and no canonical answer, and
// ends nothing.
type placeIndex struct {
	resolver *placeResolver
	places   map[string]bool
}

// newPlaceIndex resolves every name's place once, through the one resolver
// the whole stretch will share, and keeps the canonical answers the
// stretch's questions are members of.
func newPlaceIndex(root *os.Root, names []string) *placeIndex {
	resolver := newPlaceResolver(root)
	places := make(map[string]bool, len(names))
	for _, name := range names {
		if canonical, ok := resolver.place(name); ok {
			places[canonical] = true
		}
	}
	return &placeIndex{resolver: resolver, places: places}
}

// holds answers whether the recorded spelling names a place the index's
// set holds, and it is the volume-witnessed half of forget's and
// copyEntries' ownership questions. When nothing the stretch compares
// against resolved to a place at all, membership is impossible and the
// volume is not asked: this is what makes Clear -- forget with an empty
// current list -- answer every recorded entry without opening a single
// directory.
func (ix *placeIndex) holds(recorded string) bool {
	if len(ix.places) == 0 {
		return false
	}
	place, ok := ix.resolver.place(recorded)
	return ok && ix.places[place]
}

// entryPathsOf is the entries' own paths, the spelling the presence index
// is built from: the record and the rules file are carried as entries, and
// the index asks places about them one spelling at a time.
func entryPathsOf(entries []config.Entry) []string {
	paths := make([]string, len(entries))
	for i, entry := range entries {
		paths[i] = entry.Path
	}
	return paths
}
