package profile

import (
	"os"
	"path/filepath"
)

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
//
// Finding the answers a clear made false is the reverse books' work. The
// scanned loops this shape replaced walked the snapshot table, the places
// memo and the alias book whole on every real clear, folding every key to
// ask whether it sat under the taken place -- and every book is keyed by
// walk products, one namespace of stored names, so the ancestry the folds
// were groping for is already recorded exactly: dirChildren files each
// snapshot key, and each witnessed terminal place notePlace filed beside
// them, beneath the key its walk came from, placeAt files each
// witnessed spelling under the canonical place its answer named, aliasIn
// files each alias answer under the directory its question stood in. A
// retraction walks the taken place's registered subtree once, takes each
// key's snapshot and the answers filed in it back, and never sees an
// entry the clear did not touch -- visits is the counter that holds the
// pass to that, where the scanned loops paid every book, every clear.
//
// One question the books cannot answer, the volume is asked: did the
// clear take the name out of the directory that held it? A real clear
// has two shapes. The ordinary one removed the name -- RemoveAll of the
// entry, or the limits-bearing walk that spared nothing -- and the
// holding directory's listing is the old one minus exactly the taken
// name, so the snapshot is amended in place: the taken name's rows leave
// byName and the canonical index, the survivors' rows stand. That is not
// a stale listing kept for a smaller counter -- it is the listing the
// volume holds now, witnessed at the same clear that took the name, and
// a spelling the gone name would have answered is put to the volume
// again at the alias branch's open and refused by it, exactly as a fresh
// enumeration would have had it refused. The second shape comes in two,
// and the volume's own Lstat answer tells them apart. The directory the
// clear left standing -- a limits-bearing clear that spared something
// under the entry, an exclusion's charge among it -- stands under the
// same name it held all along: the holding directory's listing is the
// one it held before the clear, the taken name's row the row the volume
// holds now, and every answer the clear made false lives beneath the
// place, where the subtree walk has already been. The snapshot stands
// with the survivors' enumeration and identity in it, and nothing after
// the clear pays a re-enumeration of the holding directory for a listing
// the clear never touched -- the square a pass of such clears paid when
// the snapshot went with the place, one whole re-enumeration per clear,
// the review of 2026-09-28 (P3-1) measured. Any other answer -- an error
// that is neither the volume's nothing nor its witness of the standing
// name -- leaves the question of whether the name went open, and nothing
// narrower than the former whole scope is witnessed: the holding
// directory's snapshot goes with the place, the way it went before this
// shape, and the answer stays correct whatever the clear did. A deletion
// is never guessed narrower than it was witnessed, in either direction.
//
// The spelling is answered out of the memo a question asked a moment ago
// filled: holds resolved the recorded entry to ask the volume about it,
// and the canonical path the answer kept is the path the clear worked on.
// A spelling the resolver never walked has no answer to retract -- false,
// and the caller ends the stretch the old way, the answer that stays
// correct whatever the clear did. The presence set the place index serves
// is left as it stands: membership needs a fresh witnessed resolution
// naming the place, and a place the clear took answers nothing, so a
// stale member there can spare nothing that is not there.
func (r *placeResolver) retract(spelling string) bool {
	got, memoed := r.places[cleanEntryPath(spelling)]
	if !memoed || !got.ok {
		return false
	}
	removed := got.canonical
	parent := filepath.Dir(removed)
	_, statErr := r.root.Lstat(removed)
	gone := statErr != nil && os.IsNotExist(statErr)
	// The keys beneath the taken place, its own first: the reverse
	// book's walk down from it. A key is filed only where a walk filed
	// it, and a walk reached a key only through every key above it, so
	// this walk finds every snapshot and every witnessed terminal place
	// the clear could have made stale, and nothing else -- notePlace
	// files a leaf's canonical path here exactly as noteDir files a
	// directory's, so a leaf under the taken place is found by this walk
	// even though it was never opened as a directory itself.
	subtree := []string{removed}
	for i := 0; i < len(subtree); i++ {
		for child := range r.dirChildren[subtree[i]] {
			subtree = append(subtree, child)
		}
	}
	// Deepest first, so a key's children have taken their own rows back
	// by the time the key itself goes. A key with a snapshot drops it;
	// a key with none -- a terminal place notePlace filed but no ReadDir
	// ever touched -- still unfiles its own seat in dirChildren.
	for i := len(subtree) - 1; i >= 0; i-- {
		key := subtree[i]
		if _, ok := r.dirs[key]; ok {
			r.dropDir(key)
		} else {
			r.unlinkChild(key)
		}
		// The witnessed spellings that name the taken place or
		// something beneath it. A miss would keep its truth here as
		// everywhere, and none is filed to drop: a deletion never
		// makes a name the volume once did not have.
		for asked := range r.placeAt[key] {
			delete(r.places, asked)
			r.visits++
		}
		delete(r.placeAt, key)
	}
	if gone {
		// The alias book's say in the directory that held it: every
		// answer asked there may have been answered with the name the
		// clear removed, so none survives the clear -- the scope the
		// scanned loops gave them, paid now only in the entries the
		// book hands over.
		for opened := range r.aliasIn[parent] {
			delete(r.alias, opened)
			r.visits++
		}
		delete(r.aliasIn, parent)
		// The holding directory's listing is amended in place: the
		// taken name leaves every snapshot index and the child list.
		// removeSnapshotChild is the hand that knows the shape -- it
		// takes the byName row, the child slot and the canonical
		// answer with it -- and its rebuildCanonical already covers
		// every case the eager row deletions used to cover, the
		// taken path's answer standing or falling with what the
		// volume still holds under it.
		if snap, ok := r.dirs[parent]; ok && snap.ok {
			r.removeSnapshotChild(&snap, filepath.Base(removed))
			r.dirs[parent] = snap
		}
	} else if statErr != nil {
		// Neither the volume's nothing nor its witness of the standing
		// name: the question of whether the name went outlived the
		// clear, nothing narrower than the former whole scope is
		// witnessed, and the holding directory's snapshot goes with the
		// place, the way it went before the standing answer kept it.
		if _, ok := r.dirs[parent]; ok {
			r.dropDir(parent)
		}
	}
	return true
}
