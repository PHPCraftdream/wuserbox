package profile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/win/pathid"
)

// refreshMutation updates one parent listing after a mirror changed a name.
// It keeps unrelated sibling resolutions and their canonical-presence
// answers intact. Directory generations invalidate dependent aliases/misses.
func (r *placeResolver) refreshMutation(path, parent, dependencyDir string) error {
	path = cleanEntryPath(path)
	target := filepath.Join(parent, filepath.Base(path))
	actual := ""
	file, openErr := r.root.Open(target)
	if openErr == nil {
		actual, openErr = pathid.Canonical(file.Name())
		_ = file.Close()
		if openErr == nil && actual == "" {
			return fmt.Errorf("resolving profile path after mirror changed %s: canonical path is empty", path)
		}
	} else if !os.IsNotExist(openErr) {
		return fmt.Errorf("refreshing profile resolver after mirror changed %s: %w", path, openErr)
	}
	if openErr != nil && actual == "" && !os.IsNotExist(openErr) {
		return fmt.Errorf("resolving profile path after mirror changed %s: %w", path, openErr)
	}
	actualEntry := ""
	if actual != "" {
		actualEntry = filepath.Join(parent, filepath.Base(actual))
	}
	r.dirVersion[parent]++
	if dependencyDir != "" && dependencyDir != parent {
		r.dirVersion[dependencyDir]++
	}
	r.dirVersion[path]++
	if actualEntry != "" && actualEntry != path {
		r.dirVersion[actualEntry]++
	}

	if err := r.refreshSnapshots(target); err != nil {
		return fmt.Errorf("updating profile path after mirror changed %s: %w", path, err)
	}
	if actual != "" {
		info, statErr := r.root.Lstat(actualEntry)
		if statErr != nil && !os.IsNotExist(statErr) {
			return fmt.Errorf("checking profile path after mirror changed %s: %w", path, statErr)
		}
		if statErr == nil && info.IsDir() {
			r.dropDir(actualEntry)
		}
	}
	for dir := filepath.Clean(path); dir != "."; dir = filepath.Dir(dir) {
		if snap, ok := r.dirs[dir]; ok && !snap.ok {
			r.dropDir(dir)
		}
	}
	return nil
}

func (r *placeResolver) refreshSnapshots(path string) error {
	current := "."
	for _, component := range strings.Split(cleanEntryPath(path), string(filepath.Separator)) {
		if snap, ok := r.dirs[current]; ok && !snap.ok {
			r.dropDir(current)
		}
		snap, ok := r.dirs[current]
		if !ok {
			return nil
		}
		childPath := filepath.Join(current, component)
		file, err := r.root.Open(childPath)
		if err != nil {
			if !os.IsNotExist(err) {
				return err
			}
			r.removeSnapshotChild(&snap, component)
			r.dirs[current] = snap
			return nil
		}
		canonical, err := pathid.Canonical(file.Name())
		_ = file.Close()
		if err != nil {
			return err
		}
		name := filepath.Base(canonical)
		r.removeSnapshotChild(&snap, component)
		r.removeSnapshotChild(&snap, name)
		snap.childAt[name] = len(snap.children)
		snap.children = append(snap.children, name)
		snap.byName[name] = name
		snap.canonical[name] = canonical
		if snap.canonicalNames[canonical] == nil {
			snap.canonicalNames[canonical] = make(map[string]bool)
			r.canonicalMaps++
		}
		snap.canonicalNames[canonical][name] = true
		r.rebuildCanonical(snap, canonical)
		r.dirs[current] = snap
		current = filepath.Join(current, name)
	}
	return nil
}

// removeSnapshotChild takes one name out of a snapshot's listing and its
// answers, and it asks nothing for a name the listing never held: the byName
// rows are the witness, because canonical rows are only ever written beside
// byName rows -- snapshot() builds the two from the same enumeration, the
// alias scan writes a child's canonical answer under a name it read out of
// the listing, and refresh writes both rows for the name it just re-added.
// A name with no byName row therefore holds no canonical row, no child slot
// and no membership to take back, and the guard is what keeps a refresh's
// unchanged neighbors from being walked over twice per changed name -- the
// filter this replaces cost every neighbor of every changed name, even
// where the name was not in the listing at all.
func (r *placeResolver) removeSnapshotChild(snap *dirSnapshot, name string) {
	if _, known := snap.byName[name]; !known {
		return
	}
	delete(snap.byName, name)
	snap.takeChild(name)
	if canonical := snap.canonical[name]; canonical != "" {
		delete(snap.canonical, name)
		delete(snap.canonicalNames[canonical], name)
		r.rebuildCanonical(*snap, canonical)
	}
}

func (r *placeResolver) rebuildCanonical(snap dirSnapshot, canonical string) {
	names := snap.canonicalNames[canonical]
	switch len(names) {
	case 0:
		delete(snap.canonicalNames, canonical)
		delete(snap.byCanonical, canonical)
	case 1:
		if !snap.canonicalComplete {
			delete(snap.byCanonical, canonical)
			return
		}
		for name := range names {
			snap.byCanonical[canonical] = canonicalChild{name: name, unique: true}
		}
	default:
		name := ""
		for child := range names {
			if name == "" || child < name {
				name = child
			}
		}
		snap.byCanonical[canonical] = canonicalChild{name: name, unique: false}
	}
}

// placeIndex is one operation's resolver and canonical-presence set.
// forget updates it with retract after clears; copyEntries updates only the
// changed subtree after mirrors. Unchanged recorded places stay indexed,
// keeping mixed copy runs linear in their recorded entries.
type placeIndex struct {
	resolver *placeResolver
	paths    map[string]string
	members  map[string]map[string]bool
	// unknown is the set of recorded spellings whose resolutions did not
	// finish: the membership set cannot vouch for them, because the one
	// question that would place them never answered.
	unknown map[string]bool
	byPath  *placePathNode
}

type placePathNode struct {
	children map[string]*placePathNode
	paths    map[string]bool
}

func (n *placePathNode) add(path string) {
	if n.children == nil {
		n.children = make(map[string]*placePathNode)
	}
	parts := strings.Split(cleanEntryPath(path), string(filepath.Separator))
	for _, part := range parts {
		key := foldedName(part)
		if n.children == nil {
			n.children = make(map[string]*placePathNode)
		}
		if n.children[key] == nil {
			n.children[key] = &placePathNode{}
		}
		n = n.children[key]
	}
	if n.paths == nil {
		n.paths = make(map[string]bool)
	}
	n.paths[cleanEntryPath(path)] = true
}

func (n *placePathNode) under(path string) []string {
	parts := strings.Split(cleanEntryPath(path), string(filepath.Separator))
	for _, part := range parts {
		n = n.children[foldedName(part)]
		if n == nil {
			return nil
		}
	}
	var paths []string
	var walk func(*placePathNode)
	walk = func(node *placePathNode) {
		for path := range node.paths {
			paths = append(paths, path)
		}
		for _, child := range node.children {
			walk(child)
		}
	}
	walk(n)
	return paths
}

// newPlaceIndex resolves every name's place once, through the one resolver
// the whole stretch will share, and keeps the canonical answers the
// stretch's questions are members of.
func newPlaceIndex(root *os.Root, names []string) *placeIndex {
	resolver := newPlaceResolver(root)
	index := &placeIndex{
		resolver: resolver,
		paths:    make(map[string]string, len(names)),
		members:  make(map[string]map[string]bool, len(names)),
		byPath:   &placePathNode{},
	}
	for _, name := range names {
		index.byPath.add(name)
		index.index(name)
	}
	return index
}

func (ix *placeIndex) index(spelling string) {
	key := cleanEntryPath(spelling)
	result := ix.resolver.place(spelling)
	delete(ix.unknown, key)
	if !result.ok {
		if result.unknown {
			if ix.unknown == nil {
				ix.unknown = make(map[string]bool)
			}
			ix.unknown[key] = true
		}
		delete(ix.paths, key)
		return
	}
	ix.paths[key] = result.canonical
	if ix.members[result.canonical] == nil {
		ix.members[result.canonical] = make(map[string]bool)
	}
	ix.members[result.canonical][key] = true
}

// refresh keeps one operation-local index current after a mirror. Only
// recorded names at or below the changed entry are revisited; other places
// retain their canonical answers and the resolver's snapshots.
func (ix *placeIndex) refresh(path string) error {
	changed := ix.byPath.under(path)
	key := cleanEntryPath(path)
	parent := filepath.Dir(key)
	dependencyDir := ""
	canonical := filepath.Join(parent, filepath.Base(key))
	if known, ok := ix.paths[parent]; ok {
		parent = known
		canonical = filepath.Join(parent, filepath.Base(key))
	} else if known, ok := ix.resolver.places[parent]; ok && known.ok {
		parent = known.canonical
		canonical = filepath.Join(parent, filepath.Base(key))
		dependencyDir = known.directory
	}
	if known, ok := ix.paths[key]; ok {
		canonical = known
		parent = filepath.Dir(known)
	} else if known, ok := ix.resolver.places[key]; ok && known.ok {
		canonical = known.canonical
		parent = filepath.Dir(known.canonical)
	}
	if known, ok := ix.resolver.places[key]; ok && known.directory != "" {
		dependencyDir = known.directory
	}
	if canonical != "" {
		for _, place := range ix.resolver.placesUnder(canonical) {
			for key := range ix.members[place] {
				changed = append(changed, key)
			}
		}
	}
	ix.resolver.retract(key)
	for _, key := range changed {
		ix.resolver.retract(key)
		if canonical, ok := ix.paths[key]; ok {
			delete(ix.members[canonical], key)
			if len(ix.members[canonical]) == 0 {
				delete(ix.members, canonical)
			}
			delete(ix.paths, key)
		}
		delete(ix.resolver.places, key)
	}
	if err := ix.resolver.refreshMutation(path, parent, dependencyDir); err != nil {
		return err
	}
	for _, key := range changed {
		ix.index(key)
	}
	return nil
}

func (r *placeResolver) placesUnder(path string) []string {
	subtree := []string{path}
	for i := 0; i < len(subtree); i++ {
		for child := range r.dirChildren[subtree[i]] {
			subtree = append(subtree, child)
		}
	}
	return subtree
}

// vouchAnswer is what the record's membership answers about one entry's
// place, and it is the shape the round-11 review asked the bool to grow:
// absent and held are witnessed answers, unknown is the case where the
// question itself did not finish.
type vouchAnswer int

const (
	// witnessed: every recorded spelling that could be compared resolved,
	// and none names the place this entry names.
	vouchAbsent vouchAnswer = iota
	// witnessed: a recorded spelling resolves onto the place this entry
	// names.
	vouchHeld
	// the question did not finish: this entry's own walk stopped on a
	// failure that is not absence, or a recorded spelling that might name
	// the same place could not be resolved to be compared against. Not
	// an answer, and never to be read as one.
	vouchUnknown
)

// vouches is holds' three-state shape, asked where the answer decides a
// recorded entry's fate: copyEntries decides whether a vanished source's
// copy stays on the record, and answering that on a question nobody got
// is how a locked destination directory retires a copy that still stands.
//
// The fast path is the one that keeps Clear paying nothing: membership
// empty AND nothing unresolved means nothing was indexed at all -- an
// empty record, or an indexing pass that witnessed honest absences -- so
// absent is then witnessed without asking again, and Clear answers every
// recorded entry without opening a single directory.
//
// The len(ix.unknown) > 0 branch before absent is deliberate, and it asks
// for the entry's own witnessed place: an absence vouches for nothing, so
// where this entry names no place at all there is nothing an unanswered
// spelling could have kept standing -- a recorded spelling that went
// unanswered could only have named a place this entry actually names, and
// where the entry names none, no answer anyone owed could have kept a copy
// alive at it. The branch therefore only holds a place back while the entry
// itself names a witnessed one that an unanswered recorded spelling might
// also name.
func (ix *placeIndex) vouches(recorded string) (vouchAnswer, error) {
	if len(ix.members) == 0 && len(ix.unknown) == 0 {
		return vouchAbsent, nil
	}
	result := ix.resolver.place(recorded)
	if result.unknown {
		return vouchUnknown, result.err
	}
	if result.ok && len(ix.members[result.canonical]) > 0 {
		return vouchHeld, nil
	}
	if result.ok && len(ix.unknown) > 0 {
		return vouchUnknown, nil
	}
	return vouchAbsent, nil
}

// holds is the bool convenience over vouches, for callers whose next step
// asks the volume itself and stops on what it cannot finish: an unknown
// reading as false stays safe where every step after it -- clearEntry's
// Lstat, the reserved questions, the walks -- fails closed on its own.
// forget's first ask is not that shape, and asks vouches instead.
func (ix *placeIndex) holds(recorded string) bool {
	answer, _ := ix.vouches(recorded)
	return answer == vouchHeld
}
