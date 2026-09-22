// The operation-local index behind find: one resolution per recorded grant to
// build it and one per asked spelling to answer it, where the linear scan it
// replaced paid for both sides of every pair all over again, and the stretch
// those cheap answers are good for.

package state

import "github.com/PHPCraftdream/wuserbox/internal/policy/config"

// identityOf resolves one path's comparison key through a variable so the
// counting tests can hold the resolutions an operation pays for without the
// production path knowing it is measured.
var identityOf = config.Identity

// pathIndex is one operation's instrument for finding a grant by path. Every
// run that prepares a sandbox asks find once per rule path the rules name,
// and the record holds every grant earlier runs wrote down, so the scan used
// to put both sides of every one of those pairs through SamePath afresh --
// each side a stat and a file open -- before the unchanged fast path could
// even say there was nothing to do. The index answers the same questions the
// scan did, from two maps: each recorded grant's comparison key resolved once
// to build, each asked spelling resolved once to answer, whatever the number
// of questions either side of the multiply.
//
// What it must never do is outlive the operation that built it, persist
// across runs, or answer from a list it no longer describes. It is transient
// like fresh and written nowhere; every branch that is about to change which
// paths the record holds drops it first, and the next question rebuilds it
// over the list as it then stands. A write to an entry's kind, mark or
// pending flag changes no path and keeps it.
type pathIndex struct {
	// asked remembers one spelling's comparison key, so the same place
	// asked about twice in the operation is resolved once — including a
	// spelling that resolved to nothing, which stays that answer for the
	// operation's life, exactly as the scan it replaced would have asked
	// the volume again only to be told the same nothing.
	asked map[string]string
	// byKey maps a recorded grant's comparison key to its position in
	// s.Grants, the first match winning the way the linear scan did.
	byKey map[string]int
}

// find reports where the record holds path: the first entry naming the place,
// and (0, false) when none does, the same answer the linear scan gave.
func (s *State) find(path string) (int, bool) {
	index := s.index()
	position, found := index.byKey[index.key(path)]
	return position, found
}

// index builds the operation's index the first question asks for it, and
// hands the same one back until something drops it. The build resolves each
// recorded grant once; where two entries name one place, the first keeps the
// position, which is the entry the scan returned.
func (s *State) index() *pathIndex {
	if s.byPath != nil {
		return s.byPath
	}
	index := &pathIndex{
		asked: make(map[string]string),
		byKey: make(map[string]int, len(s.Grants)),
	}
	for i, g := range s.Grants {
		key := index.key(g.Path)
		if _, held := index.byKey[key]; !held {
			index.byKey[key] = i
		}
	}
	s.byPath = index
	return index
}

// key resolves one spelling's comparison key once per operation: the memo is
// asked first, and only a spelling this operation has never asked about
// before reaches the volume.
func (p *pathIndex) key(path string) string {
	if key, seen := p.asked[path]; seen {
		return key
	}
	key := identityOf(path)
	p.asked[path] = key
	return key
}

// dropIndex throws the operation's answers away. It is called on the branch
// into every change of the record's path list, because positions the index
// remembers would point at the wrong entry -- or past the end -- once entries
// move, and an absence it remembers may stop being one. The next question
// rebuilds it over the list as it now stands.
func (s *State) dropIndex() {
	s.byPath = nil
}
