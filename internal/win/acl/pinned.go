package acl

import (
	"fmt"
	"io/fs"
	"os"
	"sync"
	"sync/atomic"

	"github.com/PHPCraftdream/wuserbox/internal/win/pathid"
)

// Two counters, for the close test of a keep-list and anyone diagnosing one:
// how many tree entries a snapshot stored, and how often a later lookup had
// to go back to the file system because its answer was not held. The first
// is what the memory question about a walk is about; for a sweep the second
// stays at zero, because every object the narrowing consults was resolved
// before the first write could make asking again impossible.
var (
	pinnedSnapshots  atomic.Int64
	pinnedReresolves atomic.Int64
)

// pinnedPaths names existing directory entries by the spelling Windows gives
// their handles, not by Go's Unicode fold. A missing record entry is harmless:
// there is no object for it to spare. An existing entry that cannot be
// resolved is an ambiguity, and must stop the operation rather than risking
// a distinct object being spared by mistake.
type pinnedPaths struct {
	keys       map[string]struct{}
	entries    []pinnedEntry
	resolved   map[string]string
	resolvedMu *sync.RWMutex
}

type pinnedEntry struct {
	path string
	key  string
}

func makePinnedPaths(paths []string) (pinnedPaths, error) {
	set := pinnedPaths{
		keys:       make(map[string]struct{}, len(paths)),
		resolved:   make(map[string]string),
		resolvedMu: &sync.RWMutex{},
	}
	for _, path := range paths {
		key, err := pathid.Key(path)
		if err != nil {
			return pinnedPaths{}, fmt.Errorf("resolving pinned path %s: %w", path, err)
		}
		set.keys[key] = struct{}{}
		set.entries = append(set.entries, pinnedEntry{path: path, key: key})
	}
	return set, nil
}

// relevant keeps only record paths that are real descendants of root. The
// root itself is published directly by Isolate and is excluded from sweep;
// paths outside the current grant cannot be spared by its walk either. Both
// decisions use filesystem identity, never lexical or Unicode path rules.
// A record path whose directory entry is gone is dropped, per the contract
// above: there is no object for it to spare. An entry that exists but
// cannot be resolved is still an ambiguity, and an identity lookup failure
// is returned: silently dropping an entry could turn a keep-list into a
// different security decision.
func (set pinnedPaths) relevant(root string) (pinnedPaths, error) {
	out := pinnedPaths{
		keys:       make(map[string]struct{}, len(set.entries)),
		resolved:   make(map[string]string),
		resolvedMu: &sync.RWMutex{},
	}
	for _, one := range set.entries {
		if _, err := os.Lstat(one.path); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return pinnedPaths{}, fmt.Errorf("looking at pinned path %s: %w", one.path, err)
		}
		inside, err := pathid.Within(root, one.path)
		if err != nil {
			return pinnedPaths{}, fmt.Errorf("checking pinned path %s against %s: %w", one.path, root, err)
		}
		if !inside {
			continue
		}
		// Within in the reverse direction is true only for the same entry.
		// For a file root this also rejects an external hard-link name, whose
		// file identity is shared but whose directory entry is not inside root.
		isRoot, err := pathid.Within(one.path, root)
		if err != nil {
			return pinnedPaths{}, fmt.Errorf("checking whether pinned path %s is the root %s: %w", one.path, root, err)
		}
		if isRoot {
			continue
		}
		out.keys[one.key] = struct{}{}
		out.entries = append(out.entries, one)
	}
	return out, nil
}

func (set pinnedPaths) contains(path string) (bool, error) {
	if len(set.keys) == 0 {
		return false, nil
	}
	set.resolvedMu.RLock()
	key, found := set.resolved[path]
	set.resolvedMu.RUnlock()
	if !found {
		pinnedReresolves.Add(1)
		var err error
		key, err = pathid.Key(path)
		if err != nil {
			return false, fmt.Errorf("resolving path %s while applying the keep-list: %w", path, err)
		}
	}
	_, found = set.keys[key]
	return found, nil
}

// snapshot resolves one tree entry before any permission change can make it
// unreadable. The caller may run this from several workers; permission writes
// must still wait until the complete read-only pass finishes.
//
// The caller decides what is worth holding: the sweep's narrowing consults
// the keep-list for objects the sandbox's own account owns and for nothing
// else, so those are the only entries it asks to be held, and a path the
// narrowing never consults is one forgetting cannot turn into a wrong
// sparing. What is held is held for the whole operation -- once the walk's
// own writes have landed, an owned object can be one this process can no
// longer open, and the answer taken before them is the only one there will
// be. contains goes back to the file system for a path that was never held
// and fails closed when that answer is no longer to be had.
func (set pinnedPaths) snapshot(path string) error {
	key, err := pathid.Key(path)
	if err != nil {
		return fmt.Errorf("resolving %s while preparing the keep-list: %w", path, err)
	}
	set.resolvedMu.Lock()
	set.resolved[path] = key
	set.resolvedMu.Unlock()
	pinnedSnapshots.Add(1)
	return nil
}

// prepare resolves the tree before any permission change can make a child
// unreadable. The work is read-only and parallel, while later lookups use
// this snapshot and fail closed for a path that was renamed or replaced.
//
// What is held is what the walk that follows will consult: it stops at a
// pinned directory and never visits what is under it, so the entries spelled
// under a pinned path are passed over here too -- the same question
// underSkipped answers, by the filesystem's own spelling, byte for byte at
// the component boundary. A record path spelled differently from the walk's
// own never matches, and such an entry is snapshotted as before: a miss
// costs one snapshot, never a wrong answer.
func (set pinnedPaths) prepare(root string) error {
	if err := set.snapshot(root); err != nil {
		return err
	}
	return together(root, func(path string, _ fs.DirEntry) error {
		for _, one := range set.entries {
			if underSkipped(path, one.path) {
				return nil
			}
		}
		return set.snapshot(path)
	})
}
