package acl

import (
	"fmt"
	"io/fs"
	"sync"

	"github.com/PHPCraftdream/wuserbox/internal/win/pathid"
)

// pinnedPaths names existing directory entries by the spelling Windows gives
// their handles, not by Go's Unicode fold. A missing record entry is harmless:
// there is no object for it to spare. An existing entry that cannot be
// resolved is an ambiguity, and must stop the operation rather than risking
// a distinct object being spared by mistake.
type pinnedPaths struct {
	keys       map[string]struct{}
	resolved   map[string]string
	resolvedMu *sync.RWMutex
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
	}
	return set, nil
}

func (set pinnedPaths) contains(path string) (bool, error) {
	if len(set.keys) == 0 {
		return false, nil
	}
	set.resolvedMu.RLock()
	key, found := set.resolved[path]
	set.resolvedMu.RUnlock()
	if !found {
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
func (set pinnedPaths) snapshot(path string) error {
	key, err := pathid.Key(path)
	if err != nil {
		return fmt.Errorf("resolving %s while preparing the keep-list: %w", path, err)
	}
	set.resolvedMu.Lock()
	set.resolved[path] = key
	set.resolvedMu.Unlock()
	return nil
}

// prepare resolves the tree before any permission change can make a child
// unreadable. The work is read-only and parallel, while later lookups use
// this snapshot and fail closed for a path that was renamed or replaced.
func (set pinnedPaths) prepare(root string) error {
	if err := set.snapshot(root); err != nil {
		return err
	}
	return together(root, func(path string, _ fs.DirEntry) error {
		return set.snapshot(path)
	})
}
