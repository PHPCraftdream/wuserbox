package acl

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/PHPCraftdream/wuserbox/internal/win/pathid"
)

// pinnedPaths names existing directory entries by the spelling Windows gives
// their handles, not by Go's Unicode fold. A missing record entry is harmless:
// there is no object for it to spare. An existing entry that cannot be
// resolved is an ambiguity, and must stop the operation rather than risking
// a distinct object being spared by mistake.
type pinnedPaths struct {
	keys     map[string]struct{}
	resolved map[string]string
}

func makePinnedPaths(paths []string) (pinnedPaths, error) {
	set := pinnedPaths{
		keys:     make(map[string]struct{}, len(paths)),
		resolved: make(map[string]string),
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
	key, found := set.resolved[path]
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

// prepare resolves the tree before any permission change can make a child
// unreadable. Later lookups use this snapshot and fail closed for a path that
// was renamed or replaced between the two passes.
func (set pinnedPaths) prepare(root string) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("looking through %s while preparing the keep-list: %w", path, err)
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		key, err := pathid.Key(path)
		if err != nil {
			return fmt.Errorf("resolving %s while preparing the keep-list: %w", path, err)
		}
		set.resolved[path] = key
		return nil
	})
}
