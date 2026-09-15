// Package profile fills a sandbox's own thin profile from the user's real
// one, copying exactly what the rules file's profile section names. Where a
// destination for that copy comes from is somebody else's decision; this
// only knows how to fill one once it is given.
package profile

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
)

// Copy places every entry the rules file's profile section names under dest,
// at the same relative spot it holds under the user's own profile, and
// reports the entries it found and copied. A name that does not exist on
// this machine is left out rather than treated as an error, since most of a
// list shared across machines will not exist for a given one.
//
// This only ever reads under the user's profile and writes under dest, never
// the reverse, and that is fixed here rather than left to whoever calls it:
// a sandbox able to write back into the files its own credentials came from
// could rewrite them, which is the hole this exists to close.
func Copy(dest string) ([]string, error) {
	// Asked for before anything else, because the next thing this does is
	// delete. Clearing dest of what the list no longer names is right when
	// dest is a sandbox's own profile and catastrophic when it is a relative
	// path, or the drive, or a directory that was never ours -- and the
	// difference between those is one mistaken argument. A caller that has
	// not made the directory yet has not decided where it is either.
	if !filepath.IsAbs(dest) {
		return nil, fmt.Errorf("the profile to fill must be named in full, and %q is not", dest)
	}
	if info, err := os.Stat(dest); err != nil {
		return nil, fmt.Errorf("the profile to fill is not there: %w", err)
	} else if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory, so it is not a profile", dest)
	}
	rules, err := config.Load()
	if err != nil {
		return nil, err
	}
	return copyEntries(paths.Home(), dest, rules.Profile)
}

func copyEntries(home, dest string, entries []string) ([]string, error) {
	if err := prune(dest, entries); err != nil {
		return nil, fmt.Errorf("clearing %s of entries no longer named: %w", dest, err)
	}
	var copied []string
	for _, entry := range entries {
		src := filepath.Join(home, filepath.FromSlash(entry))
		info, err := os.Stat(src)
		if err != nil {
			continue // not on this machine; not an error
		}
		if err := mirror(src, filepath.Join(dest, filepath.FromSlash(entry)), info); err != nil {
			return copied, fmt.Errorf("copying %s: %w", entry, err)
		}
		copied = append(copied, entry)
	}
	return copied, nil
}

// mirror replaces dst with a copy of src, exactly, whatever dst already held.
//
// Unconditionally, on every call: dst sits inside a sandbox's own profile
// once this is wired into a run, so its own timestamps are the sandboxed
// program's to set. Skipping a copy because "dst already looks new enough"
// would trust a value the very thing being contained controls, and a rule
// that only sometimes checks a trustworthy source is worse than one that
// never checks an untrustworthy one. The source's timestamps are never
// touched by a sandbox and would be safe to trust, but comparing them against
// dst's does not help: dst still has to be believed first.
//
// The cost is paid in full every time: a large listed entry is copied whole
// on every run, whether or not it changed. That is accepted because this
// list is meant to hold credentials and settings, which are small - a
// sandbox already has its own writable profile for project data and caches,
// and those never belong in this list.
func mirror(src, dst string, info os.FileInfo) error {
	if info.IsDir() {
		return mirrorDir(src, dst)
	}
	return mirrorFile(src, dst)
}

func mirrorDir(src, dst string) error {
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	present := make(map[string]bool, len(entries))
	for _, e := range entries {
		present[e.Name()] = true
		info, err := e.Info()
		if err != nil {
			return err
		}
		if err := mirror(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name()), info); err != nil {
			return err
		}
	}
	return removeStrayChildren(dst, present)
}

// removeStrayChildren drops whatever dst holds that src does not, so a
// directory entry mirrors its source exactly instead of only ever growing -
// otherwise a file an agent left behind, or one deleted from the source since
// the last run, would sit in the sandbox's profile forever.
func removeStrayChildren(dst string, present map[string]bool) error {
	entries, err := os.ReadDir(dst)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if present[e.Name()] {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dst, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

func mirrorFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// node is one step of the tree of paths the current list names, used to
// prune dest without disturbing a listed entry's own subtree: mirror already
// reconciles what is under a leaf exactly against its source, so pruning
// stops there and leaves it alone.
type node struct {
	leaf     bool
	children map[string]*node
}

func tree(entries []string) *node {
	root := &node{children: map[string]*node{}}
	for _, entry := range entries {
		cur := root
		for _, part := range strings.Split(filepath.ToSlash(entry), "/") {
			key := strings.ToLower(part)
			child, ok := cur.children[key]
			if !ok {
				child = &node{children: map[string]*node{}}
				cur.children[key] = child
			}
			cur = child
		}
		cur.leaf = true
	}
	return root
}

// prune drops whatever dest holds under a name that is not on the path to
// any entry the current list names, so dropping an entry from the rules file
// also drops what a past copy left behind under it, and nothing else ever
// ends up in dest by another route. It stops descending at a leaf: mirror
// reconciles what is under a listed entry itself, entry by entry.
func prune(dest string, entries []string) error {
	return pruneNode(dest, tree(entries))
}

func pruneNode(dir string, n *node) error {
	items, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, item := range items {
		child, known := n.children[strings.ToLower(item.Name())]
		if !known {
			if err := os.RemoveAll(filepath.Join(dir, item.Name())); err != nil {
				return err
			}
			continue
		}
		if child.leaf {
			continue
		}
		if err := pruneNode(filepath.Join(dir, item.Name()), child); err != nil {
			return err
		}
	}
	return nil
}
