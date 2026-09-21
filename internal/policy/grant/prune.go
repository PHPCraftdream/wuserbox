package grant

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/PHPCraftdream/wuserbox/internal/base/lock"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
	"github.com/PHPCraftdream/wuserbox/internal/win/pathid"
)

// Prune takes an account's access away from everything under path that would
// otherwise keep it after the grant on path itself is gone or narrowed.
//
// Handing a directory over pins its permission list, copying what it was
// handed from above into its own entries. When the directory handed over sits
// inside one that another sandbox holds, that other sandbox's entry is among
// the copies — and a copy answers to nobody. Taking the outer grant away
// rewrites the outer directory, which the pinned one inside it no longer
// hears from, so the sandbox went on writing there after its permission was
// taken away. Measured, with a real process, after a plain revoke.
//
// held names the paths the same account was granted in its own right. Those
// are not somebody's leftovers, they are grants, and the whole subtree under
// each is left alone: an account may hold a directory and something inside it
// on different terms, which is what narrowing a directory inside a handed-over
// one is for.
//
// An object account itself owns is left alone too, and for a different
// reason: StripOwn now passes it over on its own (internal/win/acl/sweep.go),
// because owning it is what the cap answers rather than this walk, and
// whichever of Apply's sweep or Revoke's TakeBack just ran over the same tree
// already left it exactly where it should be. Calling Prune afterward asks a
// second time about ground the first pass already covered, which is
// harmless: everything left for it to find is what neither reached, another
// sandbox's nested grant holding a stale copy of this account's entry.
func Prune(account, path string, held []string) error {
	return lock.HoldTree(path, func() error {
		// The root key, the keep keys and the account's identities are
		// facts about the whole pass rather than about any object on it,
		// so each is worked out once, here under the lock, and handed to
		// the walk. Working a key out opens the path and asks Windows for
		// the directory entry it names; paying that per object, three
		// times over, was the price of deciding per object what does not
		// change per object.
		rootKeyCalls.Add(1)
		root := pathKey(path)
		keep := make(map[string]bool, len(held))
		for _, one := range held {
			keepKeyCalls.Add(1)
			if key := pathKey(one); key != root {
				keep[key] = true
			}
		}
		pass, err := acl.BeginStripOwn(account)
		if err != nil {
			return err
		}
		defer pass.End()
		return filepath.WalkDir(path, func(name string, entry fs.DirEntry, err error) error {
			if err != nil {
				return fmt.Errorf("looking through %s: %w", name, err)
			}
			leafKeyCalls.Add(1)
			key := pathKey(name)
			switch {
			case key == root:
				return nil // the grant on it has already been dealt with
			case keep[key]:
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			case entry.Type()&os.ModeSymlink != 0:
				return nil
			}
			return pass.Strip(name)
		})
	})
}

// Three counters the close test of Prune reads: how often the root key, the
// keep keys and the key of a walked object were resolved. The first is once
// per call and the second once per held path; the third is once per object
// the walk reaches, against the three resolutions per object, root
// included, that deciding per object used to cost.
var (
	rootKeyCalls atomic.Int64
	keepKeyCalls atomic.Int64
	leafKeyCalls atomic.Int64
)

func pathKey(path string) string {
	if key, err := pathid.Key(path); err == nil {
		return asciiFold(key)
	}
	return "fallback:" + asciiFold(filepath.Clean(path))
}

func asciiFold(path string) string {
	var out []rune
	for _, r := range path {
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		out = append(out, r)
	}
	return string(out)
}
