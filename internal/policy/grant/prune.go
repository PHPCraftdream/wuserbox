package grant

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/base/lock"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
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
func Prune(account, path string, held []string) error {
	keep := make(map[string]bool, len(held))
	for _, one := range held {
		if !strings.EqualFold(one, path) {
			keep[strings.ToLower(one)] = true
		}
	}
	return lock.HoldTree(path, func() error {
		return filepath.WalkDir(path, func(name string, entry fs.DirEntry, err error) error {
			switch {
			case err != nil:
				return fmt.Errorf("looking through %s: %w", name, err)
			case strings.EqualFold(name, path):
				return nil // the grant on it has already been dealt with
			case keep[strings.ToLower(name)]:
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			case entry.Type()&os.ModeSymlink != 0:
				return nil
			}
			return acl.StripOwn(name, account)
		})
	})
}
