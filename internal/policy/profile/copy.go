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
// at the same relative spot it holds under the user's own profile, takes away
// what a previous copy left under a name the list no longer holds, and
// reports what it copied this time. A name that does not exist on this
// machine is left out rather than treated as an error, since most of a list
// shared across machines will not exist for a given one.
//
// previously is what the last call returned. It is how this knows what to
// clear, and the knowing has to come from somewhere outside dest: dest is a
// sandbox's own profile, which the sandbox may write, so a list kept inside
// it would be a list the sandbox could edit into an instruction to delete
// something else. The caller keeps it where the sandbox cannot reach.
//
// This only ever reads under the user's profile and writes under dest, never
// the reverse, and that is fixed here rather than left to whoever calls it:
// a sandbox able to write back into the files its own credentials came from
// could rewrite them, which is the hole this exists to close.
func Copy(dest string, previously []string) ([]string, error) {
	// Asked for before anything else, because the next thing this does is
	// delete. Clearing is right when dest is a sandbox's own profile and
	// catastrophic when it is a relative path, or the drive, or a directory
	// that was never ours -- and the difference between those is one mistaken
	// argument. A caller that has not made the directory yet has not decided
	// where it is either.
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
	if err := forget(dest, previously, rules.Profile); err != nil {
		return nil, err
	}
	return copyEntries(paths.Home(), dest, rules.Profile)
}

// Clear takes back everything an earlier Copy placed under dest, without
// reading the rules file at all.
//
// This is what a sandbox built with --no-ai needs: the rules file's
// `profile:` list is not consulted for that flag, and should not be, since a
// sandbox told to skip the agent preset must not go on holding what it
// already copied simply because that section still names it. dest itself is
// left exactly as an empty thin profile would be.
func Clear(dest string, previously []string) error {
	if !filepath.IsAbs(dest) {
		return fmt.Errorf("the profile to clear must be named in full, and %q is not", dest)
	}
	return forget(dest, previously, nil)
}

// forget takes away what a previous copy put under a name the list no longer
// names, and nothing else.
//
// This is the whole of the pruning, and it is deliberately not what the
// obvious version does. Clearing dest of everything the list does not name
// reads as the tidier rule and is wrong here: dest is a profile, so what the
// list does not name includes NTUSER.DAT, the Temp directory and whatever
// the profile service built under AppData. Deleting those is deleting the
// sandbox's registry. Nothing is removed that wuserbox did not put there.
func forget(dest string, previously, current []string) error {
	keep := make(map[string]bool, len(current))
	for _, entry := range current {
		keep[strings.ToLower(filepath.ToSlash(entry))] = true
	}
	for _, entry := range previously {
		if keep[strings.ToLower(filepath.ToSlash(entry))] {
			continue
		}
		stale, err := inside(dest, entry)
		if err != nil {
			// A recorded name that does not land inside the profile is one
			// nothing here wrote. Refusing is the only safe reading: the
			// alternative is deleting whatever it does point at.
			return err
		}
		if err := os.RemoveAll(stale); err != nil {
			return fmt.Errorf("clearing %s, which the rules file no longer names: %w", entry, err)
		}
	}
	return nil
}

// inside turns a recorded entry into the path it names under dest, and
// refuses anything that climbs out.
func inside(dest, entry string) (string, error) {
	full := filepath.Join(dest, filepath.FromSlash(entry))
	within, err := filepath.Rel(dest, full)
	if err != nil || within == ".." || strings.HasPrefix(within, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%q does not name anything inside the profile", entry)
	}
	return full, nil
}

func copyEntries(home, dest string, entries []string) ([]string, error) {
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
