// Package profile fills a sandbox's own thin profile from the user's real
// one, copying exactly what the rules file's profile section names. Where a
// destination for that copy comes from is somebody else's decision; this
// only knows how to fill one once it is given.
//
// Everything written or deleted here goes through an os.Root pinned on the
// destination, and that is the whole of this file's care. This code runs as
// the person who owns the machine, with their rights, on a directory the
// sandbox may write: without the root, a sandbox that replaced one of these
// directories with a junction had wuserbox itself delete and overwrite
// whatever the junction pointed at. Measured, on a real junction, before the
// root went in: files outside the profile were removed and truncated.
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
	root, err := openProfile(dest)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	rules, err := config.Load()
	if err != nil {
		return nil, err
	}
	if err := forget(root, previously, rules.Profile); err != nil {
		return nil, err
	}
	return copyEntries(paths.Home(), root, rules.Profile)
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
	root, err := openProfile(dest)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	return forget(root, previously, nil)
}

// openProfile pins the directory everything below writes into.
//
// Asked for before anything else, because the next thing this does is
// delete. Naming the destination in full is required of the caller and
// checked here: clearing is right when dest is a sandbox's own profile and
// catastrophic when it is a relative path, or the drive, or a directory that
// was never ours -- and the difference between those is one mistaken
// argument.
//
// os.Root is what makes the rest of this file safe rather than merely
// careful. Every path it is given is resolved inside the opened directory,
// component by component, and a reparse point that leads out of it is
// refused rather than followed -- which is exactly the move a sandbox has
// available, since it owns its own profile and needs no privilege to make a
// junction. A string check on the path could not see that: the path would
// look fine and the file system would still take the operation somewhere
// else.
func openProfile(dest string) (*os.Root, error) {
	if !filepath.IsAbs(dest) {
		return nil, fmt.Errorf("the profile to fill must be named in full, and %q is not", dest)
	}
	root, err := os.OpenRoot(dest)
	if err != nil {
		return nil, fmt.Errorf("the profile to fill cannot be opened: %w", err)
	}
	return root, nil
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
func forget(root *os.Root, previously, current []string) error {
	keep := make(map[string]bool, len(current))
	for _, entry := range current {
		keep[strings.ToLower(filepath.ToSlash(entry))] = true
	}
	for _, entry := range previously {
		if keep[strings.ToLower(filepath.ToSlash(entry))] {
			continue
		}
		stale, err := within(entry)
		if err != nil {
			// A recorded name that does not land inside the profile is one
			// nothing here wrote. Refusing is the only safe reading: the
			// alternative is deleting whatever it does point at.
			return err
		}
		if err := root.RemoveAll(stale); err != nil {
			return fmt.Errorf("clearing %s, which the rules file no longer names: %w", entry, err)
		}
	}
	return nil
}

// within turns an entry from the rules file into the path it names under the
// profile, and refuses one that climbs out.
//
// The root refuses that too, and more thoroughly -- this cannot see a
// junction and the root can. It is here for the message: a name written
// wrongly in the rules file deserves to be told what is wrong with it,
// rather than "path escapes from parent" about a path nobody typed.
func within(entry string) (string, error) {
	clean := filepath.Clean(filepath.FromSlash(entry))
	if filepath.IsAbs(clean) || clean == ".." ||
		strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%q does not name anything inside the profile", entry)
	}
	return clean, nil
}

// Ceiling is how much one run may carry into a sandbox's profile before it is
// stopped.
//
// The list this serves names credentials and settings, and came to 254 KB
// where it was measured. It named whole agent state directories once and came
// to 72,320 files and 19,436 MB -- per sandbox, per run -- and nothing noticed
// until somebody counted. Retiring that default fixes the rules files wuserbox
// wrote; it does not fix one somebody wrote themselves, and nothing else here
// would ever tell them.
//
// Going over stops the run rather than being reported and passed over. A copy
// still going after this much is filling a sandbox with somebody's work rather
// than with what an agent needs to log in, and the run it is holding up was
// going to start with a half-built profile either way.
const Ceiling = 64 << 20

func copyEntries(home string, root *os.Root, entries []string) ([]string, error) {
	var copied []string
	left := int64(Ceiling)
	for _, entry := range entries {
		dst, err := within(entry)
		if err != nil {
			return copied, err
		}
		src := filepath.Join(home, filepath.FromSlash(entry))
		info, err := os.Stat(src)
		if err != nil {
			continue // not on this machine; not an error
		}
		if err := mirror(src, dst, root, info, &left); err != nil {
			return copied, fmt.Errorf("copying %s: %w", entry, err)
		}
		copied = append(copied, entry)
	}
	return copied, nil
}

// mirror replaces dst with a copy of src, exactly, whatever dst already held.
// src is a path on the machine; dst is a path inside the profile's root.
//
// Unconditionally, on every call: dst sits inside a sandbox's own profile, so
// its own timestamps are the sandboxed program's to set. Skipping a copy
// because "dst already looks new enough" would trust a value the very thing
// being contained controls, and a rule that only sometimes checks a
// trustworthy source is worse than one that never checks an untrustworthy
// one. The source's timestamps are never touched by a sandbox and would be
// safe to trust, but comparing them against dst's does not help: dst still
// has to be believed first.
//
// The cost is paid in full every time, which is affordable only because this
// list names credentials and settings rather than whole state directories --
// the default was the latter once, and came to 72,320 files and 19 GB per
// run. A sandbox has its own writable profile for project data and caches,
// and those never belong in this list.
func mirror(src, dst string, root *os.Root, info os.FileInfo, left *int64) error {
	if info.IsDir() {
		return mirrorDir(src, dst, root, left)
	}
	if *left -= info.Size(); *left < 0 {
		return fmt.Errorf("this is carrying more than %d MB into the sandbox's profile, and %s is "+
			"where it went over. The profile section of the rules file is for the files an agent "+
			"needs in order to be logged in, not for the directories it keeps its work in: name "+
			"those files, or take the directory out",
			Ceiling>>20, src)
	}
	return mirrorFile(src, dst, root)
}

func mirrorDir(src, dst string, root *os.Root, left *int64) error {
	if err := clearWhatIsNotADirectory(root, dst); err != nil {
		return err
	}
	if err := root.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	present := make(map[string]bool, len(entries))
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			return err
		}
		// Anything that is neither a plain file nor a directory is passed
		// over: a junction or symlink inside the source would otherwise be
		// opened as a file and fail the whole copy, or followed into a loop.
		// What it points at is the user's own arrangement to make; copying
		// the link into a sandbox is not.
		if !info.Mode().IsRegular() && !info.IsDir() {
			continue
		}
		present[e.Name()] = true
		if err := mirror(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name()), root, info, left); err != nil {
			return err
		}
	}
	return removeStrayChildren(root, dst, present)
}

// clearWhatIsNotADirectory takes away whatever sits at dst when it is not a
// plain directory, so that a copy of a directory can be made there.
//
// This is what keeps a sandbox from pinning a name in its own profile. Put a
// junction where a listed directory belongs and the root refuses to make a
// directory over it -- rightly, it will not follow the link -- and every run
// afterwards fails on the same name until somebody removes the sandbox.
// Removing the link is not following it: measured, what it pointed at is
// untouched, which is the whole reason this is safe to do without asking.
func clearWhatIsNotADirectory(root *os.Root, dst string) error {
	info, readable := lookAt(root, dst)
	// Nothing there, or nothing this can read: MkdirAll answers next, and
	// its answer is the one worth reporting.
	if !readable {
		return nil
	}
	if info.IsDir() && info.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0 {
		return nil
	}
	return root.RemoveAll(dst)
}

// lookAt is Lstat where not finding something is an answer rather than a
// failure.
func lookAt(root *os.Root, name string) (os.FileInfo, bool) {
	info, err := root.Lstat(name)
	return info, err == nil
}

// removeStrayChildren drops whatever dst holds that src does not, so a
// directory entry mirrors its source exactly instead of only ever growing -
// otherwise a file an agent left behind, or one deleted from the source since
// the last run, would sit in the sandbox's profile forever.
func removeStrayChildren(root *os.Root, dst string, present map[string]bool) error {
	dir, err := root.Open(dst)
	if err != nil {
		return err
	}
	entries, err := dir.ReadDir(-1)
	_ = dir.Close()
	if err != nil {
		return err
	}
	for _, e := range entries {
		if present[e.Name()] {
			continue
		}
		if err := root.RemoveAll(filepath.Join(dst, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

func mirrorFile(src, dst string, root *os.Root) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if parent := filepath.Dir(dst); parent != "." {
		if err := root.MkdirAll(parent, 0o755); err != nil {
			return err
		}
	}
	out, err := root.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
