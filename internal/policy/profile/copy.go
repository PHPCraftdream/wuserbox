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
// prints is what the last run recorded about the sources it carried in,
// keyed by each file's path inside the profile; the caller keeps it beside
// the .copied list, outside the profile, so the sandbox cannot rewrite
// what its own copies get compared against. It is what lets a file whose
// source has not changed be skipped without ever trusting the
// destination's timestamps. What comes back beside the copied list is this
// run's own record, to be kept the same way for the next run.
//
// This only ever reads under the user's profile and writes under dest, never
// the reverse, and that is fixed here rather than left to whoever calls it:
// a sandbox able to write back into the files its own credentials came from
// could rewrite them, which is the hole this exists to close.
func Copy(dest string, previously []config.Entry, prints map[string]Print) ([]config.Entry, map[string]Print, error) {
	root, err := openProfile(dest)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = root.Close() }()
	rules, err := config.Load()
	if err != nil {
		return nil, nil, err
	}
	// Cleanup runs first: a rule about what should not be there is applied
	// before anything decides what to bring in. It is wired in here rather
	// than in Clear, since --no-ai means this profile is not being filled at
	// all, and running the cleanup globs then would be doing the work of a
	// feature that is switched off.
	if _, err := clearCleanup(root, rules.Cleanup); err != nil {
		return nil, nil, err
	}
	if err := forget(root, previously, rules.Profile); err != nil {
		return nil, nil, err
	}
	return copyEntries(paths.Home(), root, rules.Profile, Ceiling, prints)
}

// Clear takes back everything an earlier Copy placed under dest, without
// reading the rules file at all.
//
// This is what a sandbox built with --no-ai needs: the rules file's
// `profile:` list is not consulted for that flag, and should not be, since a
// sandbox told to skip the agent preset must not go on holding what it
// already copied simply because that section still names it. dest itself is
// left exactly as an empty thin profile would be.
func Clear(dest string, previously []config.Entry) error {
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
//
// Each stale entry is cleared by clearEntry, which honors the exclusions the
// entry carried: a name leaving the list says something about copying, and
// what its exclusions protected was never ours to take back.
func forget(root *os.Root, previously []config.Entry, current []config.Entry) error {
	keep := make(map[string]bool, len(current))
	for _, entry := range current {
		keep[strings.ToLower(filepath.ToSlash(entry.Path))] = true
	}
	for _, entry := range previously {
		if keep[strings.ToLower(filepath.ToSlash(entry.Path))] {
			continue
		}
		stale, err := within(entry.Path)
		if err != nil {
			// A recorded name that does not land inside the profile is one
			// nothing here wrote. Refusing is the only safe reading: the
			// alternative is deleting whatever it does point at.
			return err
		}
		if err := clearEntry(root, stale, entry); err != nil {
			return fmt.Errorf("clearing %s, which the rules file no longer names: %w", entry.Path, err)
		}
	}
	return nil
}

// clearEntry takes back one stale entry: what a previous copy put under a
// name the rules file no longer names. An entry carrying no exclusions --
// the common case -- goes the way it always has, RemoveAll, which is cheaper
// than any walk. An entry carrying exclusions is walked instead, and only
// what its exclusions do not protect is removed, leaving the excluded paths
// and the directories on the way to them: taking the entry off the list
// said something about copying, and the exclusions it carried were never
// about copying. They name what the sandbox keeps -- the sessions the agent
// inside wrote, for one -- and nobody editing the list has said anything
// against those.
func clearEntry(root *os.Root, stale string, entry config.Entry) error {
	if len(entry.Exclude) == 0 {
		return root.RemoveAll(stale)
	}
	// A junction sitting where the entry itself landed is removed as the
	// link it is, exactly as the unfiltered clearing would: the walk below
	// opens directories through the root, and the root refuses to open one
	// that leads out of the profile, which would fail the whole clearing
	// over a link that is safe to remove and nothing else.
	info, readable := lookAt(root, stale)
	if !readable {
		return nil
	}
	if !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return root.RemoveAll(stale)
	}
	var kept bool
	if err := clearKeeping(root, stale, "", entry, &kept); err != nil {
		return err
	}
	if kept {
		return nil
	}
	// Nothing under the entry survived, so the entry's own directory goes
	// with what it held. RemoveAll rather than Remove because the entry may
	// never have landed at all, and a clearing that errors on a name that
	// is not there is worse than useless.
	return root.RemoveAll(stale)
}

// clearKeeping removes the unprotected part of one directory of a stale
// entry's subtree, through the root, and reports through kept whether
// anything under it was spared. A child an exclusion protects is left with
// everything below it and no questions asked: the mask was written against
// the child's own relative path, and the sandbox's claim does not stop at
// its first level. A directory with nothing protected under it goes once
// its children have gone -- a directory is kept only while it is the way to
// something protected -- so the clearing takes the entry's shape apart
// rather than leaving empty frames behind.
func clearKeeping(root *os.Root, dir, rel string, entry config.Entry, kept *bool) error {
	d, err := root.Open(dir)
	if err != nil {
		// The entry may never have landed, or is already gone; either way
		// there is nothing here to take back.
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	children, err := d.ReadDir(-1)
	_ = d.Close()
	if err != nil {
		return err
	}
	for _, child := range children {
		childRel := child.Name()
		if rel != "" {
			childRel = rel + "/" + child.Name()
		}
		if protectedBy(entry, childRel) {
			*kept = true
			continue
		}
		childPath := filepath.Join(dir, child.Name())
		if !child.IsDir() {
			if err := root.Remove(childPath); err != nil && !os.IsNotExist(err) {
				return err
			}
			continue
		}
		var under bool
		if err := clearKeeping(root, childPath, childRel, entry, &under); err != nil {
			return err
		}
		if under {
			*kept = true
			continue
		}
		if err := root.Remove(childPath); err != nil && !os.IsNotExist(err) {
			return err
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
// EntryEscapesProfile answers whether a profile: entry's path, exactly as
// the rules file spells it, would be refused by within for being absolute
// or for climbing out of the profile with "..", and if so, within's own
// message. Exported so validation asks this package the question rather
// than re-deciding it with a copy of the same rule: two answers to "does
// this path escape the profile" are exactly how a rules file comes to pass
// validation and then fail the run.
func EntryEscapesProfile(path string) error {
	_, err := within(path)
	return err
}

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

// copyEntries takes its budget rather than reading the ceiling itself, so a
// test can measure the counting and the refusal without asking this machine
// for sixty-four megabytes of temporary files.
//
// prints is what the last run recorded and the map returned is this run's:
// a skipped file carries its print forward and a copied file gets a fresh
// one, so anything this run did not finish with is simply absent, which
// sends the next run back to copying it.
func copyEntries(home string, root *os.Root, entries []config.Entry, left int64, prints map[string]Print) ([]config.Entry, map[string]Print, error) {
	var copied []config.Entry
	newPrints := make(map[string]Print, len(prints))
	for _, entry := range entries {
		dst, err := within(entry.Path)
		if err != nil {
			return copied, newPrints, err
		}
		src := filepath.Join(home, filepath.FromSlash(entry.Path))
		info, err := os.Stat(src)
		if err != nil {
			continue // not on this machine; not an error
		}
		// Written down before the copying and not after. What this list is for
		// is knowing what to take back, and a name that was half copied has to
		// be on it more than one that was copied whole: a directory with three
		// of its files in it, or a file truncated where the writing stopped, is
		// exactly what a later clearing must reach.
		//
		// Recording it afterwards meant the opposite. A copy stopped in the
		// middle -- by the ceiling, or by anything else -- returned a list
		// without the name it had been working on, the caller recorded that
		// list, and what had landed stayed in the sandbox's profile for good
		// because nothing left knew it was there.
		copied = append(copied, entry)
		if err := mirror(src, dst, "", root, info, &left, newWalk(entry), prints, newPrints); err != nil {
			return copied, newPrints, fmt.Errorf("copying %s: %w", entry.Path, err)
		}
	}
	return copied, newPrints, nil
}
