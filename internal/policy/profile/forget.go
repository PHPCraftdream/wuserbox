package profile

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
)

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
	for _, entry := range previously {
		if stillNamed(root, current, entry.Path) {
			continue
		}
		// A recorded entry whose name the volume resolves onto a reserved
		// path is spared, not refused and not honored: the record may
		// spell the hive with a trailing dot or a short alias -- measured,
		// both open the hive through an os.Root -- and clearEntry would
		// honor the spelling to the letter. Spared rather than refused for
		// the reason clearEntry spares: nobody editing a rules file wrote
		// this spelling, an earlier run of this tool did.
		if reservedAtResolved(root, filepath.ToSlash(cleanEntryPath(entry.Path))) {
			continue
		}
		stale, err := withinRecorded(entry.Path)
		if err != nil {
			// A recorded name that does not land inside the profile is one
			// nothing here wrote. Refusing is the only safe reading: the
			// alternative is deleting whatever it does point at. The
			// question is withinRecorded's, not within's, for the reason
			// withinRecorded gives: the spelling was not hand-written, and
			// a refusal over it would strand the entry's copy.
			return err
		}
		// A recorded entry whose limits cannot bind is refused rather than
		// guessed at, and the record is where the refusal has to stand: the
		// rules file's own bad depth is refused by Copy before this runs,
		// but a run before that refusal existed wrote the rules file's depth
		// straight into the record, and Clear -- which reads no rules file
		// -- reaches it here. With the entry's own depth at -1 the walk
		// would spare everything below and the take-back would report
		// success while taking back nothing; with a mask's depth at -1 the
		// mask reaches nothing and its exclusion stops protecting exactly
		// when the deletion is happening. The recorded limits are the only
		// thing that says what the sandbox keeps.
		//
		// The way out is named in the message, because unlike a rules file
		// this is not a file anybody was told about: a record can only carry
		// a limit like this if some earlier build accepted it, so the person
		// reading this did not write it anywhere they can see. Naming the
		// entry again is what lets a run past it -- forget skips what the
		// current list still names -- and the copy that follows rewrites the
		// record with limits that bind, after which the entry can be dropped
		// for good.
		if err := EntryCarriesNegativeDepth(entry); err != nil {
			return fmt.Errorf("the record of what an earlier run put in this sandbox names %s with a limit "+
				"that cannot bind, so what under it is the sandbox's own cannot be told from what this "+
				"tool copied, and nothing will be deleted on a guess: %w. Put %s back in the profile: "+
				"list with a depth that can bind, or with none, and run once -- that rewrites the record "+
				"and the entry can be removed again afterwards",
				entry.Path, err, entry.Path)
		}
		if err := clearEntry(root, stale, entry); err != nil {
			return fmt.Errorf("clearing %s, which the rules file no longer names: %w", entry.Path, err)
		}
	}
	return nil
}

// clearEntry takes back one stale entry: what a previous copy put under a
// name the rules file no longer names. A bare entry -- no depth, no masks,
// the common case -- goes the way it always has, RemoveAll, which is
// cheaper than any walk. An entry carrying any limit is walked instead, and
// only what the copy would have touched is removed, leaving the excluded
// paths and everything below the entry's depth: taking the entry off the
// list said something about copying, and the limits it carried were never
// about copying. They name what the sandbox keeps -- the sessions the agent
// inside wrote, for one -- and nobody editing the list has said anything
// against those.
//
// The depth bound belongs to that same promise, and it was missed once:
// depth 0 spares an agent's sessions on every ordinary run, because the
// mirroring declines to empty a directory the walk will not enter, and then
// removing the entry -- or a --no-ai run, which reads no rules file at all
// -- deleted the whole tree, sessions and all. An entry that never reached
// below its depth never put anything there, and what is there is the
// sandbox's.
func clearEntry(root *os.Root, stale string, entry config.Entry) error {
	// A reserved path is inert to the take-back whatever the entry
	// carried: the record may name the hive outright, bare or with
	// limits, and both branches below would honor the name to the
	// letter -- the bare one by RemoveAll, the limits-bearing one the
	// moment its target is not a directory. The question is asked of the
	// name the volume resolves it to as well -- a record spelling the
	// hive under an alias, a trailing dot or a short name, is spared by
	// the file the volume reaches, not the one it spells. Spared rather
	// than refused; reserved.go records why this spares where
	// refuseReservedCleanup refuses.
	rel := filepath.ToSlash(stale)
	if reservedAtResolved(root, rel) {
		return nil
	}
	if entry.Bare() {
		// An entry over a directory the hive sits under -- AppData
		// leaving the list, most commonly -- takes the hive with it by
		// the roots. What around it is ours still goes: the same walk
		// the limits-bearing branch uses, clearing around the hive.
		if reservedWithinResolved(root, rel) {
			_, err := clearKeepingReserved(root, stale)
			return err
		}
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
	if err := clearKeeping(root, stale, "", newWalk(entry), &kept); err != nil {
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

// clearKeeping removes what one directory of a stale entry's subtree holds
// that the entry's own walk would have touched, through the root, and
// reports through kept whether anything under it was spared. The questions
// are asked of w, so the same rules govern the copy and the taking-back: a
// directory the walk would not enter -- one an exclusion names, or one past
// the depth that governed the copy -- is left with everything below it and
// no questions asked, and a file the entry would not have copied -- because
// an exclusion or an include list left it out -- is left the same way. The
// mask was written against the child's own relative path, and the sandbox's
// claim does not stop at its first level. A directory with nothing spared
// under it goes once its children have gone -- a directory is kept only
// while it is the way to something kept -- so the clearing takes the entry's
// shape apart rather than leaving empty frames behind.
func clearKeeping(root *os.Root, dir, rel string, w *walk, kept *bool) error {
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
		childPath := filepath.Join(dir, child.Name())
		if child.IsDir() {
			if !w.descends(childRel) {
				*kept = true
				continue
			}
			// A directory sitting at a reserved path is spared by its
			// name -- and by the name the volume resolves it to, when the
			// two differ. Whatever the sandbox made of the hive's name,
			// nothing under a name the tables reserve was ever ours to
			// sort, and reporting it kept is what leaves it so.
			if reservedAtResolved(root, filepath.ToSlash(childPath)) {
				*kept = true
				continue
			}
			// Lstat before opening, the way cleanDir does: a junction the
			// sandbox planted where a plain directory sits is removed as
			// the link it is -- the root would refuse to open one leading
			// out of the profile, and failing the whole clearing over an
			// artifact the sandbox is entitled to leave lying around is
			// worse than taking the link.
			if info, readable := lookAt(root, childPath); !readable ||
				info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
				if err := root.Remove(childPath); err != nil && !os.IsNotExist(err) {
					return err
				}
				continue
			}
			var under bool
			if err := clearKeeping(root, childPath, childRel, w, &under); err != nil {
				return err
			}
			if under {
				*kept = true
				continue
			}
		} else {
			// A file outside the entry's include list was never ours to
			// remove. This matters when an entry is removed entirely: the
			// sandbox may have written an unrelated file beside the copies,
			// and an include is a boundary on copying just as an exclusion is
			// a boundary on taking back.
			// The registry is not ours to take back under any entry: a
			// depth that reaches four below AppData reaches the class
			// hive, and the walk honoring the entry's limits would honor
			// them straight through the profile service's file -- spelled
			// however the destination's own directory entry spells it,
			// which the resolved question is what answers.
			if reservedAtResolved(root, filepath.ToSlash(childPath)) {
				*kept = true
				continue
			}
			if !w.copiesFile(childRel) {
				*kept = true
				continue
			}
		}
		if err := root.Remove(childPath); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// stillNamed answers whether the current list names the place a recorded
// entry claims, and it is the question whose both wrong directions delete:
// reading two spellings of one place as strangers deletes a live copy, and
// reading two places as one spares a stray for good. Where the volume can
// answer, it is asked -- sameEntryPlace opens both spellings and compares
// them as the one witness both lists stand before. Where it cannot, the
// recorded place is not on disk and the spellings are compared cleaned and
// nothing else: the clean is the half that was measured (a rules file
// respelling "agent" as "./agent"), and case is deliberately left out of
// it, because with no place on disk there is nothing for case to be
// witnessed against and every extra join is the fold's i-for-U+0131
// mistake in a fallback's clothes.
//
// What the fallback has to keep working is the record's own escape hatch:
// a recorded entry whose limits cannot bind is refused below unless the
// list still names it, and the way out of that refusal is putting the
// entry back under its recorded spelling and running once -- which may be
// a run where the copy never lands at all, so the hatch cannot depend on
// anything being on disk.
func stillNamed(root *os.Root, current []config.Entry, recorded string) bool {
	cleaned := cleanEntryPath(recorded)
	for _, entry := range current {
		if cleanEntryPath(entry.Path) == cleaned {
			return true
		}
		if sameEntryPlace(root, entry.Path, recorded) {
			return true
		}
	}
	return false
}
