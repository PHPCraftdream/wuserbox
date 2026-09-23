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
	// One cleaned-spelling set of the current list, built before the loop:
	// the ordinary warm run answers every recorded entry out of it and
	// never opens the volume at all -- the pass is O(E) before anything
	// asks a directory for a child. The clean is cleanEntryPath, the same
	// one the ownership question falls back to, and case is deliberately
	// left out of the comparison exactly as it was there: where the volume
	// can witness a place it is asked -- the stretch's holds below -- and
	// case is decided against that place, but where it cannot, the
	// recorded place is not on disk and the spellings are compared cleaned
	// and nothing else, because with no place to be witnessed against
	// every extra join is the fold's i-for-U+0131 mistake in a fallback's
	// clothes. The fallback is also the record's escape hatch: a recorded
	// entry whose limits cannot bind is refused below unless the list
	// still names it, and the way out is putting the entry back under its
	// recorded spelling and running once -- which may be a run where the
	// copy never lands at all, so the spelling answer cannot depend on
	// anything being on disk.
	currentSpellings := make(map[string]bool, len(current))
	for _, entry := range current {
		currentSpellings[cleanEntryPath(entry.Path)] = true
	}
	// One placeIndex per mutation-free stretch of the loop, built the
	// first time a question actually needs the volume: a recorded entry
	// the list still names by spelling is answered above and never builds
	// anything, and an entry the volume cannot witness at all is answered
	// by the same spelling set. The stretch keeps its resolver and its
	// canonical-presence set across every question the stretch answers
	// after it is built, so a pass that clears nothing pays for one
	// indexing of the current list however many recorded entries it
	// answers. A clear that takes something back is the mutation the
	// stretch's answers cannot survive untouched, and clearEntry's own
	// answer says which clears did: each one retracts the answers it made
	// false -- the taken place's, and the directory that held it -- and
	// keeps the index of the names the list still holds, so a pass that
	// clears half the record answers the other half out of the one build.
	// A pass whose clears all find nothing to take back pays the same one
	// indexing.
	var stretch *placeIndex
	for _, entry := range previously {
		if currentSpellings[cleanEntryPath(entry.Path)] {
			continue
		}
		if stretch == nil {
			stretch = newPlaceIndex(root, entryPathsOf(current))
		}
		// An answer nobody got proceeds, because every step below asks the
		// volume itself and stops on what it cannot finish -- clearEntry's
		// Lstat, the reserved questions, the walks -- so nothing is deleted
		// on an answer nobody got. The only answer that skips the entry here
		// is a witnessed held one.
		if vouch, _ := stretch.vouches(entry.Path); vouch == vouchHeld {
			continue
		}
		// A recorded entry whose name the volume resolves onto a reserved
		// path is spared, not refused and not honored: the record may
		// spell the hive with a trailing dot or a short alias -- measured,
		// both open the hive through an os.Root -- and clearEntry would
		// honor the spelling to the letter. Spared rather than refused for
		// the reason clearEntry spares: nobody editing a rules file wrote
		// this spelling, an earlier run of this tool did.
		if answer, cause := reservedAtResolved(root, filepath.ToSlash(cleanEntryPath(entry.Path))); answer != notReserved {
			if answer == reservedUnknown {
				// Sparing a known reserved object stands; reporting a
				// finished take-back over an object whose identity
				// could not be checked is what the round-12 review
				// traced through the NoAI record wipe, and the run
				// stops instead, with the record standing for the
				// retry.
				return reservedStop(filepath.ToSlash(cleanEntryPath(entry.Path)), cause)
			}
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
		taken, err := clearEntry(root, stale, entry)
		if err != nil {
			return fmt.Errorf("clearing %s, which the rules file no longer names: %w", entry.Path, err)
		}
		if taken {
			// A clear that took something back disassembled
			// directories the stretch's cached answers still
			// describe -- but only the ones the clear worked on: the
			// place it took, and the directory that held it. The
			// names the list still holds are exactly where they
			// were, so retract takes back the answers the clear made
			// false and keeps the index of the rest, and the next
			// stale entry is answered out of the build the stretch
			// already paid for -- a pass that takes half the record
			// back used to rebuild that index once per real clear,
			// the square the review of 2026-09-26 (P3-1) measured.
			// retract's false is the clear that never witnessed the
			// place it worked on -- nothing to scope the retraction
			// to: the stretch dies here and the next question that
			// needs the volume builds a fresh one, the whole-stretch
			// answer that stays correct whatever the clear did. A
			// clear that took nothing back -- the entry's copy was
			// already gone from the profile -- changed no name, and
			// answering the next question out of the same
			// instruments stays the truth: a pass over stale entries
			// whose copies are all already gone pays for one indexing
			// of the current list however many of them it answers.
			if !stretch.resolver.retract(entry.Path) {
				stretch = nil
			}
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
//
// The bool this answers with says whether anything was actually taken --
// a name removed, a link replaced -- as against the entry's copy already
// gone from the profile, which is answered and spared the same way. forget
// holds one stretch of resolver instruments across its clears, and a clear
// that took something back retracts the answers that clear made false --
// the taken place's, and the directory that held it -- where it used to
// end the stretch outright, because the names the clear never touched are
// exactly where they were. An error
// means the take-back could not finish -- the question of whether the
// copy stood at all went unanswered -- and the entry stays on the record
// for the run that comes after: an answer nobody got is never read as
// nothing to take.
func clearEntry(root *os.Root, stale string, entry config.Entry) (bool, error) {
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
	switch answer, cause := reservedAtResolved(root, rel); answer {
	case isReserved:
		return false, nil
	case reservedUnknown:
		return false, reservedStop(rel, cause)
	}
	if entry.Bare() {
		// An entry over a directory the hive sits under -- AppData
		// leaving the list, most commonly -- takes the hive with it by
		// the roots. What around it is ours still goes: the same walk
		// the limits-bearing branch uses, clearing around the hive.
		switch answer, cause := reservedWithinResolved(root, rel); answer {
		case isReserved:
			_, taken, err := clearKeepingReserved(root, stale)
			return taken, err
		case reservedUnknown:
			return false, reservedStop(rel, cause)
		}
		// RemoveAll answers nil for a name that is not there, and the
		// stretch's question needs the two told apart: asked here, where
		// the existence answer is the removal answer. The volume's own
		// nothing is the only nothing that reads as gone: a name an
		// ordinary program still holds, or one this run's rights cannot
		// open, is a question the take-back could not finish, and
		// answering it as an absence reports success over a copy left
		// standing under a record that no longer names it. The error
		// stops the take-back with the record standing, and the next run
		// asks again.
		if _, err := root.Lstat(stale); err != nil {
			if os.IsNotExist(err) {
				return false, nil
			}
			return false, err
		}
		if err := root.RemoveAll(stale); err != nil {
			return false, err
		}
		return true, nil
	}
	// A junction sitting where the entry itself landed is removed as the
	// link it is, exactly as the unfiltered clearing would: the walk below
	// opens directories through the root, and the root refuses to open one
	// that leads out of the profile, which would fail the whole clearing
	// over a link that is safe to remove and nothing else.
	// The same distinction the bare branch draws: the volume's own
	// nothing means the entry never landed or is already gone, and the
	// take-back answers a no-op; anything else is a question this run
	// could not finish, and walking or removing on the strength of an
	// answer nobody got would report success over a copy it never
	// looked at. The error goes up with the record standing for the
	// next run to ask again.
	info, err := root.Lstat(stale)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		if err := root.RemoveAll(stale); err != nil {
			return false, err
		}
		return true, nil
	}
	var kept, taken bool
	if err := clearKeeping(root, stale, "", newWalk(entry), &kept, &taken); err != nil {
		return false, err
	}
	if kept {
		// Children of the entry's own tree may have gone even where
		// something was spared: taken is the walk's own count, and the
		// answer follows it rather than kept.
		return taken, nil
	}
	// Nothing under the entry survived, so the entry's own directory goes
	// with what it held. RemoveAll rather than Remove because the entry may
	// never have landed at all, and a clearing that errors on a name that
	// is not there is worse than useless.
	if err := root.RemoveAll(stale); err != nil {
		return false, err
	}
	return true, nil
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
// shape apart rather than leaving empty frames behind. It reports through
// removed too, whether anything was actually taken, the shape
// clearKeepingReserved answers in, so a caller that must not carry its
// cached view of the profile across a real deletion can tell the two clears
// apart.
func clearKeeping(root *os.Root, dir, rel string, w *walk, kept, removed *bool) error {
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
			if answer, cause := reservedAtResolved(root, filepath.ToSlash(childPath)); answer != notReserved {
				if answer == reservedUnknown {
					return reservedStop(filepath.ToSlash(childPath), cause)
				}
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
				if err := root.Remove(childPath); err != nil {
					if !os.IsNotExist(err) {
						return err
					}
				} else {
					*removed = true
				}
				continue
			}
			var under bool
			if err := clearKeeping(root, childPath, childRel, w, &under, removed); err != nil {
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
			if answer, cause := reservedAtResolved(root, filepath.ToSlash(childPath)); answer != notReserved {
				if answer == reservedUnknown {
					return reservedStop(filepath.ToSlash(childPath), cause)
				}
				*kept = true
				continue
			}
			if !w.copiesFile(childRel) {
				*kept = true
				continue
			}
		}
		if err := root.Remove(childPath); err != nil {
			if !os.IsNotExist(err) {
				return err
			}
		} else {
			*removed = true
		}
	}
	return nil
}
