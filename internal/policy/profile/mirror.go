package profile

import (
	"fmt"
	"os"
	"path/filepath"
)

// sink is what a walk does once it has decided, through walk.go's rules,
// that a file or directory belongs under an entry -- copy it into dest, or
// only ask what copying it would come to. Everything above sink is shared:
// the recursion in walkDir, and every descend/exclude/copy decision it asks
// of *walk. Only the action at the bottom differs, in copySink and its
// read-only twin planSink in preview.go. That is the shape --dry-run needs:
// a plan a real run cannot disagree with, because both read it off the same
// walk instead of two walks that could drift apart.
type sink interface {
	// prepareDir is asked before a directory's children are visited, with
	// the chance to make dst ready to receive them.
	prepareDir(root *os.Root, dst string) error
	// file is asked once per file the walk has let through, and does
	// whatever this sink does with it.
	file(src, dst string, root *os.Root, info os.FileInfo, left *int64, prints, newPrints map[string]Print) error
	// finishDir is asked after a directory's children are visited, with the
	// names this pass kept, so a sink that clears what is no longer present
	// can do it here.
	finishDir(root *os.Root, dst, rel string, present map[string]bool, w *walk) error
}

// mirror replaces dst with a copy of src, exactly, whatever dst already
// held. src is a path on the machine; dst is a path inside the profile's
// root; rel is dst's path relative to the entry being copied, empty for the
// entry itself. It answers whether the walk changed the destination's
// structure -- made, took, or replaced a name -- as against only rewriting
// the bytes of files that already stood: a name changed is a cached answer
// made false, a rewritten byte is not, and the caller keeps one stretch of
// resolver instruments across the mirrors that changed no name.
//
// The entry itself is never filtered: its limits say what is copied under
// it, and an entry naming a file has nothing under it.
func mirror(src, dst, rel string, root *os.Root, info os.FileInfo, left *int64, w *walk, prints, newPrints map[string]Print, scratch *[]byte) ([]string, error) {
	s := &copySink{scratch: scratch}
	err := walkEntry(s, src, dst, rel, root, info, left, w, prints, newPrints)
	return s.mutations, err
}

// walkEntry is mirror's shape with the action pulled out: dispatch to a
// directory's children, or hand one file to sk.
func walkEntry(sk sink, src, dst, rel string, root *os.Root, info os.FileInfo, left *int64, w *walk, prints, newPrints map[string]Print) error {
	// A reserved path is inert to this walk: the registry is never copied
	// into a profile, and neither is anything this walk would do to it --
	// sk.file would lay the user's own hive over the profile service's, and
	// a directory entered at a reserved name would clear onto it. Asked
	// here, above the sinks, so planSink counts a preview through the same
	// answer and --dry-run cannot disagree with the run. dst is the path
	// relative to the profile root, which is the frame the reserved tables
	// are written in; rel is relative to the entry and would guard nothing.
	// The question is asked of the name the volume resolves dst to as well,
	// and it has to be asked here and not only in within: within refuses a
	// spelling the rules file wrote wrongly, but dst on this walk is built
	// out of source directory entries the walk read itself, and a source
	// carrying the hive as "NTUSER.DAT." or under a short alias lands here
	// as exactly such a name -- a name the volume resolves onto the hive is
	// the hive, whatever the walk spelled it.
	if reservedAtResolved(root, filepath.ToSlash(dst)) {
		return nil
	}
	if info.IsDir() {
		return walkDir(sk, src, dst, rel, root, left, w, prints, newPrints)
	}
	if rel != "" && !w.copiesFile(rel) {
		return nil
	}
	return sk.file(src, dst, root, info, left, prints, newPrints)
}

// walkDir is mirrorDir's shape with the action pulled out. Which children
// are descended into or copied is answered by *walk exactly as it always
// was; what happens to dst around them is sk's to decide.
func walkDir(sk sink, src, dst, rel string, root *os.Root, left *int64, w *walk, prints, newPrints map[string]Print) error {
	if err := sk.prepareDir(root, dst); err != nil {
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
		childRel := e.Name()
		if rel != "" {
			childRel = rel + "/" + e.Name()
		}
		if info.IsDir() {
			// descends answers both exclusion and reach: an excluded
			// directory is not descended into at all, and past the bound
			// nothing inside could be copied anyway.
			if !w.descends(childRel) {
				continue
			}
			present[foldedName(e.Name())] = true
			if err := walkEntry(sk, filepath.Join(src, e.Name()), filepath.Join(dst, e.Name()), childRel, root, info, left, w, prints, newPrints); err != nil {
				return err
			}
			continue
		}
		// On the present list only what this run copies: a file the include
		// list has stopped naming is as stale in the destination as one the
		// source has lost, and the mirroring below is what retires it.
		if !w.copiesFile(childRel) {
			continue
		}
		present[foldedName(e.Name())] = true
		if err := walkEntry(sk, filepath.Join(src, e.Name()), filepath.Join(dst, e.Name()), childRel, root, info, left, w, prints, newPrints); err != nil {
			return err
		}
	}
	return sk.finishDir(root, dst, rel, present, w)
}

// copySink is the real fill: it writes, and it deletes what a directory's
// mirroring leaves stale.
//
// copySink records the relative names whose structure the walk changed.
type copySink struct {
	mutations   []string
	mutationSet map[string]bool
	// scratch points at the copy-operation's shared buffer cell, not at a
	// buffer this sink owns: mirror builds a fresh sink per entry, and the
	// buffer outlives each of them, so the pass that owns the cell pays
	// for the buffer once however many entries it runs.
	scratch *[]byte
}

func (s *copySink) markMutation(path string) {
	key := cleanEntryPath(path)
	for parent := filepath.Dir(key); parent != "."; parent = filepath.Dir(parent) {
		if s.mutationSet[parent] {
			return
		}
	}
	if s.mutationSet == nil {
		s.mutationSet = make(map[string]bool)
	}
	if !s.mutationSet[key] {
		s.mutationSet[key] = true
		s.mutations = append(s.mutations, key)
	}
}

// prepareDir takes away whatever sits at dst when it is not a plain
// directory, so that a copy of a directory can be made there, and makes the
// directory itself.
//
// This is what keeps a sandbox from pinning a name in its own profile. Put a
// junction where a listed directory belongs and the root refuses to make a
// directory over it -- rightly, it will not follow the link -- and every run
// afterwards fails on the same name until somebody removes the sandbox.
// Removing the link is not following it: measured, what it pointed at is
// untouched, which is the whole reason this is safe to do without asking.
//
// The directory is made before anything under it is decided, and left
// standing whether or not anything below ends up copied. Which directories
// exist in the destination has to follow from what the rules file walks;
// making it depend on what each one happened to match would have the shape
// of a sandbox's profile changing for reasons nobody can see from the file.
// Predictable is worth more than tidy here.
//
// MkdirAll can make more than dst: a dst several components deep, none of
// them standing yet, comes back from clearWhatIsNotADirectory as !plain the
// same way a dst that only had to take one name did, and the two are not
// the same mutation -- one name changed under an index that already knew
// its parent, against a parent MkdirAll made too, whose own listing the
// index never learned changed at all. Marking dst alone was this asymmetry:
// file's own missing-parent search two functions below already answers the
// same question for a file's parent chain, and the review of 2026-09-29
// (round 10, P2-1) named the directory branch's not doing the same the
// root of a refresh answering a stale question. This walks it for dst's
// own chain, the way the directory branch owes it.
func (s *copySink) prepareDir(root *os.Root, dst string) error {
	plain, err := clearWhatIsNotADirectory(root, dst)
	if err != nil {
		return err
	}
	if !plain {
		missingParent := ""
		for parent := filepath.Dir(dst); parent != "."; parent = filepath.Dir(parent) {
			if _, there := lookAt(root, parent); there {
				break
			}
			missingParent = parent
		}
		if missingParent != "" {
			s.markMutation(missingParent)
		}
		s.markMutation(dst)
	}
	return root.MkdirAll(dst, 0o755)
}

// clearWhatIsNotADirectory is prepareDir's own half of the work, kept apart
// so its reasoning has room to be spelled out. See prepareDir. It answers
// whether dst stood as a plain directory when it was done: false covers
// both a name that had to be taken to make room and a name that was never
// there, the two shapes the MkdirAll beside it acts on, and both are the
// destination's structure changing. A look that could not finish at all is
// neither of those and is an error rather than a plain: the volume's own
// nothing is the only nothing this walk may read as room to make the
// directory in, and going on to MkdirAll over a name it never understood
// would report that call's failure in words about a name nothing here
// examined. Stopping leaves the destination as it stood for the next run
// to ask again.
func clearWhatIsNotADirectory(root *os.Root, dst string) (plain bool, err error) {
	info, err := root.Lstat(dst)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if info.IsDir() && info.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0 {
		return true, nil
	}
	return false, root.RemoveAll(dst)
}

// lookAt is Lstat with the readable shape the walks' cautious questions
// ask, and every caller here treats unreadable as the cautious answer --
// no skip, the structure question marked changed, the removal or creation
// below attempted anyway, and the one that cannot be done is the error the
// caller reports. A caller that would read unreadable as absent must ask
// the error itself, the way clearEntry, clearWhatIsNotADirectory and
// cleanDir's descendant question do: a
// name the volume refuses to describe -- an ordinary program's exclusive
// hold on it, most commonly -- is not a name the volume reports gone, and
// reading one as the other is how a take-back reports success over a copy
// it never looked at.
func lookAt(root *os.Root, name string) (os.FileInfo, bool) {
	info, err := root.Lstat(name)
	return info, err == nil
}

// file is copySink's answer to one file the walk let through: copy it, or
// skip it where the source has not changed since the fingerprint kept for
// it was taken.
//
// This used to copy unconditionally, and the argument for it was sound as
// far as it went: dst sits inside a sandbox's own profile, so dst's own
// timestamps are the sandboxed program's to set, and skipping a copy
// because "dst already looks new enough" would trust a value the very thing
// being contained controls. What that argument missed is that a comparison
// does not have to read the destination to be trustworthy. The skip below
// compares the source, as it sits on disk now, against prints -- what the
// source looked like when this run last carried it in -- and both halves of
// that comparison are beyond the sandbox's reach: the source, which nothing
// inside a sandbox can touch, and the record, which lives beside the
// .copied list, outside the profile it describes. The destination is asked
// one question, whether it still holds a file of the source's size, and
// that catches the ordinary case -- a sandbox that deleted or truncated its
// copy and needs it back -- not an attack. A sandbox that forges its own
// file's size to keep an edit is not being defended against, for the reason
// spelled out below.
//
// What the skip gives up, said plainly because somebody will meet it: a
// sandbox that edits its own copy of a file now keeps the edit until the
// source changes, where this used to overwrite it on every run. That is a
// change in behavior rather than a loss -- a sandbox can keep a copy of
// anything it was ever handed -- and this comment is where the change is
// supposed to be found.
//
// The skip exists because unconditional stopped being affordable. The
// default list alone grew from 254 KB of credential files to roughly 2.8 MB
// across about 250 files of instructions -- agents, commands, skills --
// recopied into every sandbox on every run. What still copies every time
// is what actually changed, which is what a refresh was for.
func (s *copySink) file(src, dst string, root *os.Root, info os.FileInfo, left *int64, prints, newPrints map[string]Print) error {
	// Counted here, before the skip decision, and counted for skipped files
	// too. The ceiling measures how much the rules file names, not how much
	// one run happened to move: a list that grew to 100 MB has to be
	// refused on the run that only had to carry 5 MB of it, which is
	// exactly the run where every file matched. Charging only what a run
	// moves reads as the natural rule and is the wrong one -- it would let
	// the oversized list through on precisely the runs that noticed.
	if *left -= info.Size(); *left < 0 {
		return fmt.Errorf("this is carrying more than %d MB into the sandbox's profile, and %s is "+
			"where it went over. The profile section of the rules file is for the files an agent "+
			"needs in order to be logged in, not for the directories it keeps its work in: name "+
			"those files, or take the directory out",
			Ceiling>>20, src)
	}
	// Keyed by the file's path inside the destination profile, spelled with
	// forward slashes, exactly the path it is copied to.
	key := filepath.ToSlash(dst)
	if old, ok := prints[key]; ok && old.stillDescribes(info) {
		// The last two conditions of the skip, and the ordinary case they
		// catch: a sandbox that lost its copy -- deleted it, truncated it
		// -- gets it back even though the source has not changed. One
		// Lstat through the root answers both. It has to be a plain file:
		// a junction or a directory sitting where the file belongs is not
		// the copy, and replacing it is what the copy below is for.
		if now, there := lookAt(root, dst); there && now.Mode().IsRegular() && now.Size() == info.Size() {
			newPrints[key] = old
			return nil
		}
	}
	missingParent := ""
	for parent := filepath.Dir(dst); parent != "."; parent = filepath.Dir(parent) {
		if _, there := lookAt(root, parent); there {
			break
		}
		missingParent = parent
	}
	if missingParent != "" {
		s.markMutation(missingParent)
	}
	taken, changed, err := mirrorFile(src, dst, root, info.Size(), s.scratch)
	if err != nil {
		return err
	}
	if changed {
		s.markMutation(dst)
	}
	// Recorded only once the copy is whole, and the print is the opened
	// source's own rather than the walk's: the FileInfo this function was
	// handed was read before the copy began, and an ordinary writer to the
	// source can move it between that reading and the bytes going in. The
	// print mirrorFile answers with was read off the handle the bytes
	// actually came through, after the transfer confirmed the source did
	// not move while it was being read, so it describes the file that
	// went in rather than the one the walk happened to measure. A file
	// whose write failed, was cut short, or was refused for having grown
	// past what was declared gets no fingerprint, so the next run copies
	// it instead of skipping on the strength of a print for a copy that
	// never happened.
	newPrints[key] = taken
	return nil
}

// finishDir drops whatever dst holds that this run did not put there, so a
// directory entry mirrors its source exactly instead of only ever growing --
// otherwise a file an agent left behind, or one deleted from the source
// since the last run, would sit in the sandbox's profile forever.
//
// One kind of stray is not a stray, and dropping it is the mistake this
// whole format exists to answer: a path one of the entry's exclude masks
// names. An exclusion is two statements at once -- do not bring this in, and
// this is the sandbox's to keep -- and the mirroring is where the second
// statement is kept. Without it the copy would skip the excluded path and
// this would then delete it for not being in the source, which is a slower
// way of doing the same damage.
func (s *copySink) finishDir(root *os.Root, dst, rel string, present map[string]bool, w *walk) error {
	return s.removeStrayChildren(root, dst, rel, present, w)
}

func (s *copySink) removeStrayChildren(root *os.Root, dst, rel string, present map[string]bool, w *walk) error {
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
		if present[foldedName(e.Name())] {
			continue
		}
		childRel := e.Name()
		if rel != "" {
			childRel = rel + "/" + e.Name()
		}
		if w.excludes(childRel) {
			continue
		}
		// A directory the walk will not enter is not this entry's to empty.
		// Whatever the reason it is not entered -- an exclusion, or a depth
		// that stops above it -- the entry has declined to look inside, and
		// deleting what you have refused to look at cannot be right. Without
		// this, `depth: 0` on an agent's directory would copy the two files
		// at the top and wipe everything the agent wrote below them on every
		// run, which is the damage the whole format exists to stop and would
		// arrive by a different door.
		//
		// A file is a different question and is still taken: it sits within
		// reach, the entry did look at it, and not naming it is a decision
		// rather than a refusal to decide.
		if e.IsDir() && !w.descends(childRel) {
			continue
		}
		// The guard above spares a directory the walk declines to enter. But
		// a directory the walk WOULD have entered, and the source has since
		// lost, used to go whole -- the exclusion was asked only about the
		// directory's own relative path, so with exclude: ["**/*.db"] the
		// database at agent/local-only/history.db died with local-only the
		// moment the source lost local-only. What is inside has to be asked
		// before the tree goes, and clearKeeping already knows how to ask:
		// it is the walk the entry's own taking-back uses, sparing excluded
		// paths and everything past the entry's depth, and keeping the
		// directory only while it is the way to something spared. An entry
		// with no include, exclude, or depth can spare nothing below, and
		// keeps the RemoveAll, which is cheaper than any walk.
		childPath := filepath.Join(dst, e.Name())
		if e.IsDir() && (w.bound != nil || len(w.entry.Include) > 0 || len(w.entry.Exclude) > 0) {
			// A junction where the lost directory sat is removed as the
			// link it is, the way clearKeeping and cleanDir both treat
			// one: the root would refuse to open a link leading out of
			// the profile, and failing the mirror over an artifact the
			// sandbox may leave is worse than taking the link.
			if info, readable := lookAt(root, childPath); readable &&
				info.IsDir() && info.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0 {
				var under, removed bool
				if err := clearKeeping(root, childPath, childRel, w, &under, &removed); err != nil {
					return err
				}
				if removed {
					s.markMutation(childPath)
				}
				if under {
					continue
				}
			}
		}
		// The one stray the mirroring never takes is the registry: whatever
		// the reserved tables name, here or anywhere under here, is Windows'
		// work, not the source's absence. A spared file costs nothing
		// further; a directory with the hive under it is cleared around it
		// instead of taken whole, the way clearKeeping clears around what an
		// entry's own limits protect. childPath, built by Join from dst, is
		// relative to the profile root -- the tables' frame; childRel is the
		// entry's and would make a guard that protects nothing.
		if reservedWithinResolved(root, filepath.ToSlash(childPath)) {
			if e.IsDir() && !reservedAtResolved(root, filepath.ToSlash(childPath)) {
				_, taken, err := clearKeepingReserved(root, childPath)
				if err != nil {
					return err
				}
				if taken {
					s.markMutation(childPath)
				}
			}
			continue
		}
		if err := root.RemoveAll(childPath); err != nil {
			return err
		}
		s.markMutation(childPath)
	}
	return nil
}
