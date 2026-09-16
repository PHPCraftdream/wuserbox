package profile

import (
	"fmt"
	"io"
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
// entry itself.
//
// The entry itself is never filtered: its limits say what is copied under
// it, and an entry naming a file has nothing under it.
func mirror(src, dst, rel string, root *os.Root, info os.FileInfo, left *int64, w *walk, prints, newPrints map[string]Print) error {
	return walkEntry(copySink{}, src, dst, rel, root, info, left, w, prints, newPrints)
}

// walkEntry is mirror's shape with the action pulled out: dispatch to a
// directory's children, or hand one file to sk.
func walkEntry(sk sink, src, dst, rel string, root *os.Root, info os.FileInfo, left *int64, w *walk, prints, newPrints map[string]Print) error {
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
			present[e.Name()] = true
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
		present[e.Name()] = true
		if err := walkEntry(sk, filepath.Join(src, e.Name()), filepath.Join(dst, e.Name()), childRel, root, info, left, w, prints, newPrints); err != nil {
			return err
		}
	}
	return sk.finishDir(root, dst, rel, present, w)
}

// copySink is the real fill: it writes, and it deletes what a directory's
// mirroring leaves stale.
type copySink struct{}

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
func (copySink) prepareDir(root *os.Root, dst string) error {
	if err := clearWhatIsNotADirectory(root, dst); err != nil {
		return err
	}
	return root.MkdirAll(dst, 0o755)
}

// clearWhatIsNotADirectory is prepareDir's own half of the work, kept apart
// so its reasoning has room to be spelled out. See prepareDir.
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
func (copySink) file(src, dst string, root *os.Root, info os.FileInfo, left *int64, prints, newPrints map[string]Print) error {
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
	if err := mirrorFile(src, dst, root); err != nil {
		return err
	}
	// Recorded only once the copy is whole. A file whose write failed or
	// was cut short gets no fingerprint, so the next run copies it instead
	// of skipping on the strength of a print for a copy that never
	// happened.
	newPrints[key] = Print{Size: info.Size(), ModNanos: info.ModTime().UnixNano()}
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
func (copySink) finishDir(root *os.Root, dst, rel string, present map[string]bool, w *walk) error {
	return removeStrayChildren(root, dst, rel, present, w)
}

func removeStrayChildren(root *os.Root, dst, rel string, present map[string]bool, w *walk) error {
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
		// with neither exclusions nor a depth can spare nothing below, and
		// keeps the RemoveAll, which is cheaper than any walk.
		childPath := filepath.Join(dst, e.Name())
		if e.IsDir() && (w.bound != nil || len(w.entry.Exclude) > 0) {
			// A junction where the lost directory sat is removed as the
			// link it is, the way clearKeeping and cleanDir both treat
			// one: the root would refuse to open a link leading out of
			// the profile, and failing the mirror over an artifact the
			// sandbox may leave is worse than taking the link.
			if info, readable := lookAt(root, childPath); readable &&
				info.IsDir() && info.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0 {
				var under bool
				if err := clearKeeping(root, childPath, childRel, w, &under); err != nil {
					return err
				}
				if under {
					continue
				}
			}
		}
		if err := root.RemoveAll(childPath); err != nil {
			return err
		}
	}
	return nil
}
