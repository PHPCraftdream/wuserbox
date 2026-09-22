package profile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/win/pathid"
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
	taken, err := mirrorFile(src, dst, root, info.Size())
	if err != nil {
		return err
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

// openSource is the one place a copy's read of a source begins, and it is
// a variable for the same reason newPlaceResolver in fold.go is: the
// window the ceiling's stale measurement lives in sits between the walk's
// os.Stat of a source and the open this is, and the test that pins that
// window has to be able to stand inside it and grow the file the walk
// already measured, the way the volume would if something wrote it
// between the two.
var openSource = os.Open

// mirrorFile carries one source file into its place at dst and answers with
// the print of the file it copied.
//
// charged is what the budget was debited for this file -- the walk's own
// measure of it -- and it does two jobs. It bounds the copy stream itself,
// because the ceiling counted a measurement and a stream bounded by nothing
// but that measurement is open to exactly what changed it: the walk Stat'ed
// the source, then this opens it, and something as ordinary as a program
// saving its own settings in between leaves this holding a file larger than
// the budget was ever told about. And it is the yardstick the opened source
// is held against when the copy starts -- more bytes under the name the walk
// measured than the walk measured is a different file than the one the run
// set out to move, and the copy refuses before the destination is touched,
// since carrying the larger file whole would be carrying past the ceiling
// and carrying it cut short would be writing a mixture nobody asked for.
// A re-Stat alone would answer neither question: what bounds a live stream
// is a check against the bytes as they go, not a second reading of the
// same measurement.
//
// The print comes from the opened handle rather than the walk's stale
// FileInfo, and it is earned only after the transfer is confirmed whole:
// the handle is re-Stat'ed once the bytes are down, and a size or a stamp
// that moved under the copy means what landed may be part of the file that
// was there and part of the one that replaced it. No print may claim a
// mixture -- a print is what lets a later run skip a copy, and skipping on
// the strength of bytes nobody can describe is how a stale copy outlives
// every correction.
func mirrorFile(src, dst string, root *os.Root, charged int64) (Print, error) {
	in, err := openSource(src)
	if err != nil {
		return Print{}, err
	}
	defer func() { _ = in.Close() }()
	// The opened handle's own measure, before anything else: this is the
	// size and the stamp the transfer will be asked to stand still for,
	// and the last reading taken before the destination is touched. The
	// walk's measure said what the budget was debited; this one says what
	// is actually here, and the two disagreeing is a source that changed
	// under the run, which is refused rather than carried.
	opened, err := in.Stat()
	if err != nil {
		return Print{}, err
	}
	if opened.Size() > charged {
		return Print{}, fmt.Errorf("%s measured %d bytes when the walk counted it and holds %d when the copy opened it, and a copy of the larger would not be the copy the budget was counted for: the source changed between the two readings, and the run refuses rather than carry what it never declared", src, charged, opened.Size())
	}
	if parent := filepath.Dir(dst); parent != "." {
		if err := root.MkdirAll(parent, 0o755); err != nil {
			return Print{}, err
		}
	}
	// os.Root pins the pathname, not the file object. A sandbox can leave a
	// link or reparse point in its profile, and O_TRUNC would then modify the
	// object reached through that name. In particular, a symlink to an
	// internal hard-link name can reach an external file while Lstat sees only
	// the symlink. Refuse links before opening the destination. A plain file
	// whose names all stay under this profile remains valid and is checked
	// below.
	if info, readable := lookAt(root, dst); readable {
		if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			return Print{}, fmt.Errorf("refusing to overwrite %s: destination is a symbolic link or reparse point", dst)
		}
		if info.Mode().IsRegular() {
			full := filepath.Join(root.Name(), filepath.FromSlash(dst))
			outside, err := pathid.OutsideNames(root.Name(), full)
			if err != nil {
				return Print{}, fmt.Errorf("checking destination %s for external hard links: %w", dst, err)
			}
			if len(outside) > 0 {
				return Print{}, fmt.Errorf("refusing to overwrite %s: it is also hard-linked outside the sandbox profile (%s)",
					dst, strings.Join(outside, ", "))
			}
		}
	}
	out, err := root.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return Print{}, err
	}
	if _, err := copyBounded(out, in, charged); err != nil {
		_ = out.Close()
		return Print{}, err
	}
	// The transfer is down, and the last thing it owes is proof the source
	// held still while it was read. What this catches is the same ordinary
	// writer the size check above catches, arrived through the door the
	// size check cannot close: a rewrite that keeps the size, or a write
	// that landed after the copy began. Either way the bytes in the
	// destination may be part of one file and part of another, and no
	// refusal here means no print means the next run copies the file
	// again -- which is the whole of what an uncertain copy can honestly
	// ask for.
	settled, err := in.Stat()
	if err != nil {
		_ = out.Close()
		return Print{}, err
	}
	if settled.Size() != opened.Size() || settled.ModTime().UnixNano() != opened.ModTime().UnixNano() {
		_ = out.Close()
		return Print{}, fmt.Errorf("%s held %d bytes stamped %d when the copy opened it and %d bytes stamped %d when it finished, and what was written may be part of the file that was there and part of the one that replaced it: the run refuses rather than record a print for the mixture", src, opened.Size(), opened.ModTime().UnixNano(), settled.Size(), settled.ModTime().UnixNano())
	}
	return Print{Size: opened.Size(), ModNanos: opened.ModTime().UnixNano()}, out.Close()
}

// copyBounded copies in to out while the running total stays within limit,
// and refuses the moment the source offers a byte past it. The limit is the
// allocation the budget debited for this file -- the same charged the
// ceiling counted before the copy began -- and that is the whole reason the
// two have to be one number: a ceiling checked against a measurement, with
// a stream after it bounded by nothing, is a ceiling only for the files
// that sit still, and a source that grows between the walk and the copy
// would carry past it on the very pass that reported success. A stream that
// would exceed the limit is a source that changed under the run's
// measurement, and the refusal is the ceiling hole this exists to close.
// The chunk that would go past is never written, so what lands in the
// destination never holds more than the budget paid for, whatever the
// source does; what the source does with the rest is the next run's
// question, and the entry stays on the copied list to be cleared either
// way.
func copyBounded(out io.Writer, in io.Reader, limit int64) (int64, error) {
	buf := make([]byte, 32<<10)
	var total int64
	for {
		n, rerr := in.Read(buf)
		if n > 0 {
			if total+int64(n) > limit {
				return total, fmt.Errorf("the copy reached %d bytes of its %d-byte measure and the source still had more to give, which is a source that changed after it was measured: writing the rest would carry %d past what the budget was told of", total, limit, total+int64(n)-limit)
			}
			w, werr := out.Write(buf[:n])
			total += int64(w)
			if werr != nil {
				return total, werr
			}
			if w < n {
				return total, io.ErrShortWrite
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return total, nil
			}
			return total, rerr
		}
	}
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
				var under bool
				if err := clearKeeping(root, childPath, childRel, w, &under); err != nil {
					return err
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
				if _, err := clearKeepingReserved(root, childPath); err != nil {
					return err
				}
			}
			continue
		}
		if err := root.RemoveAll(childPath); err != nil {
			return err
		}
	}
	return nil
}
