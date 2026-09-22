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
	// Refused before anything below touches dest, through the same
	// helper Plan asks, so the two cannot drift.
	if err := refuseEntriesCopyRefuses(rules.Profile); err != nil {
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
	return copyEntries(paths.Home(), root, rules.Profile, previously, Ceiling, prints)
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

// within turns an entry from the rules file into the path it names under the
// profile, and refuses one that climbs out.
//
// The root refuses that too, and more thoroughly -- this cannot see a
// junction and the root can. It is here for the message: a name written
// wrongly in the rules file deserves to be told what is wrong with it,
// rather than "path escapes from parent" about a path nobody typed.
// EntryEscapesProfile answers whether a profile: entry's path, exactly as
// the rules file spells it, would be refused by within for being absolute,
// for climbing out of the profile with "..", for naming the profile root
// itself -- "." or anything filepath.Clean turns into it -- or for a
// spelling the volume would not store -- a segment ending in dots or
// spaces, or one shaped like an 8.3 alias -- and if so, within's own
// message. Exported so validation asks this package the question rather
// than re-deciding it with a copy of the same rule: two answers to "does
// this path escape the profile" are exactly how a rules file comes to pass
// validation and then fail the run.
func EntryEscapesProfile(path string) error {
	_, err := within(path)
	return err
}

// cleanEntryPath is the one cleaning of a rules file's or a record's
// spelling of an entry: within lands the path it names, FoldedEntryPath
// folds the key it is deduped and refused by, and the ownership comparison
// opens both of its spellings cleaned -- sameEntryPlace through it -- so
// none of them can disagree about what was cleaned.
func cleanEntryPath(entry string) string {
	return filepath.Clean(filepath.FromSlash(entry))
}

func within(entry string) (string, error) {
	clean := cleanEntryPath(entry)
	if filepath.IsAbs(clean) || clean == ".." ||
		strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%q does not name anything inside the profile", entry)
	}
	// "." is a path too, and not a safe one: filepath.Clean turns both "."
	// and "foo/.." into it, and either spelling would make the source the
	// user's whole profile and dst the sandbox's whole profile. Copy would
	// then mirror one onto the other -- copying everything the user owns in,
	// and deleting from the sandbox everything the user's profile does not
	// have, the sandbox's own registry hive among it. Refused here, not only
	// at validation: an ordinary run never calls --config validate, so the
	// copier is the only place this is always on the path.
	if clean == "." {
		return "", fmt.Errorf("%q names the profile root itself, and copying it would copy the "+
			"user's whole profile into the sandbox's and delete from the sandbox everything the "+
			"user's profile does not have -- name something inside it instead", entry)
	}
	// A spelling Windows improves on is refused, not quietly corrected,
	// and the improvement is what the refusal names. "NTUSER.DAT." opens
	// the file "NTUSER.DAT" keeps -- Win32 strips trailing dots and spaces
	// per segment before the volume looks, when it opens and when it
	// creates -- so the entry would land on the stripped name while the
	// rules file and the record spell the padded one, and what gets copied
	// and what gets taken back would never agree about the name. An 8.3
	// shape is refused for its own reason: the volume resolves such a
	// spelling onto the long name it aliases, and only the volume knows
	// which one. Both refusals hold for copyEntries and previewEntries --
	// the run and the preview ask the same within -- and for
	// EntryEscapesProfile, so validation refuses the file with the same
	// words. Kept here, not only at validation, for the same reason the
	// refusals above them are: an ordinary run never calls --config
	// validate, so the copier is the only place these are always on the
	// path.
	segments := strings.Split(clean, string(filepath.Separator))
	for _, segment := range segments {
		if !stripsTrailingPad(segment) {
			continue
		}
		stripped := make([]string, len(segments))
		for j, s := range segments {
			stripped[j] = strings.TrimRight(s, ". ")
		}
		return "", fmt.Errorf("%q ends in dots or spaces, and Windows strips those before it opens "+
			"anything -- %q is the name the volume actually keeps. Name the file as it is stored: "+
			"the entry would land on the stripped name while the rules file and the record spell "+
			"the padded one, so what gets copied and what gets taken back never agree about the name",
			entry, strings.Join(stripped, "/"))
	}
	for _, segment := range segments {
		if looksLikeShortName(segment) {
			return "", fmt.Errorf("%q is spelled like an 8.3 short name, and Windows resolves those "+
				"onto the long name they alias -- the volume, not this spelling, says which. Spell the long name",
				entry)
		}
	}
	return clean, nil
}

// withinRecorded is within for a path out of the record, which is not a
// hand-edited file: a spelling in it was written by an earlier run of this
// tool. The original refusals -- absolute, climbing out, the root itself --
// hold; the spelling refusals do not, because what a record's spelling
// resolves to is asked of the volume directly (reservedAtResolved, in
// forget), and a spelling that survives to here is one the volume resolves
// onto itself, which is the only thing a record needs. A take-back that
// refused forever over a spelling would leave the entry's copy stuck
// behind a name nothing can fix from where a record can be edited.
func withinRecorded(entry string) (string, error) {
	clean := cleanEntryPath(entry)
	if filepath.IsAbs(clean) || clean == ".." ||
		strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%q does not name anything inside the profile", entry)
	}
	// The root-itself answer is worded for clearing, not copying: this is
	// the take-back's question, and the take-back that reaches "." is one
	// recorded entry spelling the profile whole.
	if clean == "." {
		return "", fmt.Errorf("%q names the profile root itself, and clearing it would take the profile whole", entry)
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
// previously is the record the last call left, and only Copy's hands are on
// it here: a source that has gone since that record was written is told
// apart from a source that was never there by it, and by nothing else this
// sees.
//
// prints is what the last run recorded and the map returned is this run's:
// a skipped file carries its print forward and a copied file gets a fresh
// one, so anything this run did not finish with is simply absent, which
// sends the next run back to copying it.
func copyEntries(home string, root *os.Root, entries, previously []config.Entry, left int64, prints map[string]Print) ([]config.Entry, map[string]Print, error) {
	var copied []config.Entry
	newPrints := make(map[string]Print, len(prints))
	// One scratch buffer for the whole pass, built when the first file
	// actually moves: a run that copies nothing -- every file skipped by
	// its print or missing from the source -- never pays for one, and no
	// run pays for one per file. What it holds between files are pieces
	// of whatever transfer was mid-flight, so it dies with the pass and
	// nothing of one run's sources is left holding over to the next call.
	var scratch []byte
	// The previous record's own spellings. This is the oracle for a source
	// os.Stat cannot ask about, and the question it answers -- was this
	// place copied by an earlier run? -- decides a deletion, so it is
	// asked of the volume and not of a fold: both wrong directions of a
	// fold delete here.
	recorded := entryPathsOf(previously)
	// One placeIndex per mutation-free stretch of the loop, built the
	// first time a source goes missing and kept across every vouch the
	// stretch answers after it: the record is constant while nothing is
	// copied, so one indexing of it serves the whole run of missing
	// sources however long. A mirror that changes the destination's
	// structure -- makes, takes, or replaces a name -- is the real mutation
	// the stretch must not be carried across -- what it cached watched the
	// profile before the copy changed it -- so the stretch is dropped after
	// one and the next missing source builds its own. A mirror that only
	// rewrote the bytes of a file that already stood, or skipped the file
	// by its print, changed no name the stretch describes, and the mixed
	// warm run -- missing sources between unchanged present ones -- keeps
	// its one indexing instead of paying for one per no-op.
	var stretch *placeIndex
	for _, entry := range entries {
		dst, err := within(entry.Path)
		if err != nil {
			return copied, newPrints, err
		}
		src := filepath.Join(home, filepath.FromSlash(entry.Path))
		info, err := os.Stat(src)
		if err != nil {
			// os.Stat cannot tell a source that has gone since an earlier
			// run copied it from a source that was never here, and the two
			// are opposite in what they license. The first leaves a copy
			// sitting in the sandbox that this list is the only thing still
			// able to vouch for -- recording nothing, a --no-ai reported
			// success while stale credentials stayed inside for good -- so
			// where the previous record already names the path, the entry
			// stays on it. The second names a path this machine never had,
			// and recording it claimed whatever was sitting there as ours:
			// local-agent was never under the user's profile, the sandbox
			// wrote local-agent/session.txt itself, and the next --no-ai
			// took it back with the rest. The previous record is the only
			// witness that can tell the two apart; taking a vanished source
			// back here instead would act on a disappearance that is often
			// temporary -- a drive not yet mounted, a tool not yet installed.
			if stretch == nil {
				stretch = newPlaceIndex(root, recorded)
			}
			if stretch.holds(entry.Path) {
				copied = append(copied, entry)
			}
			continue
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
		changed, err := mirror(src, dst, "", root, info, &left, newWalk(entry), prints, newPrints, &scratch)
		if err != nil {
			return copied, newPrints, fmt.Errorf("copying %s: %w", entry.Path, err)
		}
		// A mirror that changed the destination's structure -- made,
		// took, or replaced a name, the file created where none stood
		// among them -- left every cached answer the stretch held
		// describing a profile that is no longer there: the stretch dies
		// here and the next missing source builds a fresh one. A mirror
		// that only rewrote the bytes of a file that already stood, or
		// skipped the file by its print, changed no name the stretch
		// describes, and a run that interleaves such mirrors with missing
		// sources keeps its one stretch of instruments instead of
		// rebuilding it for every no-op -- the mixed warm run this used
		// to square.
		if changed {
			stretch = nil
		}
	}
	return copied, newPrints, nil
}

// recordVouches answers whether the record names the place one entry lands
// at, and it is asked exactly where os.Stat cannot answer: a source that
// has gone since an earlier run copied it and a source that was never here
// look identical to that call, and the record is the only witness that can
// tell them apart. Both of its wrong directions delete -- joined too much,
// the record claims a place this machine never copied and Clear takes the
// sandbox's own file for it; split too fine, it reads a copy it did make
// as a name nothing vouches for -- so the question goes to the volume, and
// it does not fall back when a spelling opens nothing: the entry's own
// place is then missing from the profile, there is no copy for the record
// to vouch for, and dropping the claim costs nothing that exists. A vouch
// is a claim about a copy, and a claim about a copy has to be witnessed by
// the copy.
//
// This is the one-question convenience, the shape sameEntryPlace keeps for
// one comparison: a stretch of instruments built for this entry alone and
// thrown away with the answer. copyEntries holds one placeIndex across
// each mutation-free stretch of its entry loop instead of a fresh one per
// vouch, and drops it after the mirror that would turn its cached answers
// into lies.
func recordVouches(resolver *placeResolver, recorded []string, entry string) bool {
	index := &placeIndex{resolver: resolver, places: make(map[string]bool, len(recorded))}
	for _, path := range recorded {
		if canonical, ok := resolver.place(path); ok {
			index.places[canonical] = true
		}
	}
	return index.holds(entry)
}
